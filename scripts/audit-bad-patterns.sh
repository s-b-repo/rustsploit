#!/usr/bin/env bash
# audit-bad-patterns.sh — run the docs/BAD_PATTERNS.md regex matrix against
# every .rs file under src/.
#
# Usage:
#   scripts/audit-bad-patterns.sh                # full report to stdout
#   scripts/audit-bad-patterns.sh --strict       # exit non-zero on any A/B/C/L/M/N/O hit
#   scripts/audit-bad-patterns.sh --section A    # run only one section
#   scripts/audit-bad-patterns.sh --files <list> # restrict to files listed
#
# Sections (from docs/BAD_PATTERNS.md):
#   A: Panicking error handling
#   B: Silent error swallowing
#   C: Lint suppression
#   D: Panic vectors (index/slice)
#   E: Numeric / unsafe
#   F: Async / blocking
#   G: Logging
#   H: HTTP layer
#   I: Iterator glitches
#   J: Style / secrets
#   L: Crypto
#   M: SQL & command injection
#   N: UB / concurrency
#   O: Performance
#   P: API hygiene

set -u

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

STRICT=0
ONLY_SECTION=""
FILE_LIST=""

while [ $# -gt 0 ]; do
    case "$1" in
        --strict) STRICT=1; shift ;;
        --section) ONLY_SECTION="$2"; shift 2 ;;
        --files) FILE_LIST="$2"; shift 2 ;;
        -h|--help) sed -n '/^# /p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [ -n "$FILE_LIST" ]; then
    if [ ! -f "$FILE_LIST" ]; then
        echo "file list $FILE_LIST does not exist" >&2
        exit 2
    fi
    ALL_RS=$(cat "$FILE_LIST")
else
    ALL_RS=$(find src -name "*.rs" -type f)
fi
N_FILES=$(echo "$ALL_RS" | wc -l)

# ---- pattern arrays ------------------------------------------------------

A=(  # Panicking error handling — explicit \(\) anchors so we don't match the
     # value-providing _or family.
    '\.unwrap\(\)'  '\.expect\('  '\.unwrap_or_default\(\)'
    '\.parse\(\)\.unwrap\(\)'  '\.parse::<[^>]+>\(\)\.unwrap\(\)'
    '\.try_into\(\)\.unwrap\(\)'
    '\.first\(\)\.unwrap\(\)'  '\.last\(\)\.unwrap\(\)'
    '\.next\(\)\.unwrap\(\)'
    '\.iter\(\)\.[a-z_]+\([^)]*\)\.unwrap\(\)'
    '\.chars\(\)\.next\(\)\.unwrap\(\)'
    '\.split\([^)]*\)\.next\(\)\.unwrap\(\)'
    '\.position\([^)]*\)\.unwrap\(\)'
    '\.iter\(\)\.find\([^)]*\)\.unwrap\(\)'
    '\.read_to_string\([^)]*\)\.unwrap\(\)'
    '\.lock\(\)\.unwrap\(\)'
    '\.expect_err\('  '\.unwrap_err\('
    'panic!\('  'unreachable!\('  'todo!\('  'unimplemented!\('
    '\bassert!\('  '\bassert_eq!\('  '\bassert_ne!\('
)
B=(  # Silent error swallowing
    'Err\(_\)'  'Err\(_[a-zA-Z]\w*\)'  'if let Err\(_'
    'if let Ok\('  'let\s+_\s*='  'let\s+_[a-zA-Z]\w*\s*=.*\.await'
    '\.map_err\(\|_\|'  '\.or_else\(\|_\|'
    '\.to_str\(\)\.ok\(\)'  '\.json\([^)]*\)\.await\.ok\(\)'
    '\.send\(\)\.await\.ok\(\)'  '\.text\(\)\.await\.ok\(\)'
)
C=(  # Lint suppression
    '#\[allow\('  '#\[deny\('  '#\[ignore\b'
)
D=(  # Panic vectors (index/slice)
    '\b[a-zA-Z_]\w*\[[0-9]+\][^=]'
    '\&[a-zA-Z_]\w*\[\.\.\w+\]'
    '\&[a-zA-Z_]\w*\[\w+\.\.\]'
    '\&[a-zA-Z_]\w*\[\w+\.\.\w+\]'
    '\.split_at\('  '\.chars\(\)\.nth\('
)
E=(  # Numeric / unsafe
    '\bas\s+u8\b'  '\bas\s+i8\b'
    '\bas\s+u16\b'  '\bas\s+i16\b'
    '\bas\s+u32\b'  '\bas\s+i32\b'
    '\bas\s+u64\b'  '\bas\s+i64\b'
    '\bas\s+usize\b'  '\bas\s+isize\b'
    '\bas\s+f32\b'  '\bas\s+f64\b'
    '\bas\s+\*const\b'  '\bas\s+\*mut\b'
    '\btransmute\('  '\bextern\s+"C"'
    '\bunsafe\s*\{'  '\bunsafe\s+fn\b'
)
F=(  # Async / blocking
    'std::thread::sleep'  'std::process::Command'
    'std::fs::File'  'std::fs::read\b'  'std::fs::write\b'
    'std::net::TcpStream'  'std::net::UdpSocket'  'std::io::stdin'
)
G=(  # Logging
    '\bdbg!\('
    'format!\(.*"\{:\?\}".*\b[eE]rr\b'
    '\.context\(""\)'  '\.context\("\?"\)'
)
H=(  # HTTP layer
    'reqwest::Client::new\(\)'  'reqwest::Client::builder\(\)'
    '\.send\(\)\.await\?[^.]'  '\.text\(\)\.await\?[^.]'
    'format!\("\{:\?\}", \w+\)\.contains\('
)
I=(  # Iterator glitches
    '\.collect::<Result<Vec<_>,\s*_>>\(\)\.unwrap'
    '\.zip\([^)]*\)\.unwrap'
)
J=(  # Style / secrets
    '== ""'  '\.len\(\) == 0'  '\.len\(\) > 0'
    'String::from\(format!'
    '\.clone\(\)\s*\.clone'  '\.to_string\(\)\s*\.to_string'
    'XXXXXX|TODO|FIXME|HACK\b'
    'Bearer\s+[A-Za-z0-9_.-]{40,}'
    'sk-[A-Za-z0-9]{20,}'  'AKIA[A-Z0-9]{16}'
    '"admin"\s*,\s*"admin"'  '"root"\s*,\s*"root"'
    'Box<dyn'
)
L=(  # Crypto
    '\bmd5::compute\b|\bmd5::Md5\b'
    '\bsha1::Sha1\b|use sha1::'
    '\bdes::Des\b|\b3des\b|TripleDES'
    'rand::thread_rng\(\)'  'rand::random\(\)'
    '\bRC4\b|rc4::'  'aes_128_ecb|aes-128-ecb|Ecb'
)
M=(  # Injection
    'format!\("SELECT[^"]*\{'  'format!\("INSERT[^"]*\{'
    'format!\("UPDATE[^"]*\{'  'format!\("DELETE[^"]*\{'
    'std::process::Command::new\("/bin/sh"\)'
    'std::process::Command::new\("sh"\)'
    '\.arg\("-c"\).*format!'
)
N=(  # UB / concurrency
    '\bstatic\s+mut\b'  'std::mem::transmute'  'std::mem::forget'
    'std::mem::uninitialized'  'std::mem::zeroed'
    'std::ptr::read'  'std::ptr::write'
    'Result<\(\), String>'  'Result<.*,\s*String>'
)
O=(  # Performance
    '\.iter\(\)\.count\(\)'  '\.collect::<\(\)>\(\)'
    '\.iter\(\)\.map\(\|\w+\|\s*\w+\.clone\(\)\)\s*\.collect'
    '\.to_string\(\)\.as_str\(\)'
    'Vec::with_capacity\(0\)'  'String::with_capacity\(0\)'
    'Regex::new\(.*\)\.unwrap'
    'Box::new\(.*Box::new'
)
P=(  # API hygiene
    '\bpub\s+const\s+\w+\s*:\s*&str\s*=\s*"http'
    '#\[derive\(Debug\)\][^a-z]*pub\s+struct\s+\w+\s*\{[^}]*[Pp]assword'
    '#\[derive\(Debug\)\][^a-z]*pub\s+struct\s+\w+\s*\{[^}]*[Ss]ecret'
    '#\[derive\(Debug\)\][^a-z]*pub\s+struct\s+\w+\s*\{[^}]*[Tt]oken'
)

declare -A SECTION_DESC
SECTION_DESC[A]="Panicking error handling"
SECTION_DESC[B]="Silent error swallowing"
SECTION_DESC[C]="Lint suppression"
SECTION_DESC[D]="Panic vectors (index/slice)"
SECTION_DESC[E]="Numeric / unsafe"
SECTION_DESC[F]="Async / blocking"
SECTION_DESC[G]="Logging"
SECTION_DESC[H]="HTTP layer"
SECTION_DESC[I]="Iterator glitches"
SECTION_DESC[J]="Style / secrets"
SECTION_DESC[L]="Crypto"
SECTION_DESC[M]="SQL & command injection"
SECTION_DESC[N]="UB / concurrency"
SECTION_DESC[O]="Performance"
SECTION_DESC[P]="API hygiene"

# Sections that should be hard zero in module code (strict mode)
STRICT_SECTIONS=(A B C L M N O)

GRAND_TOTAL=0
GRAND_PATTERNS=0
GRAND_PATTERNS_HIT=0
STRICT_HITS=0

run_section() {
    local label="$1"; shift
    local arr=("$@")
    local total=0
    local hit_pats=0
    local pats=${#arr[@]}
    GRAND_PATTERNS=$((GRAND_PATTERNS + pats))
    declare -a lines
    for p in "${arr[@]}"; do
        local c
        # Strip line+doc comments before counting so we don't flag matches in
        # `// foo .unwrap() bar` or `/// .expect(...)`. We also filter `#[test]`
        # / `#[cfg(test)]` blocks heuristically by skipping lines tagged with
        # `// audit-allow:` (an explicit per-line waiver).
        c=$(echo "$ALL_RS" | xargs grep -hE "$p" 2>/dev/null \
            | grep -vE '^\s*//' \
            | grep -vE '// audit-allow:' \
            | wc -l)
        if [ "$c" -gt 0 ]; then
            total=$((total + c))
            hit_pats=$((hit_pats + 1))
            GRAND_PATTERNS_HIT=$((GRAND_PATTERNS_HIT + 1))
            lines+=("    [$c] /$p/")
        fi
    done
    GRAND_TOTAL=$((GRAND_TOTAL + total))
    printf "  %-2s %-32s : %5d hits across %2d/%-2d patterns\n" \
        "$label" "${SECTION_DESC[$label]}" "$total" "$hit_pats" "$pats"
    [ "$total" -gt 0 ] && printf "%s\n" "${lines[@]}"

    # Strict accounting
    local s
    for s in "${STRICT_SECTIONS[@]}"; do
        if [ "$s" = "$label" ]; then
            STRICT_HITS=$((STRICT_HITS + total))
            break
        fi
    done
}

echo "============================================================"
echo "  RUSTSPLOIT BAD-PATTERN AUDIT"
echo "  $N_FILES file(s) under audit"
echo "============================================================"
echo

if [ -z "$ONLY_SECTION" ]; then
    SECTIONS=(A B C D E F G H I J L M N O P)
else
    SECTIONS=("$ONLY_SECTION")
fi

for s in "${SECTIONS[@]}"; do
    case "$s" in
        A) run_section A "${A[@]}" ;;
        B) run_section B "${B[@]}" ;;
        C) run_section C "${C[@]}" ;;
        D) run_section D "${D[@]}" ;;
        E) run_section E "${E[@]}" ;;
        F) run_section F "${F[@]}" ;;
        G) run_section G "${G[@]}" ;;
        H) run_section H "${H[@]}" ;;
        I) run_section I "${I[@]}" ;;
        J) run_section J "${J[@]}" ;;
        L) run_section L "${L[@]}" ;;
        M) run_section M "${M[@]}" ;;
        N) run_section N "${N[@]}" ;;
        O) run_section O "${O[@]}" ;;
        P) run_section P "${P[@]}" ;;
        *) echo "unknown section: $s" >&2; exit 2 ;;
    esac
    echo
done

echo "============================================================"
echo "  TOTALS"
echo "============================================================"
echo "  Patterns scanned       : $GRAND_PATTERNS"
echo "  Patterns with hits     : $GRAND_PATTERNS_HIT"
echo "  Total hit lines        : $GRAND_TOTAL"
echo "  Strict (A/B/C/L/M/N/O) : $STRICT_HITS"

if [ "$STRICT" = "1" ] && [ "$STRICT_HITS" -gt 0 ]; then
    echo "  RESULT                  : STRICT FAILURE — fix before merge"
    exit 1
fi
echo "  RESULT                  : informational only (use --strict to gate)"
