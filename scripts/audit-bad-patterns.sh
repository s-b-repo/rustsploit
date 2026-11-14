#!/usr/bin/env bash
# audit-bad-patterns.sh — run the docs/BAD_PATTERNS.md regex matrix against
# every .rs file under src/.
#
# Usage:
#   scripts/audit-bad-patterns.sh                # full report to stdout
#   scripts/audit-bad-patterns.sh --strict       # exit non-zero on any A/B/C/L/M/N/O hit
#   scripts/audit-bad-patterns.sh --section A    # run only one section
#   scripts/audit-bad-patterns.sh --files <list> # restrict to files listed
#   scripts/audit-bad-patterns.sh --counts-file <f>   # write per-pattern counts (TSV)
#   scripts/audit-bad-patterns.sh --baseline <f>      # fail only on NEW violations
#   scripts/audit-bad-patterns.sh --update-baseline <f>  # (re)write the baseline
#   scripts/audit-bad-patterns.sh --changed-from <ref>  # audit only files changed since <ref>
#   scripts/audit-bad-patterns.sh --strict-sections A,B,C  # override which sections gate
#   scripts/audit-bad-patterns.sh --file-baseline <f>   # per-file per-section gate
#   scripts/audit-bad-patterns.sh --update-file-baseline <f>
#   scripts/audit-bad-patterns.sh --drift-report <f>    # report UP/DOWN vs a baseline
#   scripts/audit-bad-patterns.sh --report <f>          # per-hit file:line report
#
# The `--report` file is TSV: <section>\t<file>\t<line>\t<pattern>\t<source text>.
# The CI workers turn each row into a GitHub annotation and a "BROKEN" list,
# so a banned pattern shows up inline on the diff instead of only as a count.
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
#
# Baseline mode is what CI uses: the repository already carries a large amount
# of legacy debt (e.g. `md5::compute` in fingerprinters, `"admin","admin"` in
# default credential lists, `as u32` casts). A plain --strict gate is red on
# day one and therefore useless. The baseline records the CURRENT count for
# every pattern; the gate then fails only when a count INCREASES, so the
# pipeline is green now and blocks new violations from then on.
#
set -u

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

STRICT=0
ONLY_SECTION=""
FILE_LIST=""
COUNTS_FILE=""
BASELINE_FILE=""
UPDATE_BASELINE=""
CHANGED_FROM=""
STRICT_SECTIONS_OVERRIDE=""
FILE_BASELINE=""
UPDATE_FILE_BASELINE=""
DRIFT_REPORT=""
REPORT_FILE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --strict) STRICT=1; shift ;;
        --section) ONLY_SECTION="$2"; shift 2 ;;
        --files) FILE_LIST="$2"; shift 2 ;;
        --counts-file) COUNTS_FILE="$2"; shift 2 ;;
        --baseline) BASELINE_FILE="$2"; shift 2 ;;
        --update-baseline) UPDATE_BASELINE="$2"; shift 2 ;;
        --changed-from) CHANGED_FROM="$2"; shift 2 ;;
        --strict-sections) STRICT_SECTIONS_OVERRIDE="$2"; shift 2 ;;
        --file-baseline) FILE_BASELINE="$2"; shift 2 ;;
        --update-file-baseline) UPDATE_FILE_BASELINE="$2"; shift 2 ;;
        --drift-report) DRIFT_REPORT="$2"; shift 2 ;;
        --report) REPORT_FILE="$2"; shift 2 ;;
        -h|--help) sed -n '/^# /p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [ -n "$CHANGED_FROM" ]; then
    # Audit only the Rust files that changed since the given ref. Used by the
    # CI workers to hold NEW code to a stricter standard than the legacy
    # baseline: a PR may not introduce panics, swallowed errors or lint
    # suppressions, even though the repository as a whole still contains some.
    if ! git rev-parse --verify "$CHANGED_FROM" >/dev/null 2>&1; then
        echo "changed-from ref '$CHANGED_FROM' does not exist" >&2
        exit 2
    fi
    CHANGED_RS=$(git diff --name-only --diff-filter=ACMR "$CHANGED_FROM" HEAD -- '*.rs' 2>/dev/null || true)
    if [ -z "$CHANGED_RS" ]; then
        # Fall back to the working tree (covers a local run with uncommitted
        # changes, and a PR where the base is the merge target).
        CHANGED_RS=$(git diff --name-only --diff-filter=ACMR "$CHANGED_FROM" -- '*.rs' 2>/dev/null || true)
    fi
    ALL_RS=$(printf '%s\n' "$CHANGED_RS" | grep -v '^$' | grep -E '\.rs$' || true)
    if [ -z "$ALL_RS" ]; then
        echo "No Rust files changed since '$CHANGED_FROM' — nothing to audit."
        exit 0
    fi
    echo "Auditing $(printf '%s\n' "$ALL_RS" | wc -l | tr -d ' ') changed Rust file(s) since $CHANGED_FROM:"
    printf '%s\n' "$ALL_RS" | sed 's/^/  /'
    echo
elif [ -n "$FILE_LIST" ]; then
    if [ ! -f "$FILE_LIST" ]; then
        echo "file list $FILE_LIST does not exist" >&2
        exit 2
    fi
    ALL_RS=$(cat "$FILE_LIST")
else
    ALL_RS=$(find src -name "*.rs" -type f)
fi
N_FILES=$(echo "$ALL_RS" | grep -c . || true)

# ----------------------------------------------------------------------------
# The corpus the patterns are matched against.
#
# EVERYTHING is audited — test modules included. Nothing is filtered out or
# silently skipped. The only sanctioned exemption is the inline
# `// audit-allow: <reason>` marker, which is visible in the source.
# ----------------------------------------------------------------------------
CORPUS=$(mktemp)
trap 'rm -f "$CORPUS"' EXIT

cat $ALL_RS > "$CORPUS" 2>/dev/null || true

# ---- pattern arrays ------------------------------------------------------

A=(  # Panicking error handling
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
    # B10: underscore-prefixed function parameter (bypass unused-parameter warning)
    'fn\s+\w+\([^)]*\b_\w+\s*:\s*[^)]*\)'
    # B11: underscore-prefixed variable binding (bypass unused-variable warning)
    'let\s+_\w+\s*='
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
    # J7: underscore import to bypass unused_crate_dependencies
    'use\s+\w+\s+as\s+_;'
    # J8: extern crate in edition 2024 to bypass unused-dep warning
    '^extern\s+crate\s+'
    # J9: &*format!(...) temporary drop — creates dangling reference
    '&\*format!\('
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

STRICT_SECTIONS=(A B C L M N O)

# `--strict-sections A,B,C` overrides the gating set. The CI workers use this
# to hold NEW code to a stricter bar than the legacy baseline: panics (A),
# swallowed errors (B) and lint suppressions (C) are never acceptable in
# fresh code, whereas L/M/N/O are domain-legitimate inside exploit modules
# (md5 for JA3 fingerprints, RC4 for legacy protocols, and so on).
if [ -n "$STRICT_SECTIONS_OVERRIDE" ]; then
    IFS=',' read -r -a STRICT_SECTIONS <<< "$STRICT_SECTIONS_OVERRIDE"
fi

GRAND_TOTAL=0
GRAND_PATTERNS=0
GRAND_PATTERNS_HIT=0
STRICT_HITS=0
COUNTS_TSV=""

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
        c=$(grep -hE "$p" "$CORPUS" 2>/dev/null \
            | grep -vE '^\s*//' \
            | grep -vE '// audit-allow:' \
            | wc -l)
        # Machine-readable per-pattern count (section<TAB>pattern<TAB>count).
        COUNTS_TSV="${COUNTS_TSV}${label}	${p}	${c}
"
        # Detailed report: every individual hit with its file and line, so
        # the CI workers can turn them into inline PR annotations and show
        # the operator exactly what is broken.
        if [ -n "$REPORT_FILE" ] && [ "$c" -gt 0 ]; then
            grep -HnE "$p" $ALL_RS 2>/dev/null \
                | grep -vE '^[^:]*:[0-9]+:\s*//' \
                | grep -vE '// audit-allow:' \
                | while IFS= read -r hit; do
                    f="${hit%%:*}"
                    rest="${hit#*:}"
                    ln="${rest%%:*}"
                    text="${rest#*:}"
                    printf '%s\t%s\t%s\t%s\t%s\n' \
                        "$label" "$f" "$ln" "$p" "$text" >> "$REPORT_FILE"
                done
        fi
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

    local s
    for s in "${STRICT_SECTIONS[@]}"; do
        if [ "$s" = "$label" ]; then
            STRICT_HITS=$((STRICT_HITS + total))
            break
        fi
    done
}

per_file_gate() {
    # --- per-file baseline gate -------------------------------------------------
    # The aggregate baseline compares PER-PATTERN totals, so a fix in one file can
    # mask a new violation in another (net zero). This mode compares PER-FILE
    # PER-SECTION counts instead, which closes that hole: every file is held to
    # its own recorded number.
    #
    # Format: <file>\t<section>\t<count>
    if [ -n "$FILE_BASELINE" ] || [ -n "$UPDATE_FILE_BASELINE" ]; then
        # Join a section's patterns into ONE ERE alternation.
        #
        # The separator must be '|', not the default IFS character (space):
        # a space-joined string would be word-split by the shell and grep
        # would receive the extra words as FILE arguments instead of part of
        # the pattern.
        join_patterns() {
            local IFS='|'
            echo "$*"
        }
        declare -A SECTION_PATTERNS
        SECTION_PATTERNS[A]="$(join_patterns "${A[@]}")"
        SECTION_PATTERNS[B]="$(join_patterns "${B[@]}")"
        SECTION_PATTERNS[C]="$(join_patterns "${C[@]}")"
        SECTION_PATTERNS[D]="$(join_patterns "${D[@]}")"
        SECTION_PATTERNS[E]="$(join_patterns "${E[@]}")"
        SECTION_PATTERNS[F]="$(join_patterns "${F[@]}")"
        SECTION_PATTERNS[G]="$(join_patterns "${G[@]}")"
        SECTION_PATTERNS[H]="$(join_patterns "${H[@]}")"
        SECTION_PATTERNS[I]="$(join_patterns "${I[@]}")"
        SECTION_PATTERNS[J]="$(join_patterns "${J[@]}")"
        SECTION_PATTERNS[L]="$(join_patterns "${L[@]}")"
        SECTION_PATTERNS[M]="$(join_patterns "${M[@]}")"
        SECTION_PATTERNS[N]="$(join_patterns "${N[@]}")"
        SECTION_PATTERNS[O]="$(join_patterns "${O[@]}")"
        SECTION_PATTERNS[P]="$(join_patterns "${P[@]}")"

        # Which sections are compared. Defaults to the strict set; override with
        # --strict-sections.
        COMPARE_SECTIONS=("${STRICT_SECTIONS[@]}")

        FILE_TSV=""
        while IFS= read -r f; do
            [ -z "$f" ] && continue
            [ -f "$f" ] || continue
            for s in "${COMPARE_SECTIONS[@]}"; do
                pats="${SECTION_PATTERNS[$s]}"
                [ -z "$pats" ] && continue
                c=$(grep -hE "$pats" "$f" 2>/dev/null \
                    | grep -vE '^\s*//' \
                    | grep -vE '// audit-allow:' \
                    | wc -l)
                FILE_TSV="${FILE_TSV}${f}	${s}	${c}
"
            done
        done <<< "$ALL_RS"

        if [ -n "$UPDATE_FILE_BASELINE" ]; then
            {
                echo "# rustsploit per-file bad-pattern baseline"
                echo "# Generated by scripts/audit-bad-patterns.sh --update-file-baseline"
                echo "# Format: <file>\t<section>\t<count>"
                echo "#"
                echo "# Each file is held to its OWN count, so fixing a violation in"
                echo "# one file cannot mask a new violation in another."
                printf '%s' "$FILE_TSV"
            } > "$UPDATE_FILE_BASELINE"
            echo "  Per-file baseline written: $UPDATE_FILE_BASELINE"
            exit 0
        fi

        if [ ! -f "$FILE_BASELINE" ]; then
            echo "  RESULT                  : FAIL — per-file baseline '$FILE_BASELINE' not found"
            exit 1
        fi

        declare -A FBASE=()
        while IFS=$'\t' read -r f s c; do
            case "$f" in ''|\#*) continue ;; esac
            FBASE["${f}|${s}"]="$c"
        done < "$FILE_BASELINE"

        file_regressions=0
        while IFS=$'\t' read -r f s c; do
            case "$f" in ''|\#*) continue ;; esac
            key="${f}|${s}"
            if [ -z "${FBASE[$key]+present}" ]; then
                # A file that is not in the baseline at all (new file, or a
                # section newly compared) must be clean.
                if [ "$c" -gt 0 ]; then
                    echo "  NEW VIOLATION [$s] $f : $c hit(s) (file not in per-file baseline)"
                    file_regressions=$((file_regressions + 1))
                fi
                continue
            fi
            base_c="${FBASE[$key]}"
            if [ "$c" -gt "$base_c" ]; then
                echo "  REGRESSION [$s] $f : $base_c -> $c"
                file_regressions=$((file_regressions + 1))
            fi
        done <<< "$FILE_TSV"

        # Files that disappeared from the tree are ignored — their baseline
        # entries simply never match.
        if [ "$file_regressions" -gt 0 ]; then
            echo "  RESULT                  : FAIL — $file_regressions per-file regression(s)"
            exit 1
        fi
        echo "  RESULT                  : PASS — no per-file regressions"
        exit 0
    fi
}

# The per-file gate answers a different question than the aggregate one,
# and it does not need the full pattern sweep — dispatch to it early so
# it stays fast.
if [ -n "$FILE_BASELINE" ] || [ -n "$UPDATE_FILE_BASELINE" ]; then
    per_file_gate
    exit $?
fi

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

# --- machine-readable output ------------------------------------------------
if [ -n "$COUNTS_FILE" ]; then
    printf '%s' "$COUNTS_TSV" > "$COUNTS_FILE"
    echo "  Counts file            : $COUNTS_FILE"
fi

if [ -n "$UPDATE_BASELINE" ]; then
    {
        echo "# rustsploit bad-pattern baseline"
        echo "# Generated by scripts/audit-bad-patterns.sh --update-baseline"
        echo "# Format: <section>\t<pattern>\t<count>"
        echo "#"
        echo "# The CI gate fails only when a count INCREASES above the value"
        echo "# recorded here. Lower it whenever you fix a violation — that is"
        echo "# how legacy debt is paid down without the gate going green-blind."
        printf '%s' "$COUNTS_TSV"
    } > "$UPDATE_BASELINE"
    echo "  Baseline written       : $UPDATE_BASELINE"
    exit 0
fi

# --- baseline gate ----------------------------------------------------------
if [ -n "$BASELINE_FILE" ]; then
    if [ ! -f "$BASELINE_FILE" ]; then
        echo "  RESULT                  : FAIL — baseline file '$BASELINE_FILE' not found"
        exit 1
    fi
    regressions=0
    # Load baseline and current counts into associative arrays keyed by
    # "<section>|<pattern>". Deliberately avoids awk: the patterns contain
    # backslash escapes and unescaped '|' alternations, which awk mangles
    # (and warns about) when used as string literals.
    declare -A base_counts=()
    declare -A cur_counts=()
    while IFS=$'\t' read -r b_section b_pattern b_count; do
        case "$b_section" in ''|\#*) continue ;; esac
        base_counts["${b_section}|${b_pattern}"]="$b_count"
    done < "$BASELINE_FILE"
    while IFS=$'\t' read -r c_section c_pattern c_count; do
        case "$c_section" in ''|\#*) continue ;; esac
        cur_counts["${c_section}|${c_pattern}"]="$c_count"
    done <<< "$COUNTS_TSV"

    # A pattern whose count INCREASED is a regression.
    for key in "${!base_counts[@]}"; do
        b_count="${base_counts[$key]}"
        current="${cur_counts[$key]:-0}"
        if [ "$current" -gt "$b_count" ]; then
            echo "  REGRESSION [$key] : $b_count -> $current"
            regressions=$((regressions + 1))
        fi
    done

    # A pattern that is not in the baseline at all is a brand-new violation.
    for key in "${!cur_counts[@]}"; do
        c_count="${cur_counts[$key]}"
        [ "$c_count" -eq 0 ] && continue
        if [ -z "${base_counts[$key]+present}" ]; then
            echo "  NEW VIOLATION [$key] : $c_count hit(s) not in baseline"
            regressions=$((regressions + 1))
        fi
    done

    if [ "$regressions" -gt 0 ]; then
        echo "  RESULT                  : FAIL — $regressions new violation(s) vs baseline"
        exit 1
    fi
    echo "  RESULT                  : PASS — no regressions vs baseline"
    exit 0
fi

# --- baseline drift report ----------------------------------------------------
# Compare the current counts against a baseline and report the direction of
# every change:
#   UP   — a pattern gained hits. New violations; the CI gate should have
#          blocked them. If this shows up on the nightly run, the gate is not
#          covering that path.
#   DOWN — a pattern lost hits. Legacy debt was paid down, so the baseline
#          can be tightened with --update-baseline.
#
# Exits 1 if anything went UP, 0 otherwise.
if [ -n "$DRIFT_REPORT" ]; then
    if [ ! -f "$DRIFT_REPORT" ]; then
        echo "  RESULT                  : FAIL — baseline file '$DRIFT_REPORT' not found"
        exit 1
    fi
    declare -A d_base=()
    declare -A d_cur=()
    while IFS=$'\t' read -r b_section b_pattern b_count; do
        case "$b_section" in ''|\#*) continue ;; esac
        d_base["${b_section}|${b_pattern}"]="$b_count"
    done < "$DRIFT_REPORT"
    while IFS=$'\t' read -r c_section c_pattern c_count; do
        case "$c_section" in ''|\#*) continue ;; esac
        d_cur["${c_section}|${c_pattern}"]="$c_count"
    done <<< "$COUNTS_TSV"

    up=0
    down=0
    for key in "${!d_base[@]}"; do
        b_count="${d_base[$key]}"
        current="${d_cur[$key]:-0}"
        if [ "$current" -gt "$b_count" ]; then
            echo "  UP    [$key] : $b_count -> $current"
            up=$((up + 1))
        elif [ "$current" -lt "$b_count" ]; then
            echo "  DOWN  [$key] : $b_count -> $current   (baseline can be tightened)"
            down=$((down + 1))
        fi
    done
    # Patterns that are not in the baseline at all are new violations.
    for key in "${!d_cur[@]}"; do
        c_count="${d_cur[$key]}"
        [ "$c_count" -eq 0 ] && continue
        if [ -z "${d_base[$key]+present}" ]; then
            echo "  UP    [$key] : 0 -> $c_count   (not in baseline)"
            up=$((up + 1))
        fi
    done
    echo "  DRIFT SUMMARY           : $up up, $down down"
    if [ "$up" -gt 0 ]; then
        echo "  RESULT                  : DRIFT — $up pattern(s) gained hits"
        exit 1
    fi
    echo "  RESULT                  : DRIFT — no increases ($down pattern(s) can be tightened)"
    exit 0
fi

if [ "$STRICT" = "1" ] && [ "$STRICT_HITS" -gt 0 ]; then
    echo "  RESULT                  : STRICT FAILURE — fix before merge"
    exit 1
fi
echo "  RESULT                  : informational only (use --strict to gate)"
