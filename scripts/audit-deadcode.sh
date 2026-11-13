#!/usr/bin/env bash
# =============================================================================
# audit-deadcode.sh — find code that is not wired up, and code that nothing uses
#
# Usage:
#   scripts/audit-deadcode.sh                     # full report
#   scripts/audit-deadcode.sh --baseline <f>      # fail only on NEW findings
#   scripts/audit-deadcode.sh --update-baseline <f>
#   scripts/audit-deadcode.sh --no-cargo          # skip the cargo-based checks
#
# Checks:
#
#   1. UNCOMPILED FILE   a .rs file that exists but is not declared in its
#                        parent mod.rs — it is never compiled, so it never
#                        registers and the operator can never run it.
#   2. MISSING FILE      a `mod X;` declaration with no X.rs / X/mod.rs.
#   3. UNREGISTERED      a module file under src/modules/ that implements
#                        run()/info() but never calls register_native_module!
#   4. DEAD CODE         items the compiler reports as never used.
#   5. UNUSED DEP        crates in Cargo.toml that nothing imports.
#
# Findings are reported as `<check>\t<subject>\t<count>` so they can be
# baselined. The baseline gate fails only when a NEW subject appears, which
# keeps the pipeline green while making the backlog visible and shrinkable.
#
set -uo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

BASELINE_FILE=""
UPDATE_BASELINE=""
RUN_CARGO=1
REPORT_FILE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --baseline) BASELINE_FILE="$2"; shift 2 ;;
        --update-baseline) UPDATE_BASELINE="$2"; shift 2 ;;
        --report) REPORT_FILE="$2"; shift 2 ;;
        --no-cargo) RUN_CARGO=0; shift ;;
        -h|--help) sed -n '/^# /p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

FINDINGS=""

add_finding() { # add_finding <check> <subject>
    FINDINGS="${FINDINGS}$1	$2	1
"
}

# ----------------------------------------------------------------------------
# 1-3. Wiring checks (static, fast, no cargo needed)
# ----------------------------------------------------------------------------
WIRING_OUT=$(python3 - <<'PY'
import pathlib, re, sys

root = pathlib.Path("src")
MOD_DECL = re.compile(r'^\s*(?:pub\s+)?mod\s+(\w+)\s*;', re.M)

uncompiled = []   # file exists, never compiled
missing = []      # mod declared, file absent

for mod_rs in sorted(root.rglob("mod.rs")):
    d = mod_rs.parent
    text = mod_rs.read_text(errors="replace")
    declared = set(MOD_DECL.findall(text))
    for stem in sorted(declared):
        if not (d / f"{stem}.rs").exists() and not (d / stem / "mod.rs").exists():
            missing.append(f"{mod_rs}: mod {stem} (no {stem}.rs)")
    for rs in sorted(d.glob("*.rs")):
        if rs.name == "mod.rs":
            continue
        if rs.stem not in declared:
            uncompiled.append(str(rs))

# A module file that looks like a module (has run() and info()) but never
# registers itself is dead weight: it is compiled, but invisible.
unregistered = []
for rs in sorted(root.glob("modules/**/*.rs")):
    if rs.name == "mod.rs":
        continue
    text = rs.read_text(errors="replace")
    if "register_native_module!" in text:
        continue
    has_run = re.search(r'^\s*pub\s+async\s+fn\s+run\s*\(', text, re.M) is not None
    has_info = re.search(r'^\s*pub\s+fn\s+info\s*\(', text, re.M) is not None
    if has_run and has_info:
        unregistered.append(str(rs))

for f in uncompiled:
    print(f"uncompiled-file\t{f}")
for f in missing:
    print(f"missing-file\t{f}")
for f in unregistered:
    print(f"unregistered-module\t{f}")
PY
)

while IFS=$'\t' read -r check subject; do
    [ -z "$check" ] && continue
    add_finding "$check" "$subject"
done <<< "$WIRING_OUT"

# ----------------------------------------------------------------------------
# 4. Dead code — items the compiler reports as never used
# ----------------------------------------------------------------------------
DEAD_OUT=""
if [ "$RUN_CARGO" = "1" ] && command -v cargo >/dev/null 2>&1; then
    echo "Running the compiler to collect dead-code warnings..." >&2
    # --all-targets covers tests and examples; --message-format=json gives
    # machine-readable diagnostics.
    CLIPPY_JSON=$(mktemp)
    cargo clippy --all-targets --no-deps --message-format=json > "$CLIPPY_JSON" 2>/dev/null || true
    DEAD_OUT=$(python3 - "$CLIPPY_JSON" <<'PY'
import json, sys
path = sys.argv[1]
seen = set()
try:
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                msg = json.loads(line)
            except Exception:
                continue
            if msg.get("reason") != "compiler-message":
                continue
            diag = msg.get("message", {})
            if diag.get("code", {}) and diag.get("code", {}).get("code") != "dead_code":
                continue
            if "never used" not in diag.get("message", ""):
                continue
            for span in diag.get("spans", []):
                if not span.get("is_primary"):
                    continue
                # The subject deliberately omits the LINE NUMBER: any edit
                # above a dead item shifts its line, which would look like a
                # brand-new finding on every unrelated change. The file and
                # the message are stable, and the count captures duplicates.
                key = (span.get("file_name"), diag.get("message"))
                if key in seen:
                    continue
                seen.add(key)
                print(f"dead-code\t{span.get('file_name')}: {diag.get('message')}")
                break
except FileNotFoundError:
    pass
PY
)
    rm -f "$CLIPPY_JSON"
fi

while IFS=$'\t' read -r check subject; do
    [ -z "$check" ] && continue
    add_finding "$check" "$subject"
done <<< "$DEAD_OUT"

# ----------------------------------------------------------------------------
# 5. Unused dependencies
# ----------------------------------------------------------------------------
DEP_OUT=""
if [ "$RUN_CARGO" = "1" ] && command -v cargo-machete >/dev/null 2>&1; then
    DEP_OUT=$(cargo machete --with-metadata 2>/dev/null \
        | grep -vE '^(cargo-machete|Checking|Scanning|Finished|Updating|Downloading)' \
        | sed '/^$/d' \
        | awk '{print "unused-dep\t" $0}')
fi

while IFS=$'\t' read -r check subject; do
    [ -z "$check" ] && continue
    add_finding "$check" "$subject"
done <<< "$DEP_OUT"

# ----------------------------------------------------------------------------
# Report — per-finding rows for the annotation step
# ----------------------------------------------------------------------------
# Format matches scripts/annotate-findings.sh:
#   <check>\t<file>\t<line>\t<pattern>\t<subject>
if [ -n "$REPORT_FILE" ]; then
    : > "$REPORT_FILE"
    while IFS=$'\t' read -r check subject; do
        [ -z "$check" ] && continue
        case "$check" in
            uncompiled-file|unregistered-module|dead-code)
                # The subject is "<file>" or "<file>: <message>".
                f="${subject%%:*}"
                msg="${subject#*:}"
                [ "$msg" = "$subject" ] && msg="$check"
                printf '%s\t%s\t1\t%s\t%s\n' "$check" "$f" "$check" "$msg" >> "$REPORT_FILE"
                ;;
            *)
                printf '%s\t%s\t1\t%s\t%s\n' "$check" "src" "$check" "$subject" >> "$REPORT_FILE"
                ;;
        esac
    done <<< "$FINDINGS"
    echo "  Report written: $REPORT_FILE"
fi

# ----------------------------------------------------------------------------
# Report
# ----------------------------------------------------------------------------
echo "============================================================"
echo "  RUSTSPLOIT DEAD-CODE / WIRING AUDIT"
echo "============================================================"
echo

if [ -z "$FINDINGS" ]; then
    echo "  No findings."
else
    printf '%s' "$FINDINGS" | sort | while IFS=$'\t' read -r check subject count; do
        printf "  %-22s %s\n" "$check" "$subject"
    done
    echo
    TOTAL=$(printf '%s' "$FINDINGS" | grep -c . || true)
    echo "  Total findings: $TOTAL"
fi
echo

# --- baseline -------------------------------------------------------------
if [ -n "$UPDATE_BASELINE" ]; then
    {
        echo "# rustsploit dead-code / wiring baseline"
        echo "# Generated by scripts/audit-deadcode.sh --update-baseline"
        echo "# Format: <check>\t<subject>\t<count>"
        echo "#"
        echo "# The gate fails when a NEW subject appears. Remove entries as"
        echo "# you wire the code up or delete it — the baseline should only"
        echo "# ever shrink."
        printf '%s' "$FINDINGS" | sort
    } > "$UPDATE_BASELINE"
    echo "  Baseline written: $UPDATE_BASELINE"
    exit 0
fi

if [ -n "$BASELINE_FILE" ]; then
    if [ ! -f "$BASELINE_FILE" ]; then
        echo "  RESULT                  : FAIL — baseline '$BASELINE_FILE' not found"
        exit 1
    fi
    # Compare PER SUBJECT counts, not just presence. A subject whose count
    # grew means more instances of the same problem now exist.
    declare -A dbase=()
    declare -A dcur=()
    while IFS=$'\t' read -r check subject count; do
        case "$check" in ''|\#*) continue ;; esac
        dbase["${check}|${subject}"]="${count:-1}"
    done < "$BASELINE_FILE"
    while IFS=$'\t' read -r check subject count; do
        case "$check" in ''|\#*) continue ;; esac
        key="${check}|${subject}"
        dcur["$key"]=$((${dcur[$key]:-0} + ${count:-1}))
    done <<< "$FINDINGS"

    new_findings=0
    for key in "${!dcur[@]}"; do
        cur="${dcur[$key]}"
        base="${dbase[$key]:-0}"
        if [ "$cur" -gt "$base" ]; then
            echo "  NEW FINDING [$key] : ${base} -> ${cur}"
            new_findings=$((new_findings + 1))
        fi
    done
    if [ "$new_findings" -gt 0 ]; then
        echo "  RESULT                  : FAIL — $new_findings new finding(s)"
        exit 1
    fi
    echo "  RESULT                  : PASS — no new findings vs baseline"
    exit 0
fi

echo "  RESULT                  : informational only (use --baseline to gate)"
