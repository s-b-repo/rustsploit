#!/usr/bin/env bash
# =============================================================================
# check-docs.sh — documentation quality gate
#
# Enforces three invariants so the wiki cannot silently rot:
#   1. LINKS       every relative markdown link in docs/, README.md, and
#                  CLAUDE.md resolves to a real file
#   2. STALENESS   banned tokens (removed APIs, machine paths, dead counts,
#                  phantom endpoints) must not appear in *current* docs —
#                  historical records (docs/Changelog.md, docs/Legacy.md,
#                  docs/perf/) are excluded from the staleness scan, and
#                  negation lines ("no has_check arm", "was removed") are
#                  whitelisted per-rule
#   3. COVERAGE    every file in docs/*.md is reachable: listed in Home.md
#                  or linked from any other markdown file
#
# Usage:  scripts/check-docs.sh          # report + exit non-zero on failure
# Exit:   0 = clean, 1 = violations found
# =============================================================================
set -u
cd "$(dirname "$0")/.."

fail=0

note()  { printf '  %s\n' "$*"; }
bad()   { printf '  ✗ %s\n' "$*"; fail=1; }
hdr()   { printf '\n== %s ==\n' "$*"; }

# ---------------------------------------------------------------------------
hdr "1. Link check"
# ---------------------------------------------------------------------------
mapfile -t SRC_FILES < <(ls docs/*.md docs/perf/*.md README.md CLAUDE.md 2>/dev/null)
link_count=0
for f in "${SRC_FILES[@]}"; do
  # strip fenced code blocks so shell snippets don't produce false links
  body=$(awk '/^```/{inblk=!inblk; next} !inblk' "$f")
  while IFS= read -r link; do
    [ -z "$link" ] && continue
    case "$link" in
      http://*|https://*|mailto:*|\#*) continue ;;
    esac
    target="${link%%#*}"
    [ -z "$target" ] && continue
    dir=$(dirname "$f")
    if [ ! -e "$dir/$target" ]; then
      bad "$f -> $link (missing: $dir/$target)"
    fi
    link_count=$((link_count + 1))
  done < <(printf '%s\n' "$body" | grep -oP '\]\(\K[^)]+')
done
[ "$fail" -eq 0 ] && note "all $link_count relative markdown links resolve"

# ---------------------------------------------------------------------------
hdr "2. Staleness scan (current docs only)"
# ---------------------------------------------------------------------------
# Historical records where removed-API mentions are intentional:
EXCLUDE='docs/Changelog\.md|docs/Legacy\.md|docs/perf/|docs/edition-2026-migration\.md'
CURRENT_MD=$(ls docs/*.md README.md CLAUDE.md 2>/dev/null | grep -vE "$EXCLUDE")

scan() { # scan <label> <regex> [<negation-regex>]
  local label="$1" re="$2" neg="${3:-^NOPE$}" out
  out=$(grep -nE "$re" $CURRENT_MD 2>/dev/null | grep -vE "$neg")
  if [ -n "$out" ]; then
    bad "banned token [$label]:"
    printf '%s\n' "$out" | sed 's/^/      /'
  fi
}

scan "CheckResult"         'CheckResult'                       'removed|do not add|no .CheckResult|without-else'
scan "has_check"           'has_check'                         'no .has_check|There is \*\*no'
scan "check() phase"       'pub async fn check|POST /api/check|check shell command|vulnerability check\(' 'no .*check|Not implemented|non-destructive vulnerability check\('
scan "machine path"        '/home/[a-z]+/|/tmp/my_files|rustpre2'
scan "old honeypot"        'basic_honeypot_check|200 ports|250 ?ms'
scan "phantom constant"    'MAX_REQUEST_BODY_SIZE|MAX_TRACKED_IPS'
scan "deleted module path" 'modules/creds/utils\.rs|crate::modules::creds::utils' 'moved here|deleted in'
scan "phantom CLI flag"    '--output-format'
scan "phantom endpoints"   '/api/status|/api/ips'
scan "stale module count"  '389 modules|389 self-registering|All 389|363 modules|388 of 388|~380 self'
scan "stale matrix count"  '133-regex|133 regex|91 regex|95\+ regex|95\+ pattern|131 regex'
scan "phantom tool"        'check_module tool|31 RustSploit tools'
scan "old version story"   'v0\.5\.0 \(2026-06-13\)'
scan "1 MB body limit"     '1 MB max|limit \| 1 MB'
scan "malformed table row" '^\|\|'
[ "$fail" -eq 0 ] && note "no banned tokens in current docs"

# ---------------------------------------------------------------------------
hdr "3. Coverage — every wiki file reachable"
# ---------------------------------------------------------------------------
for f in docs/*.md docs/perf/*.md; do
  base=$(basename "$f")
  if ! grep -rqF "$base)" docs/*.md docs/perf/*.md README.md 2>/dev/null; then
    bad "$f is not linked from any markdown file (orphan)"
  fi
done
[ "$fail" -eq 0 ] && note "all docs/*.md files are linked"

# ---------------------------------------------------------------------------
printf '\n== RESULT ==\n'
if [ "$fail" -eq 0 ]; then
  echo "check-docs: clean"
  exit 0
else
  echo "check-docs: FAIL — fix the items above"
  exit 1
fi
