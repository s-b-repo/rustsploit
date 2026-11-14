#!/usr/bin/env bash
# =============================================================================
# annotate-findings.sh — turn audit findings into GitHub annotations
#
# Usage:
#   scripts/annotate-findings.sh <findings.tsv> [title]
#
# Input: TSV with five columns
#   <section>\t<file>\t<line>\t<pattern>\t<source text>
#
# Output:
#   - one GitHub workflow-command annotation per finding, so the finding
#     appears INLINE on the pull-request diff next to the offending line
#   - a "BROKEN" section appended to $GITHUB_STEP_SUMMARY (when set)
#
# A finding in a strict section (A: panics, B: swallowed errors, C: lint
# suppression) is an ERROR annotation: it means the code can crash, hide a
# failure, or silence a lint. Everything else is a WARNING annotation.
#
# Exit status: 0 always — the annotation step is a report, not a gate. The
# gates are `--baseline` / `--file-baseline`.
# =============================================================================
set -uo pipefail

FINDINGS="${1:-}"
TITLE="${2:-BROKEN}"
SUMMARY_FILE="${GITHUB_STEP_SUMMARY:-}"

if [ -z "$FINDINGS" ] || [ ! -f "$FINDINGS" ]; then
    echo "usage: $0 <findings.tsv> [title]" >&2
    exit 0
fi

# Sections that are hard failures rather than advisory.
STRICT_SECTIONS=" A B C "

total=0
errors=0
warnings=0
: > /tmp/rsf-annotate-lines.txt 2>/dev/null || true

while IFS=$'\t' read -r section file line pattern text; do
    case "$section" in ''|\#*) continue ;; esac
    [ -z "$file" ] && continue
    total=$((total + 1))

    # Truncate the source text so a long line cannot blow up the annotation.
    snippet=$(printf '%s' "$text" | tr '\t' ' ' | cut -c1-160)

    if [[ "$STRICT_SECTIONS" == *" $section "* ]]; then
        level="error"
        errors=$((errors + 1))
        label="BROKEN"
    else
        level="warning"
        warnings=$((warnings + 1))
        label="BANNED"
    fi

    echo "::${level} file=${file},line=${line},title=${label} [${section}] ${pattern}::${snippet}"
    printf -- "- \`%s:%s\` **[%s]** \`%s\` — %s\n" \
        "$file" "$line" "$section" "$pattern" "$snippet" \
        >> /tmp/rsf-annotate-lines.txt 2>/dev/null || true
done < "$FINDINGS"

echo "::notice title=${TITLE}::${total} finding(s): ${errors} broken (A/B/C), ${warnings} banned (other sections)"

if [ -n "$SUMMARY_FILE" ]; then
    {
        echo ""
        echo "## ${TITLE}"
        echo ""
        if [ "$total" -eq 0 ]; then
            echo "No findings."
        else
            echo "\`${errors}\` **broken** (panic / swallowed error / lint suppression) and \`${warnings}\` **banned** (other matrix sections)."
            echo ""
            echo "<details><summary>Show all ${total}</summary>"
            echo ""
            cat /tmp/rsf-annotate-lines.txt 2>/dev/null || true
            echo ""
            echo "</details>"
        fi
    } >> "$SUMMARY_FILE"
fi

rm -f /tmp/rsf-annotate-lines.txt 2>/dev/null || true
exit 0
