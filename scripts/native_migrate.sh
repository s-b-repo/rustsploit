#!/bin/bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
set -e
f="$1"
modname="$2"
if grep -q "use crate::module::{Finding" "$f"; then
    echo "  $f already migrated, skipping"
    exit 0
fi
sed -i "/^use crate::module_info::/a use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};" "$f"
sed -i 's|^use anyhow::Result;|use anyhow::{Context, Result};|' "$f"
sed -i 's|^use anyhow::{Result};|use anyhow::{Context, Result};|' "$f"
sed -i "s|pub async fn check(_target: \&str) -> CheckResult {|pub async fn check(_ctx: \&ModuleCtx) -> CheckResult {|" "$f"
sed -i "s|pub async fn check(target: \&str) -> CheckResult {|pub async fn check(ctx: \&ModuleCtx) -> CheckResult {\n    let target = match ctx.target.as_single() { Some(t) => t, None => return CheckResult::Error(\"check expects a single-host target\".into()) };|" "$f"
sed -i "s|pub async fn run(_target: \&str) -> Result<()> {|pub async fn run(_ctx: \&ModuleCtx) -> Result<ModuleOutcome> {\n    let mut outcome = ModuleOutcome::ok();|" "$f"
sed -i "s|pub async fn run(target: \&str) -> Result<()> {|pub async fn run(ctx: \&ModuleCtx) -> Result<ModuleOutcome> {\n    let target = ctx.target.as_single().context(\"${modname} requires a single-host target\")?;\n    let mut outcome = ModuleOutcome::ok();|" "$f"

python3 - "$f" << 'PYEOF'
import sys, re
fn = sys.argv[1]
txt = open(fn).read()
txt = re.sub(r'\bOk\(\(\)\)', 'Ok(outcome)', txt)
open(fn, "w").write(txt)
PYEOF

python3 - "$f" << 'PYEOF'
import sys, re
fn = sys.argv[1]
txt = open(fn).read()
pat = re.compile(
    r'(\s*)crate::workspace::track_host\(&([a-z_]+),\s*None,\s*Some\("([^"]+)"\)\)\.await;\s*$',
    re.MULTILINE,
)
def repl(m):
    indent = m.group(1)
    var = m.group(2)
    label = m.group(3)
    return (
        indent + 'crate::workspace::track_host(&' + var + ', None, Some("' + label + '")).await;\n'
        + indent + 'outcome.findings.push(Finding {\n'
        + indent + '    target: ' + var + '.clone(),\n'
        + indent + '    kind: FindingKind::Note,\n'
        + indent + '    message: format!("' + label + ' detected at {}", ' + var + '),\n'
        + indent + '    data: Some(serde_json::json!({\n'
        + indent + '        "host": ' + var + ',\n'
        + indent + '        "label": "' + label + '",\n'
        + indent + '    })),\n'
        + indent + '});'
    )
txt = pat.sub(repl, txt)
open(fn, "w").write(txt)
PYEOF

# Generic register macro update — handles any Category
python3 - "$f" << 'PYEOF'
import sys, re
fn = sys.argv[1]
txt = open(fn).read()
# Match: register_native_module!(... Category::X, "name"[, has_check]);
pat_check = re.compile(r'(crate::register_native_module!\(crate::module::Category::[A-Za-z]+,\s*"[^"]+"),\s*has_check\);')
txt = pat_check.sub(r'\1, native, has_check);', txt)
pat_nocheck = re.compile(r'(crate::register_native_module!\(crate::module::Category::[A-Za-z]+,\s*"[^"]+")\);')
def repl(m):
    if ', native' in m.group(0):
        return m.group(0)
    return m.group(1) + ', native);'
txt = pat_nocheck.sub(repl, txt)
open(fn, "w").write(txt)
PYEOF
echo "  $f migrated"
