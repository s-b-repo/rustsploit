#!/usr/bin/env python3
"""Regenerate docs/Module-Catalog.md WITHOUT building the binary.

The canonical generator is `module::render_catalog_markdown()` in the Rust
tree, invoked by `rustsploit --gen-module-catalog`. This script exists for
one reason: linking a ~690-module binary needs a few GB of RAM, and some
machines (and some CI containers) do not have it.

It parses the `register_native_module!` calls and each module's `info()`
metadata straight out of the source and emits the same markdown.

IT IS NOT THE SOURCE OF TRUTH. CI's `module-catalog` job regenerates the
catalog with the REAL binary and fails if the result differs, so any drift
between this script and the Rust generator is caught immediately. If the two
ever disagree, the Rust generator wins and this script is the bug.

Usage:
    python3 scripts/gen-module-catalog.py [repo-root] > docs/Module-Catalog.md
"""


import pathlib
import re
import sys

CATEGORY_ORDER = ["scanners", "exploits", "creds", "osint", "plugins", "post"]

REGISTER_RE = re.compile(
    r"register_native_module!\s*\(\s*"
    r"(?:crate::module::)?Category::(\w+)\s*,\s*"
    r'"([^"]+)"',
    re.M,
)

RANK_RE = re.compile(r"rank:\s*(?:[\w:]*::)?ModuleRank::(\w+)")

INFO_FN_RE = re.compile(r"pub\s+fn\s+info\s*\(")


def strip_comments(text: str) -> str:
    """Remove line comments so doc examples are not mistaken for code."""
    out = []
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped.startswith("//"):
            out.append("\n")
        else:
            out.append(line)
    return "".join(out)


def read_description(text: str) -> str:
    """The first line of the `description:` field, as Rust would render it.

    A trailing backslash inside a Rust string literal continues the literal on
    the next line AND strips that line's leading whitespace, so the joined
    string has no newline in it. The catalog shows the first line of that
    joined string.
    """
    m = re.search(r"description:\s*", text)
    if not m:
        return ""
    rest = text[m.end():].lstrip()
    if not rest.startswith('"'):
        return ""
    # Scan the literal, honouring backslash escapes.
    i = 1
    buf = []
    while i < len(rest):
        ch = rest[i]
        if ch == "\\" and i + 1 < len(rest):
            buf.append(rest[i:i + 2])
            i += 2
            continue
        if ch == '"':
            break
        buf.append(ch)
        i += 1
    literal = "".join(buf)
    # A backslash at the end of a line continues the literal and drops the
    # newline plus the next line's leading whitespace.
    literal = re.sub(r"\\\s*\n\s*", "", literal)
    # Undo the escapes Rust would have interpreted.
    literal = (
        literal.replace("\\\\", "\x00")
        .replace('\\n', "\n")
        .replace('\\"', '"')
        .replace("\\t", "\t")
        .replace("\x00", "\\")
    )
    return literal.split("\n")[0]


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    src = root / "src"
    if not src.is_dir():
        print(f"no src/ under {root}", file=sys.stderr)
        return 2

    entries = []  # (category, name, description, rank)
    modules_dir = src / "modules"
    for path in sorted(modules_dir.rglob("*.rs")):
        raw = path.read_text(errors="replace")
        if "register_native_module!" not in raw:
            continue
        # Doc examples inside `//!` comments mention register_native_module!
        # too — they are not real registrations.
        text = strip_comments(raw)
        # Anchor the metadata lookup at the module's `info()` function: a
        # struct field named `description` earlier in the file is not the
        # module description.
        info_at = INFO_FN_RE.search(text)
        scope = text[info_at.start():] if info_at else text
        desc = read_description(scope)
        rank_match = RANK_RE.search(scope)
        rank = rank_match.group(1) if rank_match else "Normal"
        for category, name in REGISTER_RE.findall(text):
            entries.append((category.lower(), name, desc, rank))

    by_cat = {}
    for category, name, desc, rank in entries:
        by_cat.setdefault(category, []).append((name, desc, rank))
    for v in by_cat.values():
        v.sort(key=lambda e: e[0])

    total = len(entries)
    out = []
    out.append("# Module Catalog\n\n")
    out.append("> Auto-generated from the inventory registry by ")
    out.append("`rustsploit --gen-module-catalog`. Do not edit by hand.\n\n")
    out.append(f"**Total registered modules: {total}**\n\n")
    out.append(
        "All modules support mass scan universally — `random` / CIDR / file targets / "
        "comma-separated lists fan out through `crate::scheduler::run` regardless of "
        "the module.\n\n"
    )

    for cat in CATEGORY_ORDER:
        items = by_cat.get(cat)
        if not items:
            continue
        out.append(f"## {cat} ({len(items)})\n\n")
        out.append("| Module | Description | Rank |\n")
        out.append("|---|---|---|\n")
        for name, desc, rank in items:
            out.append(f"| `{cat}/{name}` | {desc.replace('|', chr(92) + '|')} | {rank} |\n")
        out.append("\n")

    sys.stdout.write("".join(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
