#!/usr/bin/env python3
"""Check relative links and #anchors in the repository's Markdown files.

Usage: python3 scripts/check-links.py [ROOT]

Read-only. Uses only the Python standard library. External (http/https/
mailto) links are not checked, so the script needs no network access.
Exits 0 when every link resolves, 1 otherwise.
"""

import pathlib
import re
import sys

SKIP_DIRS = {".git", "target", ".memsearch", "node_modules"}
LINK = re.compile(r"\]\(([^)\s]+)\)")
FENCE = re.compile(r"```.*?```", re.S)


def slug(heading: str) -> str:
    """Approximate GitHub's heading anchor rules."""
    text = re.sub(r"[`*_]", "", heading.strip().lower())
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def anchors(path: pathlib.Path) -> set[str]:
    text = FENCE.sub("", path.read_text(encoding="utf-8"))
    return {slug(m.group(1)) for m in re.finditer(r"^#+\s+(.+)$", text, re.M)}


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    broken = 0
    for md in sorted(root.rglob("*.md")):
        if SKIP_DIRS.intersection(md.relative_to(root).parts):
            continue
        text = FENCE.sub("", md.read_text(encoding="utf-8"))
        for link in LINK.findall(text):
            if re.match(r"(https?|mailto):", link):
                continue
            path, _, fragment = link.partition("#")
            target = (md.parent / path).resolve() if path else md
            where = md.relative_to(root)
            if not target.exists():
                print(f"broken link: {where} -> {link}")
                broken += 1
            elif fragment and target.suffix == ".md" and fragment not in anchors(target):
                print(f"broken anchor: {where} -> {link}")
                broken += 1
    print(f"checked Markdown links under {root}: {broken} broken")
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
