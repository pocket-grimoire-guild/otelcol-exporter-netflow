#!/usr/bin/env python3
"""Check public documentation and repository-relative file links."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    "README.md", "CONTRIBUTING.md", "SECURITY.md", "ARCHITECTURE.md",
    "docs/README.md", "docs/operator-guide.md", "docs/release.md",
    "docs/product-specs/netflow-exporter.md",
    "docs/compatibility/receiver-attributes.md",
    "docs/compatibility/protocol-mapping.md",
    "distribution/ocb/README.md", "distribution/ocb/consumer/README.md",
]
IGNORED = {".git", ".venv", "bin", "dist", "artifacts", "__pycache__"}
LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
REFERENCE_RE = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*(\S+)", re.MULTILINE)


def markdown_files():
    for directory, dirs, files in os.walk(ROOT):
        dirs[:] = sorted(name for name in dirs if name not in IGNORED)
        for name in sorted(files):
            if name.endswith(".md"):
                yield Path(directory) / name


def main() -> int:
    errors: list[str] = []
    for relative in REQUIRED:
        if not (ROOT / relative).is_file():
            errors.append(f"missing required file: {relative}")

    paths = list(markdown_files())
    for path in paths:
        text = path.read_text(encoding="utf-8")
        if "\t" in text:
            errors.append(f"tab character in Markdown: {path.relative_to(ROOT)}")
        if not text.endswith("\n"):
            errors.append(f"missing final newline: {path.relative_to(ROOT)}")
        for raw in LINK_RE.findall(text) + REFERENCE_RE.findall(text):
            target = raw.strip().strip("<>")
            if not target or target.startswith(("https://", "http://", "mailto:", "#")):
                continue
            target = target.split("#", 1)[0]
            resolved = (path.parent / target).resolve()
            try:
                resolved.relative_to(ROOT.resolve())
            except ValueError:
                errors.append(f"relative link escapes repository: {path.relative_to(ROOT)} -> {target}")
                continue
            if not resolved.exists():
                errors.append(f"broken relative link: {path.relative_to(ROOT)} -> {target}")

    if errors:
        print("documentation checks failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(f"documentation checks passed ({len(paths)} Markdown files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
