#!/usr/bin/env python3
"""Validate source configuration and pinned CI inputs without network access."""

from __future__ import annotations

import json
import os
import re
import stat
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IGNORED = {".git", ".venv", "bin", "dist", "artifacts", "__pycache__"}
CI_ACTION_PINS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-go": "b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",
}


def source_files():
    for directory, dirs, files in os.walk(ROOT):
        dirs[:] = sorted(name for name in dirs if name not in IGNORED)
        for name in sorted(files):
            yield Path(directory) / name


def main() -> int:
    errors: list[str] = []
    parsed = 0
    scripts = 0
    for path in source_files():
        relative = path.relative_to(ROOT)
        if path.suffix in {".json", ".toml"}:
            try:
                text = path.read_text(encoding="utf-8")
                if path.suffix == ".json":
                    json.loads(text)
                else:
                    tomllib.loads(text)
                parsed += 1
            except (OSError, ValueError) as exc:
                errors.append(f"invalid configuration {relative}: {exc}")
        if path.suffix == ".sh":
            scripts += 1
            if not path.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                errors.append(f"shell script is not executable: {relative}")
            if not path.read_text(encoding="utf-8").startswith("#!/usr/bin/env bash\n"):
                errors.append(f"shell script has unexpected shebang: {relative}")

    go_mod = (ROOT / "go.mod").read_text(encoding="utf-8").splitlines()
    if not go_mod or go_mod[0] != "module github.com/pocket-grimoire-guild/otelcol-exporter-netflow":
        errors.append("go.mod module path is incorrect")
    if "go 1.26.0" not in go_mod:
        errors.append("go.mod must declare go 1.26.0")

    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    actions = re.findall(
        r"^\s*- uses:\s+([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([0-9A-Za-z_.-]+)",
        workflow,
        flags=re.MULTILINE,
    )
    for action, pin in CI_ACTION_PINS.items():
        if (action, pin) not in actions:
            errors.append(f"CI must pin {action}@{pin}")
    for action, revision in actions:
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            errors.append(f"CI action must use a full commit SHA: {action}@{revision}")
        if action in CI_ACTION_PINS and revision != CI_ACTION_PINS[action]:
            errors.append(f"unexpected CI revision for {action}: {revision}")

    if errors:
        print("configuration checks failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(f"configuration checks passed ({parsed} JSON/TOML files, {scripts} shell scripts)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
