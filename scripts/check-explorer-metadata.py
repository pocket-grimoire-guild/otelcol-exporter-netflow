#!/usr/bin/env python3
"""Check local Explorer presentation readiness, then reuse pinned mdatagen."""

import argparse
from pathlib import Path
import subprocess
import sys

import yaml


def check_shape(path):
    with path.open(encoding="utf-8") as source:
        metadata = yaml.safe_load(source)
    if not isinstance(metadata, dict):
        raise ValueError("metadata must be a mapping")
    for field in ("display_name", "description"):
        value = metadata.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} must be a nonempty top-level string")
    if metadata.get("type") != "netflow":
        raise ValueError("component type must remain netflow")
    status = metadata.get("status")
    if not isinstance(status, dict) or status.get("class") != "exporter":
        raise ValueError("component class must remain exporter")
    if status.get("stability") != {"alpha": ["logs"]}:
        raise ValueError("component stability must remain alpha for logs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--shape-only", type=Path, metavar="METADATA",
        help="validate a fixture only; does not claim generated-output readiness",
    )
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    try:
        check_shape(args.shape_only if args.shape_only is not None else repo / "metadata.yaml")
        if args.shape_only is None:
            subprocess.run(
                [str(repo / "scripts/check-generated.sh"), "--go", "1.26.8",
                 "--mdatagen", "go.opentelemetry.io/collector/cmd/mdatagen@v0.160.0"],
                cwd=repo, check=True,
            )
    except (OSError, ValueError, yaml.YAMLError, subprocess.CalledProcessError) as error:
        print(f"Explorer metadata check failed: {error}", file=sys.stderr)
        return 1
    print("Explorer metadata shape PASS" if args.shape_only is not None
          else "Explorer metadata shape and pinned generation PASS (local readiness only)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
