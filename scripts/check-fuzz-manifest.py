#!/usr/bin/env python3
"""Check the finite, reviewed corpus for the implemented fuzz targets."""

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    "FuzzPreflight": "internal/normalize/preflight_fuzz_test.go",
    "FuzzNormalize": "internal/normalize/normalize_fuzz_test.go",
    "FuzzCompileMapping": "internal/mapping/compiler_fuzz_test.go",
    "FuzzTemplateCatalog": "internal/destination/template_fuzz_test.go",
    "FuzzPacketPacking": "internal/destination/packing_fuzz_test.go",
    "FuzzNetFlow5Writer": "internal/wire/netflow5/writer_fuzz_test.go",
    "FuzzNetFlow9Writer": "internal/wire/netflow9/writer_fuzz_test.go",
    "FuzzIPFIXWriter": "internal/wire/ipfix/writer_fuzz_test.go",
}


def check():
    manifest = json.loads((ROOT / "integration/testdata/fuzz/manifest.json").read_text())
    assert manifest["version"] == 1, "unsupported fuzz manifest version"
    targets = manifest["targets"]
    names = [target["name"] for target in targets]
    pending = manifest["pending_targets"]
    assert len(names) == len(set(names)), "duplicate implemented target"
    assert len(pending) == len(set(pending)), "duplicate pending target"
    assert not set(names) & set(pending), "target is both implemented and pending"
    assert set(names) | set(pending) == set(TARGETS), "manifest must account for all eight planned targets"
    discovered = {}
    for source in (ROOT / "internal").rglob("*_test.go"):
        for name in re.findall(r"^func (Fuzz\w+)\(", source.read_text(), re.MULTILINE):
            assert name not in discovered, "duplicate fuzz target name"
            discovered[name] = source.relative_to(ROOT).as_posix()
    assert discovered == {name: TARGETS[name] for name in names}, "target inventory differs from manifest"

    count = 0
    for target in targets:
        name = target["name"]
        assert target["source"] == TARGETS[name], "unexpected target source"
        assert target["package"] == str(Path(TARGETS[name]).parent), "unexpected target package"
        corpus = ROOT / target["package"] / "testdata/fuzz" / name
        files = [seed["file"] for seed in target["seeds"]]
        assert files and len(files) == len(set(files)), "missing or duplicate seeds"
        assert set(files) == {path.name for path in corpus.iterdir()}, "unreviewed or missing corpus entry"
        for seed in target["seeds"]:
            filename = seed["file"]
            assert re.fullmatch(r"[a-z0-9-]+", filename), "invalid seed filename"
            path = corpus / filename
            assert path.is_file() and not path.is_symlink(), "seed must be a regular file"
            assert path.stat().st_size <= 32768, "seed exceeds serialized input bound"
            data = path.read_bytes()
            assert data.startswith(b"go test fuzz v1\n") and data.endswith(b"\n"), "invalid corpus framing"
            assert hashlib.sha256(data).hexdigest() == seed["sha256"], "seed changed without manifest review"
            assert seed["covers"] and all(isinstance(case, str) and case for case in seed["covers"]), "seed lacks case labels"
            count += 1
    print(f"fuzz manifest passed ({len(targets)} targets, {count} seeds; {len(pending)} targets pending)")


if __name__ == "__main__":
    try:
        check()
    except (AssertionError, OSError, ValueError, KeyError, TypeError) as error:
        raise SystemExit(f"fuzz manifest failed: {error}") from error
