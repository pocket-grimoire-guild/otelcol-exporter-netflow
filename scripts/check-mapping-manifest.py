#!/usr/bin/env python3
"""Fail-closed checker for the receiver-to-protocol mapping coverage manifest.

The manifest deliberately uses JSON syntax even though its filename ends in
``.yaml``.  Keeping the checker on the Python standard library makes the
coverage gate usable before any Collector or YAML dependency is available.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


SCHEMA = "otel-netflow-mapping-coverage"
VERSION = 1
MAX_INPUT_BYTES = 512 * 1024
READ_CHUNK_BYTES = 64 * 1024
MAX_DIAGNOSTIC_BYTES = 256
PROTOCOLS = ("netflow_v5", "netflow_v9", "ipfix")
CLASSIFICATIONS = ("exact", "lossy", "synthesized", "unsupported", "inapplicable")
RECEIVER_PROFILE = "contrib-netflowreceiver-v0.160.0"
CONTRIB_COMMIT = "982f20b8a8e8a2569fab3e27cf8b008e8a5080c1"
GOFLOW2_COMMIT = "c9824f41bcad11d4490a668ed5270b03056d8217"
RECEIVER_PATH = "docs/compatibility/receiver-attributes.md"
MATRIX_PATH = "docs/compatibility/protocol-mapping.md"
RECEIVER_SHA256 = "587f155e51b9d7eee55d61b42f5f97308c926004b7073f28963de85b1cfcc9d4"
MATRIX_SHA256 = "8f72fb01b702afdeb493e7a4413d0b1d20408163c669000122c428ac8f679104"
EXTRA_TESTS = {
    "custom_ipfix_enterprise": "internal/mapping:TestCustom",
    "v9_private": "internal/mapping:TestCustom",
    "raw_body_rejection": "internal/normalize:TestMalformed",
    "unknown_unselected_traversal": "internal/normalize:TestPreflightIgnoresIrrelevantMetadata",
}


class ManifestError(Exception):
    pass


def error(message: str) -> None:
    raise ManifestError(message)


def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            error(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    error(f"non-JSON numeric constant: {value}")


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _open_regular(path: Path) -> int:
    """Open one regular file through descriptor-relative, no-follow traversal."""
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        error("safe descriptor traversal is unavailable")
    absolute = Path(os.path.abspath(os.fspath(path)))
    if len(absolute.parts) < 2:
        error("unsafe manifest path")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_fd: int | None = None
    descriptor: int | None = None
    try:
        directory_fd = os.open(absolute.anchor, directory_flags)
        for component in absolute.parts[1:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        descriptor = os.open(
            absolute.parts[-1],
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
    except OSError:
        error("manifest path is unavailable or contains a symlink")
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
    if descriptor is None:
        error("manifest path is unavailable")
    return descriptor


def bounded_read(path: Path) -> bytes:
    descriptor = _open_regular(path)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            error("manifest must be a regular file")
        if before.st_size > MAX_INPUT_BYTES:
            error("manifest exceeds bounded input size")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, remaining))
            if not chunk:
                error("manifest truncated during read")
            if len(chunk) > remaining:
                error("manifest grew during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            error("manifest grew beyond bounded input size")
        after = os.fstat(descriptor)
        if _identity(before) != _identity(after):
            error("manifest changed while being read")
        return b"".join(chunks)
    except OSError:
        error("manifest read failed")
    finally:
        os.close(descriptor)


def require_keys(value: Any, expected: set[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        error(f"{where} must be an object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        error(f"{where} keys differ; missing={missing} unknown={unknown}")
    return value


def string(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        error(f"{where} must be a non-empty string")
    return value


def integer(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        error(f"{where} must be an integer")
    return value


def exact_string(value: Any, expected: str, where: str) -> None:
    if value != expected:
        error(f"{where} mismatch")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_source(root: Path, relative: str, expected: str) -> bytes:
    source = root / relative
    data = bounded_read(source)
    if sha256_bytes(data) != expected:
        error("bound source drift")
    return data


def receiver_attributes(data: bytes) -> list[str]:
    text = data.decode("utf-8")
    names: list[str] = []
    for line in text.splitlines():
        match = re.match(r"^\|\s*`([^`]+)`\s*\|", line)
        if match:
            name = match.group(1)
            if name in names:
                error(f"duplicate receiver attribute: {name}")
            names.append(name)
    expected = [name for name in names if name not in ("Timestamp", "ObservedTimestamp")]
    if len(expected) != 41:
        error(f"receiver profile has {len(expected)} canonical attributes, want 41")
    return expected


def split_matrix_row(line: str) -> list[str]:
    # Matrix prose contains a bitwise ``|`` in one qualifier.  Markdown cell
    # separators are the pipes followed by the next cell's bold class.
    if not line.startswith("| `"):
        error("malformed matrix row")
    parts = re.split(r"\s+\|\s+(?=\*\*)", line.strip()[1:-1])
    if len(parts) != 4:
        error("matrix row does not have four cells")
    return parts


def matrix_rows(data: bytes, attributes: list[str]) -> list[dict[str, Any]]:
    text = data.decode("utf-8")
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line.startswith("| `"):
            continue
        parts = split_matrix_row(line)
        attribute = parts[0].strip().strip("`")
        if attribute not in attributes:
            error(f"matrix has unknown attribute: {attribute}")
        if len(rows) >= len(attributes):
            error("matrix has extra canonical rows")
        if rows and attributes[len(rows)] != attribute:
            error(f"matrix row order drift at {attribute}")
        cells: list[dict[str, Any]] = []
        for column, cell in enumerate(parts[1:], 1):
            normalized = " ".join(cell.split())
            match = re.match(
                r"\*\*((?:exact|lossy|synthesized|unsupported|inapplicable)"
                r"(?:/(?:exact|lossy|synthesized|unsupported|inapplicable))*)",
                normalized,
            )
            if not match:
                error(f"matrix cell has no accepted classification: {attribute}/{column}")
            classification = match.group(1).split("/")
            if len(set(classification)) != len(classification):
                error(f"matrix cell repeats a classification: {attribute}/{column}")
            cells.append(
                {
                    "classification": classification,
                    "outcome": normalized,
                    "outcome_sha256": sha256_bytes(normalized.encode("utf-8")),
                }
            )
        rows.append({"attribute": attribute, "cells": cells})
    if len(rows) != 41:
        error(f"matrix has {len(rows)} canonical rows, want 41")
    return rows


def test_reference_exists(root: Path, reference: str) -> None:
    match = re.fullmatch(r"([A-Za-z0-9_./-]+):((?:Test)[A-Za-z0-9_]*)", reference)
    if not match:
        error(f"invalid executable test reference: {reference}")
    package, test_name = match.groups()
    package_path = root / package
    if not package_path.is_dir():
        error(f"test reference package missing: {reference}")
    pattern = re.compile(r"\bfunc\s+" + re.escape(test_name) + r"\s*\(")
    found = False
    for source in package_path.rglob("*.go"):
        try:
            if pattern.search(source.read_text(encoding="utf-8")):
                found = True
                break
        except OSError as exc:
            error(f"cannot inspect test reference: {source}: {exc}")
    if not found:
        error(f"executable test reference does not exist: {reference}")


def canonical_fingerprint(cells: list[dict[str, Any]]) -> str:
    stream = [
        [
            cell["attribute"],
            cell["protocol"],
            cell["classification"],
            [cell["matrix_ref"]["row"], cell["matrix_ref"]["column"]],
            cell["outcome_sha256"],
            cell["test_id"],
        ]
        for cell in cells
    ]
    encoded = json.dumps(stream, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(encoded)


def check_manifest(path: Path) -> tuple[str, dict[str, int]]:
    root = Path(__file__).resolve().parent.parent
    raw = bounded_read(path)
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except ManifestError:
        raise
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        error(f"manifest is not strict JSON: {exc}")
    root_object = require_keys(document, {"schema", "version", "sources", "canonical", "extras"}, "root")
    exact_string(root_object["schema"], SCHEMA, "schema")
    if integer(root_object["version"], "version") != VERSION:
        error("unsupported manifest version")

    sources = require_keys(root_object["sources"], {"receiver_profile", "matrix"}, "sources")
    receiver = require_keys(
        sources["receiver_profile"],
        {"id", "contrib_commit", "goflow2_commit", "path", "sha256"},
        "sources.receiver_profile",
    )
    exact_string(receiver["id"], RECEIVER_PROFILE, "sources.receiver_profile.id")
    exact_string(receiver["contrib_commit"], CONTRIB_COMMIT, "sources.receiver_profile.contrib_commit")
    exact_string(receiver["goflow2_commit"], GOFLOW2_COMMIT, "sources.receiver_profile.goflow2_commit")
    exact_string(receiver["path"], RECEIVER_PATH, "sources.receiver_profile.path")
    exact_string(receiver["sha256"], RECEIVER_SHA256, "sources.receiver_profile.sha256")
    matrix = require_keys(sources["matrix"], {"id", "path", "sha256"}, "sources.matrix")
    exact_string(matrix["id"], "receiver-to-protocol-conversion-matrix-v1", "sources.matrix.id")
    exact_string(matrix["path"], MATRIX_PATH, "sources.matrix.path")
    exact_string(matrix["sha256"], MATRIX_SHA256, "sources.matrix.sha256")
    receiver_data = read_source(root, RECEIVER_PATH, RECEIVER_SHA256)
    matrix_data = read_source(root, MATRIX_PATH, MATRIX_SHA256)
    attributes = receiver_attributes(receiver_data)
    rows = matrix_rows(matrix_data, attributes)

    canonical = require_keys(root_object["canonical"], {"attributes", "protocols", "cells", "fingerprint"}, "canonical")
    if canonical["attributes"] != attributes:
        error("canonical attribute order does not match receiver profile")
    if canonical["protocols"] != list(PROTOCOLS):
        error("canonical protocol order does not match accepted vocabulary")
    cells = canonical["cells"]
    if not isinstance(cells, list) or len(cells) != 123:
        error("canonical cells must contain exactly 123 entries")
    expected: dict[tuple[str, str], dict[str, Any]] = {}
    for row_number, row in enumerate(rows, 1):
        for column_number, outcome in enumerate(row["cells"], 1):
            expected[(row["attribute"], PROTOCOLS[column_number - 1])] = {
                "attribute": row["attribute"],
                "protocol": PROTOCOLS[column_number - 1],
                "classification": outcome["classification"],
                "matrix_ref": {"row": row_number, "column": column_number},
                "outcome": outcome["outcome"],
                "outcome_sha256": outcome["outcome_sha256"],
            }
    seen: set[tuple[str, str]] = set()
    checked_cells: list[dict[str, Any]] = []
    for index, cell in enumerate(cells, 1):
        cell = require_keys(
            cell,
            {"attribute", "protocol", "classification", "matrix_ref", "outcome", "outcome_sha256", "test_id"},
            f"canonical.cells[{index}]",
        )
        attribute = string(cell["attribute"], f"canonical.cells[{index}].attribute")
        protocol = string(cell["protocol"], f"canonical.cells[{index}].protocol")
        key = (attribute, protocol)
        if key in seen:
            error(f"duplicate canonical cell: {attribute}/{protocol}")
        seen.add(key)
        want = expected.get(key)
        if want is None:
            error(f"stale or unknown canonical cell: {attribute}/{protocol}")
        classification = cell["classification"]
        if not isinstance(classification, list) or not classification or any(
            not isinstance(item, str) or item not in CLASSIFICATIONS for item in classification
        ) or len(set(classification)) != len(classification):
            error(f"invalid classification set: {attribute}/{protocol}")
        if classification != want["classification"]:
            error(f"classification drift: {attribute}/{protocol}")
        matrix_ref = require_keys(cell["matrix_ref"], {"row", "column"}, f"canonical.cells[{index}].matrix_ref")
        row = integer(matrix_ref["row"], "matrix_ref.row")
        column = integer(matrix_ref["column"], "matrix_ref.column")
        if row != want["matrix_ref"]["row"] or column != want["matrix_ref"]["column"]:
            error(f"matrix reference drift: {attribute}/{protocol}")
        if index != (row - 1) * len(PROTOCOLS) + column:
            error(f"canonical cell order drift: {attribute}/{protocol}")
        if string(cell["outcome"], "outcome") != want["outcome"]:
            error(f"qualified matrix outcome drift: {attribute}/{protocol}")
        digest = string(cell["outcome_sha256"], "outcome_sha256")
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or digest != want["outcome_sha256"]:
            error(f"qualified outcome digest drift: {attribute}/{protocol}")
        test_id = string(cell["test_id"], "test_id")
        expected_test_id = f"integration/mapping:TestManifestCoverage/{protocol}/{attribute}"
        if test_id != expected_test_id:
            error(f"unstable or untested test ID: {attribute}/{protocol}")
        checked_cells.append(cell)
    if seen != set(expected):
        error("canonical cells are missing one or more receiver/protocol pairs")
    fingerprint = string(canonical["fingerprint"], "canonical.fingerprint")
    if not re.fullmatch(r"[0-9a-f]{64}", fingerprint) or fingerprint != canonical_fingerprint(checked_cells):
        error("canonical aggregate fingerprint mismatch")

    extras = require_keys(root_object["extras"], set(EXTRA_TESTS), "extras")
    for name, expected_test in EXTRA_TESTS.items():
        extra = require_keys(extras[name], {"test_id"}, f"extras.{name}")
        test_id = string(extra["test_id"], f"extras.{name}.test_id")
        if test_id != expected_test:
            error(f"extra test reference drift: {name}")
        if test_id.startswith("integration/mapping:TestManifestCoverage/"):
            error(f"canonical test used as extra: {name}")
        test_reference_exists(root, test_id)

    counts = {classification: 0 for classification in CLASSIFICATIONS}
    for cell in checked_cells:
        for classification in cell["classification"]:
            counts[classification] += 1
    return fingerprint, counts


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: check-mapping-manifest.py MANIFEST.yaml", file=sys.stderr)
        return 2
    try:
        fingerprint, counts = check_manifest(Path(argv[1]))
    except Exception:
        # Internal validation details intentionally never cross the process
        # boundary: malformed manifests may contain attacker-controlled keys,
        # values, paths, or OS exception text. Keep this stable and bounded.
        diagnostic = "mapping manifest: FAIL: invalid manifest"
        print(diagnostic[:MAX_DIAGNOSTIC_BYTES], file=sys.stderr)
        return 1
    print(
        "mapping manifest: PASS "
        f"canonical=123 attributes=41 protocols=3 extras=4 "
        f"classifications=exact:{counts['exact']},lossy:{counts['lossy']},"
        f"synthesized:{counts['synthesized']},unsupported:{counts['unsupported']},"
        f"inapplicable:{counts['inapplicable']} fingerprint={fingerprint}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
