#!/usr/bin/env python3
"""Validate the aggregate immutable golden-slot manifest.

V1b deliberately accepts structurally complete pending slots.  Supplying
--protocol is a fail-closed gate for later writer work: every slot for that
protocol must be complete and carry nonzero payload hashes.
"""
import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path


class ManifestError(ValueError):
    pass


MAX_MANIFEST_BYTES = 1 << 20
MANIFEST_READ_CHUNK = 64 << 10


EXPECTED_SLOTS = {
    "v5-canonical-ipv4-v1": ("v5", ["canonical-v5-ipv4-v1"], ["v5/canonical-ipv4-v1.bin"]),
    "v9-canonical-ipv4-v1": ("v9", ["canonical-ipv4-v1"], ["v9/canonical-ipv4-v1.bin"]),
    "v9-canonical-ipv6-v1": ("v9", ["canonical-ipv6-v1"], ["v9/canonical-ipv6-v1.bin"]),
    "v9-sampling-ie34-two-distinct-rates-v1": ("v9", ["sampling-ie34-two-distinct-rates-v9-v1"], ["v9/sampling-ie34-two-distinct-rates-v1.bin"]),
    "ipfix-canonical-ipv4-v1": ("ipfix", ["canonical-ipfix-ipv4-v1"], ["ipfix/canonical-ipv4-v1.bin"]),
    "ipfix-canonical-ipv6-v1": ("ipfix", ["canonical-ipfix-ipv6-v1"], ["ipfix/canonical-ipv6-v1.bin"]),
    "ipfix-sampling-ie34-two-distinct-rates-v1": ("ipfix", ["sampling-ie34-two-distinct-rates-ipfix-v1"], ["ipfix/sampling-ie34-two-distinct-rates-v1.bin"]),
}


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load(path):
    try:
        if not hasattr(os, "O_NOFOLLOW"):
            raise ManifestError("manifest: O_NOFOLLOW is unavailable")
        candidate = Path(path)
        for component in (candidate, *candidate.parents):
            try:
                if stat.S_ISLNK(os.lstat(component).st_mode):
                    raise ManifestError("manifest: symlink path component is forbidden")
            except FileNotFoundError:
                continue
        absolute = Path(os.path.abspath(os.fspath(candidate)))
        if len(absolute.parts) < 2 or not hasattr(os, "O_DIRECTORY"):
            raise ManifestError("manifest: safe path traversal is unavailable")
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        dir_fd = os.open(absolute.anchor, directory_flags)
        try:
            for component in absolute.parts[1:-1]:
                next_fd = os.open(component, directory_flags, dir_fd=dir_fd)
                os.close(dir_fd)
                dir_fd = next_fd
            fd = os.open(absolute.parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=dir_fd)
        finally:
            os.close(dir_fd)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise ManifestError("manifest: input must be a regular file")
            if before.st_size > MAX_MANIFEST_BYTES:
                raise ManifestError("manifest: input exceeds 1 MiB")
            chunks = []
            remaining = before.st_size
            while remaining:
                chunk = os.read(fd, min(MANIFEST_READ_CHUNK, remaining))
                if not chunk:
                    raise ManifestError("manifest: input truncated during read")
                if len(chunk) > remaining:
                    raise ManifestError("manifest: input grew during read")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(fd, 1):
                raise ManifestError("manifest: input grew beyond bounded size")
            after = os.fstat(fd)
            before_identity = (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            after_identity = (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            if before_identity != after_identity:
                raise ManifestError("manifest: input changed during read")
            raw = b"".join(chunks)
        finally:
            os.close(fd)
        return json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except ManifestError:
        raise
    except Exception as exc:
        raise ManifestError(f"invalid JSON: {exc}") from exc


def expect_obj(value, allowed, where):
    if not isinstance(value, dict):
        raise ManifestError(f"{where}: expected object")
    unknown = set(value) - set(allowed)
    if unknown:
        raise ManifestError(f"{where}: unknown key(s): {', '.join(sorted(unknown))}")
    return value


def sha256_canonical(value):
    data = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def verify_artifact(manifest_dir, payload, where):
    """Open, bound, and hash one reserved artifact through directory FDs."""
    rel = Path(payload["path"])
    if rel.is_absolute() or not rel.parts or ".." in rel.parts:
        raise ManifestError(f"{where}.path: unsafe relative path")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise ManifestError(f"{where}.path: safe descriptor traversal is unavailable")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    artifact_flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    directory_fd = None
    artifact_fd = None
    try:
        # Walk the absolute manifest directory and the reserved relative path
        # one component at a time.  Every component is opened relative to the
        # already trusted descriptor, so symlink ancestors cannot redirect the
        # final open between validation and hashing.
        absolute_dir = Path(os.path.abspath(os.fspath(manifest_dir)))
        directory_fd = os.open(absolute_dir.anchor, directory_flags)
        for component in absolute_dir.parts[1:]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        for component in rel.parts[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        artifact_fd = os.open(rel.parts[-1], artifact_flags, dir_fd=directory_fd)
    except OSError as exc:
        raise ManifestError(f"{where}.path: artifact is unavailable") from exc
    finally:
        if directory_fd is not None:
            os.close(directory_fd)

    try:
        declared = payload["length"]
        before = os.fstat(artifact_fd)
        if not stat.S_ISREG(before.st_mode):
            raise ManifestError(f"{where}.path: artifact must be a regular file")
        if before.st_size != declared:
            raise ManifestError(f"{where}.length: declared {declared} but artifact size differs")
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        digest = hashlib.sha256()
        remaining = declared
        while remaining:
            chunk = os.read(artifact_fd, min(MANIFEST_READ_CHUNK, remaining))
            if not chunk:
                raise ManifestError(f"{where}.length: artifact truncated during read")
            if len(chunk) > remaining:
                raise ManifestError(f"{where}.length: artifact grew during read")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(artifact_fd, 1):
            raise ManifestError(f"{where}.length: artifact grew during read")
        after = os.fstat(artifact_fd)
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity:
            raise ManifestError(f"{where}: artifact changed during read")
        if digest.hexdigest() != payload["sha256"]:
            raise ManifestError(f"{where}.sha256: artifact digest mismatch")
    except OSError as exc:
        raise ManifestError(f"{where}.path: artifact read failed") from exc
    finally:
        os.close(artifact_fd)


def verify(path, canonical_path=None, protocol=None):
    manifest = load(path)
    expect_obj(manifest, {"schema", "version", "canonical_manifest_sha256", "slot_policy", "slots"}, "root")
    if manifest.get("schema") != "otel-netflow-golden-manifest" or manifest.get("version") != 1:
        raise ManifestError("root: unsupported schema/version")
    canonical_sha = manifest.get("canonical_manifest_sha256")
    if not isinstance(canonical_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", canonical_sha) or int(canonical_sha, 16) == 0:
        raise ManifestError("root.canonical_manifest_sha256: nonzero lowercase SHA-256 required")
    if not isinstance(manifest.get("slot_policy"), str) or not manifest["slot_policy"]:
        raise ManifestError("root.slot_policy: descriptive policy is required")
    if canonical_path is None:
        canonical_path = Path(os.path.abspath(os.fspath(path))).parent.parent / "canonical" / "fixtures.json"
    manifest_dir = Path(os.path.abspath(os.fspath(path))).parent
    canonical = load(canonical_path)
    if sha256_canonical(canonical) != canonical_sha:
        raise ManifestError("canonical_manifest_sha256 does not match canonical fixtures")
    fixture_ids = set()
    fixture_protocols = {}
    for item in canonical.get("fixtures", []):
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            fixture_ids.add(item["id"])
            fixture_protocols[item["id"]] = item.get("protocol")
    for item in canonical.get("generated_cases", []):
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            fixture_ids.add(item["id"])
            fixture_protocols[item["id"]] = item.get("protocol")
    slots = manifest.get("slots")
    if not isinstance(slots, list) or not slots:
        raise ManifestError("slots: non-empty array required")
    if len(slots) != 7 or {slot.get("id") for slot in slots if isinstance(slot, dict)} != set(EXPECTED_SLOTS):
        raise ManifestError("slots: exact seven-slot V1b reservation is required")
    seen = set()
    by_protocol = {}
    for index, slot in enumerate(slots):
        where = f"slots[{index}]"
        slot = expect_obj(slot, {"id", "protocol", "fixture_ids", "canonical_manifest_sha256", "status", "expected_payload_paths", "payloads"}, where)
        sid = slot.get("id")
        if not isinstance(sid, str) or not re.fullmatch(r"[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?-v[0-9]+$", sid) or sid in seen:
            raise ManifestError(f"{where}.id: duplicate or unstable slot ID")
        seen.add(sid)
        proto = slot.get("protocol")
        if proto not in {"v5", "v9", "ipfix"}:
            raise ManifestError(f"{where}.protocol: unsupported protocol")
        by_protocol.setdefault(proto, []).append(slot)
        refs = slot.get("fixture_ids")
        expected_proto, expected_refs, expected_paths = EXPECTED_SLOTS[sid]
        if proto != expected_proto or refs != expected_refs:
            raise ManifestError(f"{where}: slot protocol/fixture mapping is not the pinned singleton")
        if not isinstance(refs, list) or not refs or len(set(refs)) != len(refs) or any(not isinstance(x, str) or x not in fixture_ids for x in refs):
            raise ManifestError(f"{where}.fixture_ids: unknown, duplicate, or empty fixture reference")
        if any(fixture_protocols.get(ref) != proto for ref in refs):
            raise ManifestError(f"{where}.fixture_ids: fixture protocol does not match slot protocol")
        if slot.get("canonical_manifest_sha256") != canonical_sha:
            raise ManifestError(f"{where}.canonical_manifest_sha256: does not bind canonical source")
        if slot.get("expected_payload_paths") != expected_paths:
            raise ManifestError(f"{where}.expected_payload_paths: reservation drifted")
        status = slot.get("status")
        if status not in {"pending", "complete"}:
            raise ManifestError(f"{where}.status: must be pending or complete")
        payloads = slot.get("payloads")
        if not isinstance(payloads, list):
            raise ManifestError(f"{where}.payloads: expected array")
        if status == "pending":
            if payloads:
                raise ManifestError(f"{where}: pending slot may not contain payload hashes")
            continue
        if not payloads:
            raise ManifestError(f"{where}: complete slot requires payloads")
        if [payload.get("path") for payload in payloads if isinstance(payload, dict)] != expected_paths:
            raise ManifestError(f"{where}.payloads: paths do not match exact reservation")
        payload_seen = set()
        for j, payload in enumerate(payloads):
            pwhere = f"{where}.payloads[{j}]"
            payload = expect_obj(payload, {"path", "length", "sha256"}, pwhere)
            pth = payload.get("path")
            if not isinstance(pth, str) or not pth or pth in payload_seen or Path(pth).is_absolute() or ".." in Path(pth).parts:
                raise ManifestError(f"{pwhere}.path: duplicate or unsafe relative path")
            payload_seen.add(pth)
            length = payload.get("length")
            if isinstance(length, bool) or not isinstance(length, int) or length <= 0 or length > 65535:
                raise ManifestError(f"{pwhere}.length: expected 1..65535")
            digest = payload.get("sha256")
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or int(digest, 16) == 0:
                raise ManifestError(f"{pwhere}.sha256: nonzero lowercase SHA-256 required")
            verify_artifact(manifest_dir, payload, pwhere)
    if protocol is not None:
        if protocol not in {"v5", "v9", "ipfix"}:
            raise ManifestError("--protocol must be v5, v9, or ipfix")
        selected = by_protocol.get(protocol, [])
        if not selected:
            raise ManifestError(f"--protocol {protocol}: no reserved slots")
        pending = [slot["id"] for slot in selected if slot["status"] != "complete"]
        if pending:
            raise ManifestError(f"--protocol {protocol}: incomplete/pending slots: {', '.join(pending)}")
    return canonical_sha, len(slots), by_protocol


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest")
    parser.add_argument("--canonical-manifest", help="canonical fixtures path (defaults to sibling canonical/fixtures.json)")
    parser.add_argument("--protocol", choices=("v5", "v9", "ipfix"), help="require complete nonzero slots for one protocol")
    args = parser.parse_args(argv)
    try:
        digest, count, by_protocol = verify(args.manifest, args.canonical_manifest, args.protocol)
    except (ManifestError, OSError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    suffix = f" protocol={args.protocol}" if args.protocol else ""
    print(f"PASS: golden manifest valid; slots={count}; canonical_manifest_sha256={digest}{suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
