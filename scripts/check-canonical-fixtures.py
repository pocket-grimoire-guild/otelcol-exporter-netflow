#!/usr/bin/env python3
"""Validate the project-owned canonical receiver fixture authority.

This checker deliberately has no imports from the Go module.  JSON is parsed
with duplicate-key detection and every object is checked against an explicit
allow-list so a typo cannot silently become fixture data.
"""
import argparse
import hashlib
import ipaddress
import json
import os
import re
import stat
import sys
from pathlib import Path


class FixtureError(ValueError):
    pass


MAX_MANIFEST_BYTES = 1 << 20
MANIFEST_READ_CHUNK = 64 << 10


def reject_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise FixtureError(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def load(path):
    try:
        if not hasattr(os, "O_NOFOLLOW"):
            raise FixtureError("manifest: O_NOFOLLOW is unavailable")
        candidate = Path(path)
        for component in (candidate, *candidate.parents):
            try:
                if stat.S_ISLNK(os.lstat(component).st_mode):
                    raise FixtureError("manifest: symlink path component is forbidden")
            except FileNotFoundError:
                continue
        absolute = Path(os.path.abspath(os.fspath(candidate)))
        if len(absolute.parts) < 2 or not hasattr(os, "O_DIRECTORY"):
            raise FixtureError("manifest: safe path traversal is unavailable")
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
                raise FixtureError("manifest: input must be a regular file")
            if before.st_size > MAX_MANIFEST_BYTES:
                raise FixtureError("manifest: input exceeds 1 MiB")
            chunks = []
            remaining = before.st_size
            while remaining:
                chunk = os.read(fd, min(MANIFEST_READ_CHUNK, remaining))
                if not chunk:
                    raise FixtureError("manifest: input truncated during read")
                if len(chunk) > remaining:
                    raise FixtureError("manifest: input grew during read")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(fd, 1):
                raise FixtureError("manifest: input grew beyond bounded size")
            after = os.fstat(fd)
            before_identity = (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            after_identity = (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            if before_identity != after_identity:
                raise FixtureError("manifest: input changed during read")
            raw = b"".join(chunks)
        finally:
            os.close(fd)
        return json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except FixtureError:
        raise
    except Exception as exc:
        raise FixtureError(f"invalid JSON: {exc}") from exc


def obj(value, allowed, where):
    if not isinstance(value, dict):
        raise FixtureError(f"{where}: expected object")
    unknown = set(value) - set(allowed)
    if unknown:
        raise FixtureError(f"{where}: unknown key(s): {', '.join(sorted(unknown))}")
    return value


def required(value, key, where):
    if key not in value:
        raise FixtureError(f"{where}: missing key {key}")
    return value[key]


def string(value, where):
    if not isinstance(value, str):
        raise FixtureError(f"{where}: expected string")
    return value


def integer(value, where):
    if isinstance(value, bool) or not isinstance(value, int):
        raise FixtureError(f"{where}: expected integer")
    if value < 0 or value > (1 << 63) - 1:
        raise FixtureError(f"{where}: integer outside OTel int64 range")
    return value


ATTR_NAMES = [
    "source.address", "source.port", "destination.address", "destination.port",
    "network.transport", "network.type", "flow.io.bytes", "flow.io.packets",
    "flow.type", "flow.sequence_num", "flow.time_received", "flow.start", "flow.end",
    "flow.sampling_rate", "flow.sampler_address", "flow.tcp_flags", "flow.in_if",
    "flow.out_if", "flow.ip_tos", "flow.ip_ttl", "flow.ip_flags", "flow.fragment_id",
    "flow.fragment_offset", "flow.ipv6_flow_label", "flow.icmp_type", "flow.icmp_code",
    "flow.src_mac", "flow.dst_mac", "flow.src_vlan", "flow.dst_vlan", "flow.vlan_id",
    "flow.next_hop", "flow.next_hop_as", "flow.src_as", "flow.dst_as", "flow.bgp_next_hop",
    "flow.src_net", "flow.dst_net", "flow.forwarding_status", "flow.observation_domain_id",
    "flow.observation_point_id",
]
STRING_ATTRS = {
    "source.address", "destination.address", "network.transport", "network.type",
    "flow.type", "flow.sampler_address", "flow.src_mac", "flow.dst_mac",
    "flow.next_hop", "flow.bgp_next_hop",
}
OPTIONAL_ATTRS = {"flow.next_hop", "flow.bgp_next_hop"}
FLOW_TYPES = {"unknown", "sflow_5", "netflow_v5", "netflow_v9", "ipfix"}
TRANSPORTS = {"hopopt", "icmp", "tcp", "udp", "ipv6-icmp"}
NETWORK_TYPES = {"ipv4", "ipv6"}
PROTOCOLS = {"v5", "v9", "ipfix"}
SHAPES = {"ipv4-fixed-v1", "ipv4-core-v1", "ipv6-core-v1"}
REQUIRED_FIXTURE_IDS = {
    "canonical-ipv4-v1", "canonical-zero-v1", "canonical-ipv6-v1",
    "canonical-next-hop-v1", "canonical-bgp-next-hop-v1", "canonical-v5-ipv4-v1",
    "canonical-ipfix-ipv4-v1", "canonical-ipfix-ipv6-v1",
    "sampling-ie34-two-distinct-rates-v9-v1", "sampling-ie34-two-distinct-rates-ipfix-v1",
}
ID_RE = re.compile(r"^[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?-v[0-9]+$")
MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")


def materialize(fixtures, fixture_id, stack=()):
    if fixture_id not in fixtures:
        raise FixtureError(f"unknown fixture reference: {fixture_id}")
    if fixture_id in stack:
        raise FixtureError(f"fixture inheritance cycle: {' -> '.join(stack + (fixture_id,))}")
    item = fixtures[fixture_id]
    attrs = dict(item.get("attributes", {}))
    metadata = dict(item.get("metadata", {}))
    if item["kind"] != "base":
        base = materialize(fixtures, item["base_fixture_id"], stack + (fixture_id,))
        attrs = dict(base["attributes"])
        metadata = dict(base["metadata"])
        overrides = item.get("overrides", {})
        attrs.update(overrides.get("attributes", {}))
        for name in overrides.get("remove_attributes", []):
            attrs.pop(name, None)
        metadata.update(item["metadata"])
    return {"attributes": attrs, "metadata": metadata, "protocol": item["protocol"], "shape": item["shape"]}


def validate_metadata(meta, where):
    obj(meta, {"configured_ids", "uptime_origin", "reserved_header_instant", "template_ids", "sequence_start", "options", "sampling_ie"}, where)
    ids = obj(required(meta, "configured_ids", where), {"observation_domain_id", "source_id", "engine_type", "engine_id"}, f"{where}.configured_ids")
    for key, value in ids.items():
        integer(value, f"{where}.configured_ids.{key}")
    for key in ("uptime_origin", "reserved_header_instant"):
        value = string(required(meta, key, where), f"{where}.{key}")
        if not value.endswith("Z"):
            raise FixtureError(f"{where}.{key}: must be UTC RFC3339 with Z suffix")
    templates = obj(required(meta, "template_ids", where), {"ipv4", "ipv6"}, f"{where}.template_ids")
    for key, value in templates.items():
        integer(value, f"{where}.template_ids.{key}")
        if value < 256 or value > 65535:
            raise FixtureError(f"{where}.template_ids.{key}: outside template ID range")
    sequence = integer(required(meta, "sequence_start", where), f"{where}.sequence_start")
    if sequence > (1 << 32) - 1:
        raise FixtureError(f"{where}.sequence_start: outside uint32 range")
    if required(meta, "options", where) != "none":
        raise FixtureError(f"{where}.options: only none is permitted in V1b")
    if "sampling_ie" in meta:
        ie = obj(meta["sampling_ie"], {"identity", "width", "ordinary"}, f"{where}.sampling_ie")
        if ie != {"identity": 34, "width": 4, "ordinary": True}:
            raise FixtureError(f"{where}.sampling_ie: must be ordinary four-byte IE/type 34")


def validate_attrs(attrs, schema, where, partial=False):
    if not isinstance(attrs, dict):
        raise FixtureError(f"{where}: expected object")
    allowed = set(ATTR_NAMES)
    unknown = set(attrs) - allowed
    if unknown:
        raise FixtureError(f"{where}: unknown attribute(s): {', '.join(sorted(unknown))}")
    for name in ATTR_NAMES:
        required_flag = schema[name]["required"]
        if required_flag and not partial and name not in attrs:
            raise FixtureError(f"{where}: missing required attribute {name}")
    for name, value in attrs.items():
        typ = schema[name]["type"]
        if typ == "string":
            string(value, f"{where}.{name}")
        else:
            integer(value, f"{where}.{name}")
        if name in ("source.address", "destination.address", "flow.sampler_address", "flow.next_hop", "flow.bgp_next_hop"):
            try:
                parsed = ipaddress.ip_address(value)
            except ValueError as exc:
                raise FixtureError(f"{where}.{name}: non-canonical IP address") from exc
            if str(parsed) != value:
                raise FixtureError(f"{where}.{name}: non-canonical IP spelling")
        if name in ("flow.src_mac", "flow.dst_mac") and not MAC_RE.fullmatch(value):
            raise FixtureError(f"{where}.{name}: expected lower-case six-octet MAC")
        if name in ("network.transport",) and value not in TRANSPORTS:
            raise FixtureError(f"{where}.{name}: token is not in pinned vocabulary subset")
        if name == "network.type" and value not in NETWORK_TYPES:
            raise FixtureError(f"{where}.{name}: token is not an IPv4/IPv6 family")
        if name == "flow.type" and value not in FLOW_TYPES:
            raise FixtureError(f"{where}.{name}: token is not in pinned flow-type vocabulary")
    # Width/range gates mirror receiver-attributes.md. Keeping every integer
    # field in one table prevents a newly reviewed key from losing its gate.
    ranges = {
        "source.port": 65535, "destination.port": 65535,
        "flow.sequence_num": (1 << 32) - 1, "flow.tcp_flags": 65535,
        "flow.in_if": (1 << 32) - 1, "flow.out_if": (1 << 32) - 1,
        "flow.ip_tos": 255, "flow.ip_ttl": 255, "flow.ip_flags": (1 << 32) - 1,
        "flow.fragment_id": (1 << 32) - 1, "flow.fragment_offset": (1 << 32) - 1,
        "flow.ipv6_flow_label": 0xFFFFF, "flow.icmp_type": 255, "flow.icmp_code": 255,
        "flow.src_vlan": 4095, "flow.dst_vlan": 4095, "flow.vlan_id": 4095,
        "flow.next_hop_as": (1 << 32) - 1, "flow.src_as": (1 << 32) - 1,
        "flow.dst_as": (1 << 32) - 1, "flow.src_net": 128, "flow.dst_net": 128,
        "flow.forwarding_status": (1 << 32) - 1,
        "flow.observation_domain_id": (1 << 32) - 1,
        "flow.observation_point_id": (1 << 32) - 1,
    }
    unbounded_int64 = {"flow.io.bytes", "flow.io.packets", "flow.time_received", "flow.start", "flow.end", "flow.sampling_rate"}
    int_fields = {name for name, descriptor in schema.items() if descriptor["type"] == "int"}
    if set(ranges) | unbounded_int64 != int_fields:
        raise FixtureError("integer range table does not cover every int attribute")
    for name, maximum in ranges.items():
        if name in attrs and attrs[name] > maximum:
            raise FixtureError(f"{where}.{name}: outside accepted range 0..{maximum}")
    family = attrs.get("network.type")
    if family:
        for key in ("source.address", "destination.address"):
            if key in attrs and ipaddress.ip_address(attrs[key]).version != int(family[-1]):
                raise FixtureError(f"{where}.{key}: address family does not match network.type")
        if family == "ipv4" and any(attrs.get(k, "").find(":") >= 0 for k in ("flow.next_hop", "flow.bgp_next_hop")):
            raise FixtureError(f"{where}: IPv4 fixture has an IPv6 next-hop")
        if family == "ipv4":
            for key in ("flow.src_net", "flow.dst_net"):
                if key in attrs and attrs[key] > 32:
                    raise FixtureError(f"{where}.{key}: IPv4 prefix exceeds 32")



###############################################################################
# Repair-2 authority checks.  The definitions below supersede the initial
# draft validator while retaining its strict duplicate-key/range primitives.
from datetime import datetime, timezone

R2_HIERARCHY = {
    "logs": 1, "resource_logs": 1, "scope_logs": 1,
    "resource_attributes": {}, "scope_name": "otelcol/netflowreceiver",
    "scope_attributes": {"receiver": "netflow"}, "parsed_body_empty": True,
    "fixed_traversal_nodes": 11, "record_base_nodes": 3, "node_bytes": 64,
}
R2_ROLES = {
    "canonical-ipv4-v1": ("base", "v9", "ipv4-core-v1", None),
    "canonical-zero-v1": ("variant", "v9", "ipv4-core-v1", "canonical-ipv4-v1"),
    "canonical-ipv6-v1": ("variant", "v9", "ipv6-core-v1", "canonical-ipv4-v1"),
    "canonical-next-hop-v1": ("variant", "v9", "ipv4-core-v1", "canonical-ipv4-v1"),
    "canonical-bgp-next-hop-v1": ("variant", "ipfix", "ipv4-core-v1", "canonical-ipv4-v1"),
    "canonical-v5-ipv4-v1": ("variant", "v5", "ipv4-fixed-v1", "canonical-ipv4-v1"),
    "canonical-ipfix-ipv4-v1": ("variant", "ipfix", "ipv4-core-v1", "canonical-ipv4-v1"),
    "canonical-ipfix-ipv6-v1": ("variant", "ipfix", "ipv6-core-v1", "canonical-ipv6-v1"),
    "sampling-ie34-two-distinct-rates-v9-v1": ("two-rate", "v9", "ipv4-core-v1", "canonical-ipv4-v1"),
    "sampling-ie34-two-distinct-rates-ipfix-v1": ("two-rate", "ipfix", "ipv4-core-v1", "canonical-ipfix-ipv4-v1"),
}
R2_GENERATED_ROLES = {
    "hard-admission-unselected-v1": {
        "base_fixture_id": "canonical-ipv4-v1",
        "protocol": "ipfix",
        "shape": "ipv4-core-v1",
        "metadata": {
            "configured_ids": {"observation_domain_id": 49, "source_id": 49, "engine_type": 1, "engine_id": 9},
            "uptime_origin": "2026-09-01T00:00:00Z",
            "reserved_header_instant": "2026-09-01T00:00:03Z",
            "template_ids": {"ipv4": 256, "ipv6": 257},
            "sequence_start": 0,
            "options": "none",
        },
    },
    "hard-copy-selected-v1": {
        "base_fixture_id": "canonical-ipv4-v1",
        "protocol": "ipfix",
        "shape": "ipv4-core-v1",
        "metadata": {
            "configured_ids": {"observation_domain_id": 50, "source_id": 50, "engine_type": 1, "engine_id": 10},
            "uptime_origin": "2026-09-01T00:00:00Z",
            "reserved_header_instant": "2026-09-01T00:00:03Z",
            "template_ids": {"ipv4": 256, "ipv6": 257},
            "sequence_start": 0,
            "options": "none",
        },
    },
}


def r2_utc(value, where):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise FixtureError(f"{where}: UTC RFC3339 instant with Z suffix required")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise FixtureError(f"{where}: invalid RFC3339 instant") from exc
    if parsed.tzinfo != timezone.utc:
        raise FixtureError(f"{where}: instant must be UTC")
    return parsed


def r2_metadata(meta, where, protocol, kind):
    obj(meta, {"configured_ids", "uptime_origin", "reserved_header_instant", "template_ids", "sequence_start", "options", "sampling_ie"}, where)
    ids = obj(required(meta, "configured_ids", where), {"observation_domain_id", "source_id", "engine_type", "engine_id"}, where + ".configured_ids")
    for key, val in ids.items():
        integer(val, where + ".configured_ids." + key)
        limit = 255 if key.startswith("engine_") else (1 << 32) - 1
        if val > limit: raise FixtureError(f"{where}.configured_ids.{key}: outside pinned range")
    origin = r2_utc(required(meta, "uptime_origin", where), where + ".uptime_origin")
    header = r2_utc(required(meta, "reserved_header_instant", where), where + ".reserved_header_instant")
    if header < origin: raise FixtureError(f"{where}: reserved header instant precedes uptime origin")
    templates = required(meta, "template_ids", where)
    expected_templates = {} if protocol == "v5" else {"ipv4": 256, "ipv6": 257}
    if templates != expected_templates: raise FixtureError(f"{where}.template_ids: protocol-specific template set drifted")
    if required(meta, "options", where) != "none": raise FixtureError(f"{where}.options: only none is permitted")
    sequence = integer(required(meta, "sequence_start", where), where + ".sequence_start")
    if sequence > (1 << 32) - 1: raise FixtureError(f"{where}.sequence_start: outside uint32")
    has_ie = "sampling_ie" in meta
    if has_ie:
        ie = obj(meta["sampling_ie"], {"identity", "width", "ordinary"}, where + ".sampling_ie")
        if ie != {"identity": 34, "width": 4, "ordinary": True}: raise FixtureError(f"{where}.sampling_ie: must be ordinary four-byte IE/type 34")
    if (kind == "two-rate") != has_ie: raise FixtureError(f"{where}: sampling IE metadata is required only for two-rate fixtures")


def validate(path):
    root = load(path)
    obj(root, {"schema", "version", "profile", "framing", "hierarchy", "attribute_schema", "fixtures", "generated_cases"}, "root")
    if root.get("schema") != "otel-netflow-canonical-fixtures" or root.get("version") != 1: raise FixtureError("root: unsupported schema/version")
    profile = obj(required(root, "profile", "root"), {"name", "contrib_commit", "goflow2_commit"}, "profile")
    if profile != {"name": "contrib-netflowreceiver-v0.160.0", "contrib_commit": "982f20b8a8e8a2569fab3e27cf8b008e8a5080c1", "goflow2_commit": "c9824f41bcad11d4490a668ed5270b03056d8217"}: raise FixtureError("profile: pinned revisions drifted")
    if root["hierarchy"] != R2_HIERARCHY: raise FixtureError("hierarchy: pinned Logs/ResourceLogs/ScopeLogs shape drifted")
    framing = obj(root["framing"], {"tuple_stream", "logical_request", "independent_calculator", "type_codes", "integer_encoding", "attribute_order"}, "framing")
    if framing.get("tuple_stream") != "record-index:u32be,key-length:u16be,key:utf8,type:u8,value-length:u32be,value:bytes" or framing.get("logical_request") != "magic:OTELNETFLOW-FIXTURE-V1,record-count:u32be,descriptor-json-length:u32be,descriptor-json:{attributes,hierarchy,mode,role{id,base_fixture_id,protocol,shape,metadata}}:utf8-sort_keys=true-separators=(',',':'),tuple-stream" or framing.get("independent_calculator") != "magic:OTELNETFLOW-INDEPENDENT-TUPLES-V1,record-count:u32be,descriptor-json-length:u16be,descriptor-json:{attributes,hierarchy,mode,role{id,base_fixture_id,protocol,shape,metadata}}:utf8-sort_keys=true-separators=(',',':'),independently-derived-tuples" or framing.get("integer_encoding") != "signed-int64-big-endian" or framing.get("attribute_order") != "attribute_schema order, then generated custom order": raise FixtureError("framing representation is unpinned")
    if framing.get("type_codes") != {"string": 1, "int": 2, "bytes": 3}: raise FixtureError("framing.type_codes: unexpected")
    schema_items = root["attribute_schema"]
    if not isinstance(schema_items, list) or len(schema_items) != 41: raise FixtureError("attribute_schema: exactly 41 entries required")
    schema = {}
    for i, item in enumerate(schema_items):
        item = obj(item, {"name", "type", "required"}, f"attribute_schema[{i}]")
        if item.get("name") != ATTR_NAMES[i] or item.get("name") in schema or item.get("type") not in {"string", "int"} or not isinstance(item.get("required"), bool): raise FixtureError(f"attribute_schema[{i}]: name/order/type mismatch")
        schema[item["name"]] = {"type": item["type"], "required": item["required"]}
    if {k for k, v in schema.items() if not v["required"]} != OPTIONAL_ATTRS: raise FixtureError("attribute_schema: optional set drifted")
    fixture_items = root["fixtures"]
    if not isinstance(fixture_items, list): raise FixtureError("fixtures: expected array")
    fixtures = {}
    for i, item in enumerate(fixture_items):
        item = obj(item, {"id", "kind", "base_fixture_id", "protocol", "shape", "metadata", "attributes", "overrides", "records"}, f"fixtures[{i}]")
        fid = string(required(item, "id", f"fixtures[{i}]"), f"fixtures[{i}].id")
        if fid in fixtures or not ID_RE.fullmatch(fid): raise FixtureError(f"{fid}: duplicate or unstable ID")
        kind, protocol, shape = item.get("kind"), item.get("protocol"), item.get("shape")
        if kind not in {"base", "variant", "two-rate"} or protocol not in PROTOCOLS or shape not in SHAPES: raise FixtureError(f"{fid}: unsupported kind/protocol/shape")
        expected = R2_ROLES.get(fid)
        if expected is None or (kind, protocol, shape, item.get("base_fixture_id")) != expected: raise FixtureError(f"{fid}: exact role table mismatch")
        r2_metadata(required(item, "metadata", fid), fid + ".metadata", protocol, kind)
        if kind == "base":
            if set(item) != {"id", "kind", "protocol", "shape", "metadata", "attributes"}: raise FixtureError(f"{fid}: base keys drifted")
            validate_attrs(required(item, "attributes", fid), schema, fid + ".attributes")
        elif kind == "variant":
            if set(item) != {"id", "kind", "base_fixture_id", "protocol", "shape", "metadata", "overrides"}: raise FixtureError(f"{fid}: variant keys drifted")
            ov = obj(item["overrides"], {"attributes", "remove_attributes"}, fid + ".overrides")
            if "attributes" in ov: validate_attrs(ov["attributes"], schema, fid + ".overrides.attributes", partial=True)
            if "remove_attributes" in ov and (not isinstance(ov["remove_attributes"], list) or len(set(ov["remove_attributes"])) != len(ov["remove_attributes"]) or any(x not in ATTR_NAMES for x in ov["remove_attributes"])): raise FixtureError(f"{fid}.overrides.remove_attributes: invalid")
        else:
            if set(item) != {"id", "kind", "base_fixture_id", "protocol", "shape", "metadata", "records"}: raise FixtureError(f"{fid}: two-rate keys drifted")
            records = item["records"]
            if not isinstance(records, list) or len(records) != 2: raise FixtureError(f"{fid}: exactly two records required")
            for j, rec in enumerate(records):
                ov = obj(required(rec, "overrides", f"{fid}.records[{j}]"), {"attributes", "remove_attributes"}, f"{fid}.records[{j}].overrides")
                if set(ov.get("attributes", {})) != {"flow.sampling_rate"} or ov["attributes"]["flow.sampling_rate"] != (1000 if j == 0 else 2000): raise FixtureError(f"{fid}: rates must be exactly 1000 then 2000")
        fixtures[fid] = item
    if set(fixtures) != set(R2_ROLES): raise FixtureError("fixtures: mandated role set mismatch")
    material = {}
    for fid, item in fixtures.items():
        material[fid] = materialize(fixtures, fid)
        validate_attrs(material[fid]["attributes"], schema, fid + ".materialized")
    base = material["canonical-ipv4-v1"]["attributes"]
    fixed = {"source.address": "192.0.2.1", "destination.address": "198.51.100.2", "source.port": 12345, "destination.port": 443, "network.transport": "tcp", "network.type": "ipv4", "flow.io.bytes": 56789, "flow.io.packets": 1234, "flow.type": "netflow_v9", "flow.sequence_num": 7, "flow.time_received": 1788220802000000000, "flow.start": 1788220801000000000, "flow.end": 1788220801001000000, "flow.sampling_rate": 1000, "flow.sampler_address": "192.0.2.254"}
    for key, val in fixed.items():
        if base.get(key) != val: raise FixtureError(f"canonical-ipv4-v1.{key}: pinned value drifted")
    zero = material["canonical-zero-v1"]["attributes"]
    for key, val in zero.items():
        if key in STRING_ATTRS:
            expected = "00:00:00:00:00:00" if key in {"flow.src_mac", "flow.dst_mac"} else ("hopopt" if key == "network.transport" else ("ipv4" if key == "network.type" else ("netflow_v9" if key == "flow.type" else "0.0.0.0")))
        else: expected = 0
        if val != expected: raise FixtureError(f"canonical-zero-v1.{key}: zero sentinel drifted")
    ipv6 = material["canonical-ipv6-v1"]["attributes"]
    if ipv6.get("source.address") != "2001:db8::1" or ipv6.get("destination.address") != "2001:db8::2" or ipv6.get("flow.next_hop") != "2001:db8::ff" or ipv6.get("flow.bgp_next_hop") != "2001:db8::fe" or ipv6.get("network.type") != "ipv6": raise FixtureError("canonical-ipv6-v1: endpoints/family drifted")
    if material["canonical-next-hop-v1"]["attributes"].get("flow.next_hop") is None or "flow.bgp_next_hop" in material["canonical-next-hop-v1"]["attributes"]: raise FixtureError("next-hop role mismatch")
    if material["canonical-bgp-next-hop-v1"]["attributes"].get("flow.bgp_next_hop") is None or "flow.next_hop" in material["canonical-bgp-next-hop-v1"]["attributes"]: raise FixtureError("BGP-next-hop role mismatch")
    generated = root["generated_cases"]
    if not isinstance(generated, list) or {g.get("id") for g in generated} != {"hard-admission-unselected-v1", "hard-copy-selected-v1"}: raise FixtureError("generated_cases: exact hard-case IDs required")
    for case in generated:
        obj(case, {"id", "base_fixture_id", "protocol", "shape", "metadata", "generator", "hashes", "copied_subset", "occupancy"}, case.get("id", "generated"))
        role = R2_GENERATED_ROLES.get(case.get("id"))
        if role is None or any(case.get(key) != role[key] for key in ("base_fixture_id", "protocol", "shape")) or case.get("metadata") != role["metadata"]:
            raise FixtureError(f"{case.get('id')}: generated role or metadata drifted")
        if case.get("base_fixture_id") not in fixtures: raise FixtureError(f"{case.get('id')}: unknown base fixture")
        r2_metadata(case["metadata"], case["id"] + ".metadata", case["protocol"], "base")
        hashes = obj(case["hashes"], {"tuple_stream_sha256", "logical_request_sha256", "independent_calculator_sha256"}, case["id"] + ".hashes")
        if any(not isinstance(v, str) or not re.fullmatch(r"[0-9a-f]{64}", v) or int(v, 16) == 0 for v in hashes.values()): raise FixtureError(f"{case['id']}.hashes: nonzero lowercase SHA-256 values required")
        obj(case["occupancy"], {"logical_bytes", "fixed_occupancy_bytes", "padding_total", "node_count", "record_nodes", "attributes_per_record", "scope_bytes", "canonical_key_string_bytes", "custom_key_bytes", "pad_key_bytes", "subset_node_count", "subset_record_nodes", "subset_attributes_per_record", "copied_subset_bytes", "max_message_bytes", "q_min", "q_max"}, case["id"] + ".occupancy")
        if case["id"] == "hard-copy-selected-v1":
            if case["generator"].get("endpoint_host") != "192.0.2.200" or case["generator"].get("endpoint_port") != 2055: raise FixtureError("hard-copy endpoint drifted")
    canonical_bytes = json.dumps(root, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical_bytes).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest")
    args = parser.parse_args(argv)
    try:
        digest = validate(args.manifest)
    except FixtureError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"PASS: canonical fixtures valid; canonical_manifest_sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
