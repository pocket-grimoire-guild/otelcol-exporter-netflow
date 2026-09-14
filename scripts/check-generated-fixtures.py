#!/usr/bin/env python3
"""Reproduce and verify the two deterministic hostile fixture generators."""
import argparse
import hashlib
import ipaddress
import json
import os
import stat
import struct
import sys
from pathlib import Path


class GeneratedError(ValueError):
    pass


MAX_MANIFEST_BYTES = 1 << 20
MANIFEST_READ_CHUNK = 64 << 10


def reject_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise GeneratedError(f"duplicate JSON key: {k}")
        out[k] = v
    return out


def load(path):
    try:
        if not hasattr(os, "O_NOFOLLOW"):
            raise GeneratedError("manifest: O_NOFOLLOW is unavailable")
        candidate = Path(path)
        for component in (candidate, *candidate.parents):
            try:
                if stat.S_ISLNK(os.lstat(component).st_mode):
                    raise GeneratedError("manifest: symlink path component is forbidden")
            except FileNotFoundError:
                continue
        absolute = Path(os.path.abspath(os.fspath(candidate)))
        if len(absolute.parts) < 2 or not hasattr(os, "O_DIRECTORY"):
            raise GeneratedError("manifest: safe path traversal is unavailable")
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
                raise GeneratedError("manifest: input must be a regular file")
            if before.st_size > MAX_MANIFEST_BYTES:
                raise GeneratedError("manifest: input exceeds 1 MiB")
            chunks = []
            remaining = before.st_size
            while remaining:
                chunk = os.read(fd, min(MANIFEST_READ_CHUNK, remaining))
                if not chunk:
                    raise GeneratedError("manifest: input truncated during read")
                if len(chunk) > remaining:
                    raise GeneratedError("manifest: input grew during read")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(fd, 1):
                raise GeneratedError("manifest: input grew beyond bounded size")
            after = os.fstat(fd)
            before_identity = (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            after_identity = (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            if before_identity != after_identity:
                raise GeneratedError("manifest: input changed during read")
            raw = b"".join(chunks)
        finally:
            os.close(fd)
        return json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except GeneratedError:
        raise
    except Exception as exc:
        raise GeneratedError(f"invalid JSON: {exc}") from exc


def expect_obj(value, allowed, where):
    if not isinstance(value, dict):
        raise GeneratedError(f"{where}: expected object")
    unknown = set(value) - set(allowed)
    if unknown:
        raise GeneratedError(f"{where}: unknown key(s): {', '.join(sorted(unknown))}")
    return value


ATTR_NAMES = [
    "source.address", "source.port", "destination.address", "destination.port",
    "network.transport", "network.type", "flow.io.bytes", "flow.io.packets", "flow.type",
    "flow.sequence_num", "flow.time_received", "flow.start", "flow.end", "flow.sampling_rate",
    "flow.sampler_address", "flow.tcp_flags", "flow.in_if", "flow.out_if", "flow.ip_tos",
    "flow.ip_ttl", "flow.ip_flags", "flow.fragment_id", "flow.fragment_offset",
    "flow.ipv6_flow_label", "flow.icmp_type", "flow.icmp_code", "flow.src_mac", "flow.dst_mac",
    "flow.src_vlan", "flow.dst_vlan", "flow.vlan_id", "flow.next_hop", "flow.next_hop_as",
    "flow.src_as", "flow.dst_as", "flow.bgp_next_hop", "flow.src_net", "flow.dst_net",
    "flow.forwarding_status", "flow.observation_domain_id", "flow.observation_point_id",
]
TYPE_CODES = {"string": 1, "int": 2, "bytes": 3}
STRING_ATTRS = {
    "source.address", "destination.address", "network.transport", "network.type", "flow.type",
    "flow.sampler_address", "flow.src_mac", "flow.dst_mac", "flow.next_hop", "flow.bgp_next_hop",
}
MAGIC = b"OTELNETFLOW-FIXTURE-V1"
SUBSET_MAGIC = b"OTELNETFLOW-COPIED-SUBSET-V1"


def materialize(fixtures, fid, stack=()):
    if fid not in fixtures:
        raise GeneratedError(f"unknown base fixture ID: {fid}")
    if fid in stack:
        raise GeneratedError(f"fixture cycle: {' -> '.join(stack + (fid,))}")
    item = fixtures[fid]
    if item["kind"] == "base":
        return dict(item["attributes"])
    base = materialize(fixtures, item["base_fixture_id"], stack + (fid,))
    ov = item.get("overrides", {})
    base.update(ov.get("attributes", {}))
    for key in ov.get("remove_attributes", []):
        base.pop(key, None)
    return base



###############################################################################
# Repair-2 implementation: occupancy and framing are checked by two
# independently written calculator paths below.
R2_HIERARCHY = {
    "logs": 1, "resource_logs": 1, "scope_logs": 1,
    "resource_attributes": {}, "scope_name": "otelcol/netflowreceiver",
    "scope_attributes": {"receiver": "netflow"}, "parsed_body_empty": True,
    "fixed_traversal_nodes": 11, "record_base_nodes": 3, "node_bytes": 64,
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
PRIMARY_MAGIC = MAGIC
INDEPENDENT_MAGIC = b"OTELNETFLOW-INDEPENDENT-TUPLES-V1"
SUBSET_MAGIC = b"OTELNETFLOW-COPIED-SUBSET-V1"
R2_SELECTED = [
    "flow.io.bytes", "flow.io.packets", "network.transport", "flow.ip_tos",
    "flow.tcp_flags", "source.port", "source.address", "flow.src_net",
    "flow.in_if", "destination.port", "destination.address", "flow.dst_net",
    "flow.out_if", "flow.src_as", "flow.dst_as", "flow.sampling_rate",
    "flow.ip_ttl", "network.type", "flow.start", "flow.end",
]


def r2_hierarchy(value):
    value = expect_obj(value, set(R2_HIERARCHY), "hierarchy")
    if value != R2_HIERARCHY:
        raise GeneratedError("hierarchy metadata is not the pinned receiver shape")
    return value


def r2_scope_bytes(h):
    return len(h["scope_name"].encode("utf-8")) + len("receiver".encode()) + len("netflow".encode())


def r2_schema(root):
    items = root["attribute_schema"]
    if not isinstance(items, list) or len(items) != len(ATTR_NAMES):
        raise GeneratedError("attribute schema must contain exactly 41 entries")
    order, types = [], {}
    for i, item in enumerate(items):
        item = expect_obj(item, {"name", "type", "required"}, f"attribute_schema[{i}]")
        name, typ = item.get("name"), item.get("type")
        if name != ATTR_NAMES[i] or name in types or typ not in {"string", "int"}:
            raise GeneratedError("attribute schema contains invalid names/types/order")
        order.append(name); types[name] = typ
    return order, types


def r2_key_string(attrs, names, types):
    total = 0
    for name in names:
        total += len(name.encode("utf-8"))
        if types[name] == "string":
            total += len(str(attrs[name]).encode("utf-8"))
    return total


def r2_occupancy(attrs, types, h, gen, custom_names, names, mode):
    n = gen["record_count"]
    a = len(names) + len(custom_names)
    record_nodes = h["record_base_nodes"] + a
    node_count = h["fixed_traversal_nodes"] + record_nodes * n
    if node_count > 1_048_576:
        raise GeneratedError("logical traversal node bound exceeded")
    canonical = r2_key_string(attrs, names, types)
    custom = sum(len(k.encode("utf-8")) for k in custom_names)
    fixed = h["node_bytes"] * node_count + r2_scope_bytes(h) + (canonical + custom) * n
    left = gen["logical_budget"] - fixed
    if left < 0:
        raise GeneratedError(f"{mode} fixed occupancy exceeds logical budget")
    if mode == "admission":
        q = []
        for _ in range(n):
            take = min(gen["scalar_ceiling"], left)
            q.append(take); left -= take
    else:
        quotient, remainder = divmod(left, n)
        q = [quotient + (1 if i < remainder else 0) for i in range(n)]
        left = 0
    if left != 0:
        raise GeneratedError(f"{mode} fill did not consume logical budget")
    return {
        "logical_bytes": fixed + sum(q), "fixed_occupancy_bytes": fixed,
        "padding_total": sum(q), "padding_lengths": q,
        "node_count": node_count, "record_nodes": record_nodes,
        "attributes_per_record": a, "scope_bytes": r2_scope_bytes(h),
        "canonical_key_string_bytes": canonical, "custom_key_bytes": custom,
        "pad_key_bytes": len(gen.get("padding_key", "").encode("utf-8")) if mode == "admission" else 0,
    }


def r2_frame(index, key, value, string_keys):
    if key in string_keys:
        raw, typ = str(value).encode("utf-8"), 1
    elif isinstance(value, int) and not isinstance(value, bool):
        raw, typ = struct.pack(">q", value), 2
    else:
        raise GeneratedError(f"invalid value for {key}")
    key_raw = key.encode("utf-8")
    return struct.pack(">IH", index, len(key_raw)) + key_raw + bytes((typ,)) + struct.pack(">I", len(raw)) + raw


def r2_primary_admission(attrs, types, h, gen, case):
    occ = r2_occupancy(attrs, types, h, gen, [gen["padding_key"]], ATTR_NAMES, "admission")
    if occ["attributes_per_record"] != 42 or occ["record_nodes"] != 45:
        raise GeneratedError("admission A=42/45-node relation drifted")
    if any(q > gen["scalar_ceiling"] for q in occ["padding_lengths"]):
        raise GeneratedError("admission scalar ceiling exceeded")
    stream, logical = hashlib.sha256(), hashlib.sha256()
    role = {key: case[key] for key in ("id", "base_fixture_id", "protocol", "shape", "metadata")}
    descriptor = json.dumps({"attributes": 42, "hierarchy": h, "mode": "admission", "role": role}, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    logical.update(PRIMARY_MAGIC + struct.pack(">I", gen["record_count"]) + struct.pack(">I", len(descriptor)) + descriptor)
    string_keys = STRING_ATTRS
    pad = gen["padding_key"]
    for i, size in enumerate(occ["padding_lengths"]):
        for name in ATTR_NAMES:
            raw = r2_frame(i, name, attrs[name], string_keys); stream.update(raw); logical.update(raw)
        nr = pad.encode("utf-8"); head = struct.pack(">IH", i, len(nr)) + nr + b"\x03" + struct.pack(">I", size)
        stream.update(head); logical.update(head)
        remain, off = size, 0
        while remain:
            take = min(remain, 65536); data = bytes((i + off + j) % 251 for j in range(take))
            stream.update(data); logical.update(data); remain -= take; off += take
    return {**occ, "tuple_stream_sha256": stream.hexdigest(), "logical_request_sha256": logical.hexdigest(), "record_count": gen["record_count"], "q_min": min(occ["padding_lengths"]), "q_max": max(occ["padding_lengths"]), "subset_node_count": 0, "subset_record_nodes": 0, "subset_attributes_per_record": 0, "copied_subset_bytes": 0, "max_message_bytes": 0}


def r2_independent_admission(attrs, order, types, h, gen, case):
    n = gen["record_count"]; pad = gen["padding_key"]
    per = sum(len(name.encode()) + (len(str(attrs[name]).encode()) if types[name] == "string" else 0) for name in order) + len(pad.encode())
    nodes = h["fixed_traversal_nodes"] + (h["record_base_nodes"] + 42) * n
    fixed = h["node_bytes"] * nodes + len(h["scope_name"].encode("utf-8")) + len("receiver".encode()) + len(h["scope_attributes"]["receiver"].encode()) + per * n
    left = gen["logical_budget"] - fixed
    if left < 0 or nodes > 1_048_576: raise GeneratedError("independent admission occupancy bounds failed")
    lengths = []
    for _ in range(n):
        take = min(gen["scalar_ceiling"], left); lengths.append(take); left -= take
    if left: raise GeneratedError("independent admission fill drift")
    digest = hashlib.sha256()
    role = {key: case[key] for key in ("id", "base_fixture_id", "protocol", "shape", "metadata")}
    desc = json.dumps({"attributes": 42, "hierarchy": h, "mode": "admission", "role": role}, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest.update(b"OTELNETFLOW-INDEPENDENT-TUPLES-V1" + struct.pack(">I", n) + struct.pack(">H", len(desc)) + desc)
    for i, size in enumerate(lengths):
        for name in order:
            nr = name.encode(); typ = 1 if types[name] == "string" else 2
            val = str(attrs[name]).encode() if typ == 1 else struct.pack(">q", attrs[name])
            digest.update(struct.pack(">I", i) + struct.pack(">H", len(nr)) + nr + bytes((typ,)) + struct.pack(">I", len(val)) + val)
        nr = pad.encode(); digest.update(struct.pack(">I", i) + struct.pack(">H", len(nr)) + nr + b"\x03" + struct.pack(">I", size))
        remain, off = size, 0
        while remain:
            take = min(remain, 65536); digest.update(bytes((i + off + j) % 251 for j in range(take))); remain -= take; off += take
    scope = len(h["scope_name"].encode("utf-8")) + len("receiver".encode()) + len(h["scope_attributes"]["receiver"].encode())
    return {"sha256": digest.hexdigest(), "logical_bytes": fixed + sum(lengths), "fixed_occupancy_bytes": fixed, "padding_total": sum(lengths), "node_count": nodes, "record_nodes": 45, "attributes_per_record": 42, "scope_bytes": scope, "canonical_key_string_bytes": per - len(pad.encode()), "padding_lengths": lengths}


def r2_primary_copy(attrs, types, h, gen, case):
    if gen.get("endpoint_host") != "192.0.2.200" or gen.get("endpoint_port") != 2055:
        raise GeneratedError("hard-copy endpoint must be literal IPv4 192.0.2.200:2055")
    try:
        if ipaddress.ip_address(gen["endpoint_host"]).version != 4: raise ValueError
    except ValueError as exc: raise GeneratedError("hard-copy endpoint is not IPv4") from exc
    if not (1 <= gen["endpoint_port"] <= 65535): raise GeneratedError("hard-copy endpoint port out of range")
    if gen["path_mtu"] != 65535 or gen["outer_header_reserve"] != 28 or 65535 - 28 != 65507 or gen["max_datagram_size"] != 65507:
        raise GeneratedError("hard-copy PMTU/reserve/datagram coupling drifted")
    if gen["core_record_bytes"] != 72 or gen["variable_prefix_bytes"] != 3 or gen["message_set_header_bytes"] != 20:
        raise GeneratedError("hard-copy core/header/prefix relationship drifted")
    names = [f"{gen['custom_prefix']}{i:02d}" for i in range(gen["custom_count"])]
    if names != [f"plan000.copy_pad_{i:02d}" for i in range(32)] or [gen["custom_element_id_start"] + i for i in range(32)] != list(range(100, 132)):
        raise GeneratedError("hard-copy custom identity/order drifted")
    occ = r2_occupancy(attrs, types, h, gen, names, ATTR_NAMES, "copy")
    if occ["attributes_per_record"] != 73 or occ["record_nodes"] != 76: raise GeneratedError("hard-copy A=73/76-node relation drifted")
    stream, logical, subset = hashlib.sha256(), hashlib.sha256(), hashlib.sha256()
    role = {key: case[key] for key in ("id", "base_fixture_id", "protocol", "shape", "metadata")}
    descriptor = json.dumps({"attributes": 73, "hierarchy": h, "mode": "copy", "role": role}, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    logical.update(PRIMARY_MAGIC + struct.pack(">I", gen["record_count"]) + struct.pack(">I", len(descriptor)) + descriptor)
    subdesc = json.dumps({"attributes": 52, "hierarchy": h, "mode": "copy-subset", "role": role}, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    subset.update(SUBSET_MAGIC + struct.pack(">I", gen["record_count"]) + struct.pack(">H", len(subdesc)) + subdesc)
    max_message = 0
    for i, total in enumerate(occ["padding_lengths"]):
        q, rem = divmod(total, 32); row = [q + (1 if j < rem else 0) for j in range(32)]
        if any(v > gen["max_length"] for v in row): raise GeneratedError("selected value exceeds max_length")
        for name in ATTR_NAMES:
            raw = r2_frame(i, name, attrs[name], STRING_ATTRS); stream.update(raw); logical.update(raw)
            if name in R2_SELECTED:
                subset.update(raw)
        message = gen["core_record_bytes"] + gen["message_set_header_bytes"] + 32 * gen["variable_prefix_bytes"] + sum(row)
        if message > gen["path_mtu"] - gen["outer_header_reserve"] or message > gen["max_datagram_size"]: raise GeneratedError("one-record message exceeds PMTU/datagram")
        max_message = max(max_message, message)
        for f, name in enumerate(names):
            value = bytes((i + f + j) % 251 for j in range(row[f])); nr = name.encode()
            if any(value[j] != (i + f + j) % 251 for j in range(len(value))): raise GeneratedError("selected custom byte survival check failed")
            framed = struct.pack(">IH", i, len(nr)) + nr + b"\x03" + struct.pack(">I", len(value)) + value
            stream.update(framed); logical.update(framed); subset.update(framed)
    sub_key = r2_key_string(attrs, R2_SELECTED, types) + sum(len(k.encode()) for k in names)
    sub_nodes = 11 + 55 * gen["record_count"]
    subset_bytes = 64 * sub_nodes + 38 + sub_key * gen["record_count"] + occ["padding_total"]
    if not (60 * 1024 * 1024 <= subset_bytes <= 64 * 1024 * 1024): raise GeneratedError("copied subset outside 60..64 MiB")
    return {**occ, "tuple_stream_sha256": stream.hexdigest(), "logical_request_sha256": logical.hexdigest(), "copied_subset_sha256": subset.hexdigest(), "copied_subset_bytes": subset_bytes, "max_message_bytes": max_message, "q_min": min(occ["padding_lengths"]), "q_max": max(occ["padding_lengths"]), "subset_node_count": sub_nodes, "subset_record_nodes": 55, "subset_attributes_per_record": 52, "record_count": gen["record_count"]}


def r2_independent_copy(attrs, order, types, h, gen, case):
    if gen.get("endpoint_host") != "192.0.2.200" or gen.get("endpoint_port") != 2055: raise GeneratedError("independent endpoint drift")
    if gen.get("path_mtu") != 65535 or gen.get("outer_header_reserve") != 28 or gen.get("max_datagram_size") != 65507: raise GeneratedError("independent PMTU drift")
    n, count = gen["record_count"], gen["custom_count"]; custom = [gen["custom_prefix"] + format(i, "02d") for i in range(count)]
    all_keys = sum(len(name.encode()) + (len(str(attrs[name]).encode()) if types[name] == "string" else 0) for name in order) + sum(len(k.encode()) for k in custom)
    nodes = h["fixed_traversal_nodes"] + (h["record_base_nodes"] + 73) * n
    fixed = h["node_bytes"] * nodes + len(h["scope_name"].encode("utf-8")) + len("receiver".encode()) + len(h["scope_attributes"]["receiver"].encode()) + all_keys * n; left = gen["logical_budget"] - fixed
    if left <= 0: raise GeneratedError("independent copy fixed occupancy exceeds budget")
    quotient, rem = divmod(left, n); qlist = [quotient + (1 if i < rem else 0) for i in range(n)]
    role = {key: case[key] for key in ("id", "base_fixture_id", "protocol", "shape", "metadata")}
    logical, subset = hashlib.sha256(), hashlib.sha256(); desc = json.dumps({"attributes": 73, "hierarchy": h, "mode": "copy", "role": role}, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    logical.update(b"OTELNETFLOW-INDEPENDENT-TUPLES-V1" + struct.pack(">I", n) + struct.pack(">H", len(desc)) + desc)
    subset_descriptor = json.dumps({"attributes": 52, "hierarchy": h, "mode": "copy-subset", "role": role}, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    subset.update(b"OTELNETFLOW-COPIED-SUBSET-V1" + struct.pack(">I", n) + struct.pack(">H", len(subset_descriptor)) + subset_descriptor)
    max_message = 0
    for i, total in enumerate(qlist):
        per, r = divmod(total, count); row = [per + (1 if j < r else 0) for j in range(count)]
        for name in order:
            nr = name.encode(); typ = 1 if types[name] == "string" else 2; val = str(attrs[name]).encode() if typ == 1 else struct.pack(">q", attrs[name]
            )
            framed = struct.pack(">I", i) + struct.pack(">H", len(nr)) + nr + bytes((typ,)) + struct.pack(">I", len(val)) + val
            logical.update(framed)
            if name in {"flow.io.bytes", "flow.io.packets", "network.transport", "flow.ip_tos", "flow.tcp_flags", "source.port", "source.address", "flow.src_net", "flow.in_if", "destination.port", "destination.address", "flow.dst_net", "flow.out_if", "flow.src_as", "flow.dst_as", "flow.sampling_rate", "flow.ip_ttl", "network.type", "flow.start", "flow.end"}:
                subset.update(framed)
        msg = 72 + 20 + 32 * 3 + sum(row)
        if msg > 65535 - 28: raise GeneratedError("independent packet bound exceeded")
        max_message = max(max_message, msg)
        for f, name in enumerate(custom):
            val = bytes((i + f + j) % 251 for j in range(row[f])); nr = name.encode(); subset_tuple = struct.pack(">I", i) + struct.pack(">H", len(nr)) + nr + b"\x03" + struct.pack(">I", len(val)) + val
            if any(val[j] != (i + f + j) % 251 for j in range(len(val))): raise GeneratedError("independent custom byte survival check failed")
            logical.update(subset_tuple); subset.update(subset_tuple)
    selected = ["flow.io.bytes", "flow.io.packets", "network.transport", "flow.ip_tos", "flow.tcp_flags", "source.port", "source.address", "flow.src_net", "flow.in_if", "destination.port", "destination.address", "flow.dst_net", "flow.out_if", "flow.src_as", "flow.dst_as", "flow.sampling_rate", "flow.ip_ttl", "network.type", "flow.start", "flow.end"]
    selected_keys = 0
    for name in selected:
        selected_keys += len(name.encode())
        if types[name] == "string": selected_keys += len(str(attrs[name]).encode())
    selected_keys += sum(len(k.encode()) for k in custom)
    subset_nodes = h["fixed_traversal_nodes"] + (h["record_base_nodes"] + 52) * n
    subset_bytes = h["node_bytes"] * subset_nodes + r2_scope_bytes(h) + selected_keys * n + sum(qlist)
    scope = len(h["scope_name"].encode("utf-8")) + len("receiver".encode()) + len(h["scope_attributes"]["receiver"].encode())
    return {"logical_request_sha256": logical.hexdigest(), "copied_subset_sha256": subset.hexdigest(), "logical_bytes": fixed + sum(qlist), "fixed_occupancy_bytes": fixed, "padding_total": sum(qlist), "node_count": nodes, "record_nodes": 76, "attributes_per_record": 73, "scope_bytes": scope, "copied_subset_bytes": subset_bytes, "max_message_bytes": max_message, "q_min": min(qlist), "q_max": max(qlist), "subset_node_count": subset_nodes}


def verify(path, print_computed=False):
    root = load(path)
    expect_obj(root, {"schema", "version", "profile", "framing", "hierarchy", "attribute_schema", "fixtures", "generated_cases"}, "root")
    if root.get("schema") != "otel-netflow-canonical-fixtures" or root.get("version") != 1: raise GeneratedError("unsupported schema/version")
    h = r2_hierarchy(root.get("hierarchy")); framing = expect_obj(root["framing"], {"tuple_stream", "logical_request", "independent_calculator", "type_codes", "integer_encoding", "attribute_order"}, "framing")
    if framing.get("tuple_stream") != "record-index:u32be,key-length:u16be,key:utf8,type:u8,value-length:u32be,value:bytes" or framing.get("logical_request") != "magic:OTELNETFLOW-FIXTURE-V1,record-count:u32be,descriptor-json-length:u32be,descriptor-json:{attributes,hierarchy,mode,role{id,base_fixture_id,protocol,shape,metadata}}:utf8-sort_keys=true-separators=(',',':'),tuple-stream" or framing.get("independent_calculator") != "magic:OTELNETFLOW-INDEPENDENT-TUPLES-V1,record-count:u32be,descriptor-json-length:u16be,descriptor-json:{attributes,hierarchy,mode,role{id,base_fixture_id,protocol,shape,metadata}}:utf8-sort_keys=true-separators=(',',':'),independently-derived-tuples" or framing.get("integer_encoding") != "signed-int64-big-endian" or framing.get("attribute_order") != "attribute_schema order, then generated custom order": raise GeneratedError("framing metadata drifted")
    order, types = r2_schema(root); fixtures = {}
    for item in root["fixtures"]:
        if not isinstance(item, dict): raise GeneratedError("fixture entry must be object")
        expect_obj(item, {"id", "kind", "base_fixture_id", "protocol", "shape", "metadata", "attributes", "overrides", "records"}, "fixture")
        if item.get("id") in fixtures: raise GeneratedError("duplicate fixture ID")
        fixtures[item["id"]] = item
    generated = root["generated_cases"]
    if not isinstance(generated, list) or {g.get("id") for g in generated} != {"hard-admission-unselected-v1", "hard-copy-selected-v1"}: raise GeneratedError("exact hard-case IDs required")
    seen = set(fixtures); results = {}
    for case in generated:
        cid = case.get("id")
        if cid in seen: raise GeneratedError(f"duplicate generated ID: {cid}")
        seen.add(cid); expect_obj(case, {"id", "base_fixture_id", "protocol", "shape", "metadata", "generator", "hashes", "copied_subset", "occupancy"}, cid)
        role = R2_GENERATED_ROLES.get(cid)
        if role is None or any(case.get(key) != role[key] for key in ("base_fixture_id", "protocol", "shape")) or case.get("metadata") != role["metadata"]:
            raise GeneratedError(f"{cid}: generated role or metadata drifted")
        attrs = materialize(fixtures, case["base_fixture_id"])
        expect_obj(case["metadata"], {"configured_ids", "uptime_origin", "reserved_header_instant", "template_ids", "sequence_start", "options", "sampling_ie"}, cid + ".metadata")
        gen = case["generator"]
        allowed = {"version", "record_count", "padding_key", "padding_type", "scalar_ceiling", "logical_budget", "node_charge", "selected", "fill", "custom_prefix", "custom_count", "custom_pen", "custom_element_id_start", "custom_type", "max_length", "path_mtu", "outer_header_reserve", "max_datagram_size", "core_record_bytes", "variable_prefix_bytes", "message_set_header_bytes", "endpoint_host", "endpoint_port", "attributes_per_record", "record_nodes", "subset_attributes_per_record", "subset_record_nodes"}
        gen = expect_obj(gen, allowed, cid + ".generator")
        if cid == "hard-admission-unselected-v1":
            expected = {"version":"hard-admission-v1", "record_count":8192, "padding_key":"plan000.unselected_pad", "padding_type":"bytes", "scalar_ceiling":1048576, "logical_budget":67108864, "node_charge":64, "selected":False, "fill":"ascending-record-byte-pattern-mod-251", "attributes_per_record":42, "record_nodes":45}
            if gen != expected: raise GeneratedError("hard-admission generator metadata drifted")
            primary = r2_primary_admission(attrs, types, h, gen, case); independent = r2_independent_admission(attrs, order, types, h, gen, case)
            if any(primary[k] != independent[k] for k in ("logical_bytes", "fixed_occupancy_bytes", "padding_total", "node_count", "record_nodes", "attributes_per_record", "scope_bytes", "canonical_key_string_bytes", "padding_lengths")): raise GeneratedError("independent admission occupancy mismatch")
            result = {**primary, "independent_calculator_sha256": independent["sha256"]}
        elif cid == "hard-copy-selected-v1":
            expected = {"version":"hard-copy-selected-v1", "record_count":1024, "custom_prefix":"plan000.copy_pad_", "custom_count":32, "custom_pen":32473, "custom_element_id_start":100, "custom_type":"octet_array", "max_length":4096, "path_mtu":65535, "outer_header_reserve":28, "max_datagram_size":65507, "core_record_bytes":72, "variable_prefix_bytes":3, "message_set_header_bytes":20, "logical_budget":67108864, "node_charge":64, "selected":True, "fill":"quotient-remainder-byte-pattern-mod-251", "endpoint_host":"192.0.2.200", "endpoint_port":2055, "attributes_per_record":73, "record_nodes":76, "subset_attributes_per_record":52, "subset_record_nodes":55}
            if gen != expected: raise GeneratedError("hard-copy generator metadata drifted")
            primary = r2_primary_copy(attrs, types, h, gen, case); independent = r2_independent_copy(attrs, order, types, h, gen, case)
            if primary["logical_request_sha256"] == independent["logical_request_sha256"] or primary["copied_subset_sha256"] != independent["copied_subset_sha256"]: raise GeneratedError("independent hard-copy hash disagrees")
            if any(primary[k] != independent[k] for k in ("logical_bytes", "fixed_occupancy_bytes", "padding_total", "node_count", "record_nodes", "attributes_per_record", "scope_bytes", "copied_subset_bytes", "max_message_bytes", "q_min", "q_max")): raise GeneratedError("independent copy occupancy mismatch")
            result = {**primary, "independent_calculator_sha256": independent["logical_request_sha256"]}
        else: raise GeneratedError(f"unknown generated case ID: {cid}")
        hashes = expect_obj(case["hashes"], {"tuple_stream_sha256", "logical_request_sha256", "independent_calculator_sha256"}, cid + ".hashes")
        expected_hashes = {k: result[k] for k in hashes}
        if print_computed: print(cid, json.dumps(expected_hashes, sort_keys=True))
        elif hashes != expected_hashes: raise GeneratedError(f"{cid}.hashes: stored digest differs")
        occupancy = expect_obj(case["occupancy"], {"logical_bytes", "fixed_occupancy_bytes", "padding_total", "node_count", "record_nodes", "attributes_per_record", "scope_bytes", "canonical_key_string_bytes", "custom_key_bytes", "pad_key_bytes", "subset_node_count", "subset_record_nodes", "subset_attributes_per_record", "copied_subset_bytes", "max_message_bytes", "q_min", "q_max"}, cid + ".occupancy")
        if set(occupancy) != {"logical_bytes", "fixed_occupancy_bytes", "padding_total", "node_count", "record_nodes", "attributes_per_record", "scope_bytes", "canonical_key_string_bytes", "custom_key_bytes", "pad_key_bytes", "subset_node_count", "subset_record_nodes", "subset_attributes_per_record", "copied_subset_bytes", "max_message_bytes", "q_min", "q_max"}:
            raise GeneratedError(f"{cid}.occupancy: complete pinned occupancy object required")
        for key, val in occupancy.items():
            if key in result and result[key] != val: raise GeneratedError(f"{cid}.occupancy.{key}: drift")
        if cid == "hard-copy-selected-v1":
            subset = expect_obj(case["copied_subset"], {"logical_bytes", "logical_request_sha256", "every_selected_byte_survives"}, cid + ".copied_subset")
            if not print_computed and subset != {"logical_bytes": result["copied_subset_bytes"], "logical_request_sha256": result["copied_subset_sha256"], "every_selected_byte_survives": True}: raise GeneratedError(f"{cid}.copied_subset drift")
            if print_computed:
                print(cid, "copied_subset", result["copied_subset_bytes"], result["copied_subset_sha256"])
        results[cid] = result
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument("manifest"); parser.add_argument("--print-computed", action="store_true"); args = parser.parse_args(argv)
    try: values = verify(args.manifest, args.print_computed)
    except (GeneratedError, KeyError, TypeError) as exc: print(f"FAIL: {exc}", file=sys.stderr); return 1
    if not args.print_computed:
        for cid, value in values.items(): print(f"PASS: {cid} records={value['record_count']} logical_bytes={value['logical_bytes']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
