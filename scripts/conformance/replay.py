#!/usr/bin/env python3
"""Capture the current checkout's SDK metrics and replay them over OTLP/gRPC.

The conformance runner owns the scenario process.  This bridge deliberately
keeps the capture and replay boundary visible: the Go test exercises the
package-local pilot seam, writes a complete SDK snapshot, and this process
validates and serializes that snapshot to the runner's OTLP receiver.  The
two invalid modes mutate one exact data-point attribute only after capture.
"""

from __future__ import annotations

import argparse
import base64
import json
import math
import os
import re
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import grpc
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import (
    ExportMetricsServiceRequest,
)
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2_grpc import (
    MetricsServiceStub,
)
from opentelemetry.proto.common.v1.common_pb2 import AnyValue, KeyValue
from opentelemetry.proto.metrics.v1.metrics_pb2 import (
    AGGREGATION_TEMPORALITY_CUMULATIVE,
)

MAX_CHILD_LOG_BYTES = 1 << 20
MAX_CAPTURE_BYTES = 64 << 20
CAPTURE_ID = re.compile(r"^[0-9]+-[0-9]+$")
RUN_ID = re.compile(r"^[A-Za-z0-9_.-]+$")

EXPECTED_METRICS = {
    "otelcol_exporter_in_flight_requests",
    "otelcol_exporter_sent_log_records",
    "otelcol_netflow.exporter.admission",
    "otelcol_netflow.exporter.bytes",
    "otelcol_netflow.exporter.data_messages",
    "otelcol_netflow.exporter.dns",
    "otelcol_netflow.exporter.endpoint_epochs",
    "otelcol_netflow.exporter.failures",
    "otelcol_netflow.exporter.losses",
    "otelcol_netflow.exporter.records",
    "otelcol_netflow.exporter.rejected_records",
    "otelcol_netflow.exporter.templates",
    "otelcol_netflow.exporter.uptime_remaining",
    "otelcol_netflow.exporter.uptime_exhausted",
}
MUTATION_METRIC = "otelcol_netflow.exporter.records"
LIFETIME_TYPES = {
    "otelcol_netflow.exporter.uptime_remaining": "gauge[float64]",
    "otelcol_netflow.exporter.uptime_exhausted": "gauge[int64]",
}
REJECTION_METRIC = "otelcol_netflow.exporter.rejected_records"
REJECTION_REASONS = {
    "unsupported_body", "missing_field", "invalid_type", "invalid_value",
    "map_miss", "family_mismatch", "protocol_mismatch", "time_invalid",
    "custom_unavailable", "custom_invalid", "record_too_large",
    "record_invalid", "other",
}
EXPECTED_UNITS = {
    "otelcol_exporter_in_flight_requests": "{request}",
    "otelcol_exporter_sent_log_records": "{record}",
    **{
        f"otelcol_netflow.exporter.{name}": unit
        for name, unit in {
            "admission": "{request}", "bytes": "By", "data_messages": "{message}",
            "dns": "{lookup}", "endpoint_epochs": "{epoch}", "failures": "{event}",
            "losses": "{event}", "records": "{record}",
            "rejected_records": "{record}", "templates": "{message}",
            "uptime_remaining": "s", "uptime_exhausted": "1",
        }.items()
    },
}


class ReplayError(RuntimeError):
    """A closed-boundary replay or capture failure."""


def required_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise ReplayError(f"{name} is required")
    return value


def regular_new_file(path: Path, label: str) -> None:
    if path.exists() or path.is_symlink():
        raise ReplayError(f"{label} already exists: {path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)


def run_go_test(
    core: Path, capture: Path, go: str, adapter: Path, go_log: Path
) -> None:
    source = core / "telemetry_conditional_test.go"
    if not source.is_file() or source.is_symlink():
        raise ReplayError("current checkout telemetry_conditional_test.go is missing")
    if not adapter.is_file() or adapter.is_symlink():
        raise ReplayError("conformance snapshot adapter is missing")

    original = source.read_text(encoding="utf-8")
    needle = "\twriteConditionalSnapshot(t, capture, snapshot)\n"
    if original.count(needle) != 1:
        raise ReplayError(
            "pilot test final snapshot write changed; refusing an unreviewed overlay"
        )

    with tempfile.TemporaryDirectory(prefix="netflow-conformance-overlay-") as name:
        temporary = Path(name)
        patched = temporary / source.name
        patched.write_text(
            original.replace(
                needle,
                "\twriteConformanceSnapshot(t, capture, conformanceSnapshotFromMetrics(t, &rm))\n",
                1,
            ),
            encoding="utf-8",
        )
        overlay_adapter = temporary / "conformance_snapshot_adapter_test.go"
        overlay_adapter.write_bytes(adapter.read_bytes())
        overlay = temporary / "overlay.json"
        overlay.write_text(
            json.dumps(
                {
                    "Replace": {
                        str(source): str(patched),
                        str(core / overlay_adapter.name): str(overlay_adapter),
                    }
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )

        environment = os.environ.copy()
        environment["NETFLOW_CONDITIONAL_SNAPSHOT"] = str(capture)
        environment["NETFLOW_CONFORMANCE_CAPTURE"] = str(capture)
        environment.pop("OTEL_RESOURCE_ATTRIBUTES", None)
        environment.pop("OTEL_SERVICE_NAME", None)
        command = [
            go,
            "test",
            "-mod=readonly",
            f"-overlay={overlay}",
            ".",
            "-run",
            "^TestTelemetryConditionalProbe$",
            "-count=1",
            "-timeout=120s",
        ]
        capture_script = core / "scripts/ci/capture.py"
        if not capture_script.is_file() or capture_script.is_symlink():
            raise ReplayError("bounded command capture helper is missing")
        regular_new_file(go_log, "SDK probe log")
        process = subprocess.Popen(
            [
                sys.executable,
                str(capture_script),
                "--output",
                str(go_log),
                "--max-bytes",
                str(MAX_CHILD_LOG_BYTES),
                "--",
                *command,
            ],
            cwd=core,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            output, _ = process.communicate(timeout=180)
        except subprocess.TimeoutExpired as error:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            raise ReplayError("current checkout SDK probe exceeded 180 seconds") from error
        if go_log.stat().st_size > MAX_CHILD_LOG_BYTES:
            raise ReplayError("current checkout SDK probe exceeded the 1 MiB log bound")
        if process.returncode != 0:
            detail = go_log.read_bytes()[-8192:].decode("utf-8", errors="replace")
            raise ReplayError(f"current checkout SDK probe failed:\n{detail}")


def read_snapshot(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ReplayError("SDK capture is not a regular file")
    size = path.stat().st_size
    if size <= 0 or size > MAX_CAPTURE_BYTES:
        raise ReplayError(f"SDK capture size {size} is outside the bounded range")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReplayError("SDK capture is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ReplayError("SDK capture root must be an object")
    return value


def validate_snapshot(snapshot: dict[str, Any]) -> None:
    if snapshot.get("Mode") is not None:
        raise ReplayError("SDK capture uses an unexpected key spelling")
    if snapshot.get("mode") != "actual-sdk-snapshot":
        raise ReplayError("SDK capture did not come from the actual SDK boundary")
    if snapshot.get("source") != "TestTelemetryConditionalProbe":
        raise ReplayError("SDK capture source is not the pilot conditional runner")
    capture_id = snapshot.get("capture_id")
    if not isinstance(capture_id, str) or not CAPTURE_ID.fullmatch(capture_id):
        raise ReplayError("SDK capture has no fresh capture ID")
    captured_at = snapshot.get("captured_at")
    if not isinstance(captured_at, str) or not captured_at.endswith("Z"):
        raise ReplayError("SDK capture has no UTC capture timestamp")

    resource = snapshot.get("resource")
    if not isinstance(resource, dict):
        raise ReplayError("SDK resource identity is missing")
    resource_attrs = resource.get("attributes")
    if not isinstance(resource_attrs, list) or not resource_attrs:
        raise ReplayError("SDK resource values are missing")
    if not all_attribute_values(resource_attrs, "resource"):
        raise ReplayError("SDK resource attribute values are malformed")
    resource_keys = {item["key"] for item in resource_attrs}
    declared_resource_keys = snapshot.get("resource_attributes")
    if not isinstance(declared_resource_keys, list) or set(declared_resource_keys) != resource_keys:
        raise ReplayError("SDK resource identity summary does not match values")

    scopes = snapshot.get("scope_metrics")
    if not isinstance(scopes, list) or not scopes:
        raise ReplayError("SDK scope identity is missing")
    if snapshot.get("scope_count") != len(scopes):
        raise ReplayError("SDK scope count does not match the captured scopes")
    for entry in scopes:
        if not isinstance(entry, dict) or not isinstance(entry.get("scope"), dict):
            raise ReplayError("SDK scope entry is malformed")
        scope = entry["scope"]
        if not isinstance(scope.get("name"), str) or not scope["name"]:
            raise ReplayError("SDK scope name is missing")
        attrs = scope.get("attributes")
        if not isinstance(attrs, list) or not all_attribute_values(attrs, "scope"):
            raise ReplayError("SDK scope attributes are malformed")

    metrics = snapshot.get("metrics")
    if not isinstance(metrics, list):
        raise ReplayError("SDK metric summary is missing")
    names = [metric.get("name") for metric in metrics if isinstance(metric, dict)]
    if len(names) != len(metrics) or set(names) != EXPECTED_METRICS:
        missing = sorted(EXPECTED_METRICS - set(names))
        extra = sorted(set(names) - EXPECTED_METRICS)
        raise ReplayError(f"SDK signal set mismatch; missing={missing} extra={extra}")
    if len(names) != len(set(names)):
        raise ReplayError("SDK metric summary contains duplicate metric names")
    for metric in metrics:
        validate_metric(metric)
    flat_by_name = {metric["name"]: metric for metric in metrics}
    nested: list[dict[str, Any]] = []
    for entry in scopes:
        scope = entry["scope"]
        scoped_metrics = entry.get("metrics")
        if not isinstance(scoped_metrics, list):
            raise ReplayError("SDK scope metric list is malformed")
        nested.extend(scoped_metrics)
    nested_names = [metric.get("name") for metric in nested]
    if len(nested_names) != len(EXPECTED_METRICS) or set(nested_names) != EXPECTED_METRICS:
        raise ReplayError("SDK nested scope metrics do not cover all 14 signals")
    if any(flat_by_name.get(metric.get("name")) != metric for metric in nested):
        raise ReplayError("SDK nested scope metrics differ from the flat summary")
    for metric in nested:
        validate_metric(metric)


def all_attribute_values(attributes: Any, label: str) -> bool:
    if not isinstance(attributes, list):
        return False
    seen: set[str] = set()
    for item in attributes:
        if not isinstance(item, dict):
            return False
        key = item.get("key")
        kind = item.get("type")
        if not isinstance(key, str) or not key or key in seen:
            return False
        if not isinstance(kind, str) or kind not in {
            "bool",
            "bool[]",
            "int64",
            "int64[]",
            "float64",
            "float64[]",
            "string",
            "string[]",
            "bytes",
        }:
            raise ReplayError(f"unsupported {label} attribute type {kind!r}")
        if "value" not in item:
            return False
        if not attribute_value_matches(item["value"], kind):
            raise ReplayError(f"malformed {label} attribute value for {key!r}")
        seen.add(key)
    return True


def attribute_value_matches(value: Any, kind: str) -> bool:
    if kind == "bool":
        return isinstance(value, bool)
    if kind == "int64":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "float64":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if kind == "string":
        return isinstance(value, str)
    if kind == "bytes":
        if not isinstance(value, str):
            return False
        try:
            base64.b64decode(value, validate=True)
        except ValueError:
            return False
        return True
    if kind.endswith("[]"):
        return isinstance(value, list) and all(
            attribute_value_matches(item, kind[:-2]) for item in value
        )
    return False


def validate_metric(metric: Any) -> None:
    if not isinstance(metric, dict):
        raise ReplayError("SDK metric is malformed")
    for key in ("name", "unit", "description", "data_type", "points"):
        if key not in metric:
            raise ReplayError(f"SDK metric is missing {key}")
    if not isinstance(metric["name"], str) or not metric["name"]:
        raise ReplayError("SDK metric name is empty")
    name = metric["name"]
    lifetime = name in LIFETIME_TYPES
    if not isinstance(metric["unit"], str) or not isinstance(metric["description"], str):
        raise ReplayError(f"SDK metric {name} has invalid metadata")
    if (
        name not in EXPECTED_UNITS
        or metric["unit"] != EXPECTED_UNITS[name]
        or metric["data_type"] != LIFETIME_TYPES.get(name, "sum[int64]")
    ):
        raise ReplayError(f"SDK metric {name} differs from its instrument contract")
    if lifetime:
        if "monotonic" in metric or "temporality" in metric:
            raise ReplayError(f"SDK gauge {name} has sum metadata")
    else:
        expected_monotonic = name != "otelcol_exporter_in_flight_requests"
        if type(metric.get("monotonic")) is not bool or metric["monotonic"] != expected_monotonic:
            raise ReplayError(f"SDK metric {name} has invalid monotonicity")
        if metric.get("temporality") != "CumulativeTemporality":
            raise ReplayError(f"SDK metric {name} is not cumulative")
    points = metric["points"]
    if not isinstance(points, list) or not points:
        raise ReplayError(f"SDK metric {metric['name']} has no data points")
    seen_lifetime_exporters: set[str] = set()
    for point in points:
        scalar_type = float if metric["data_type"] == "gauge[float64]" else int
        if not isinstance(point, dict) or type(point.get("value")) is not scalar_type:
            raise ReplayError(f"SDK metric {name} has a malformed point")
        value = point["value"]
        if scalar_type is float:
            if not math.isfinite(value) or value < 0:
                raise ReplayError(f"SDK remaining lifetime is not finite and nonnegative")
        elif not 0 <= value <= (1 << 63) - 1:
            raise ReplayError(f"SDK metric {name} has an invalid Int64 value")
        if name == "otelcol_netflow.exporter.uptime_exhausted" and value not in (0, 1):
            raise ReplayError("SDK exhausted lifetime is not binary")
        if not all_attribute_values(point.get("attributes"), "point"):
            raise ReplayError(f"SDK metric {metric['name']} has malformed attributes")
        if lifetime:
            attrs = point["attributes"]
            if (len(attrs) != 1 or attrs[0]["key"] != "exporter"
                    or attrs[0]["type"] != "string" or not attrs[0]["value"]):
                raise ReplayError(f"SDK gauge {name} requires only a nonempty string exporter")
            if attrs[0]["value"] in seen_lifetime_exporters:
                raise ReplayError(f"SDK gauge {name} has duplicate exporter points")
            seen_lifetime_exporters.add(attrs[0]["value"])
        if metric["name"] == REJECTION_METRIC:
            attrs = {item["key"]: item for item in point["attributes"]}
            if set(attrs) != {"exporter", "rejection_reason"}:
                raise ReplayError("SDK rejected_records requires only exporter and rejection_reason")
            if any(item["type"] != "string" for item in attrs.values()):
                raise ReplayError("SDK rejected_records attributes must be strings")
            if not attrs["exporter"]["value"] or attrs["rejection_reason"]["value"] not in REJECTION_REASONS:
                raise ReplayError("SDK rejected_records has an unknown reason or empty exporter")
            if point["value"] <= 0:
                raise ReplayError("SDK rejected_records must have a genuine nonzero count")


def find_mutation_target(snapshot: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    for entry in snapshot["scope_metrics"]:
        for metric in entry["metrics"]:
            if metric.get("name") != MUTATION_METRIC:
                continue
            points = metric.get("points")
            if not isinstance(points, list) or not points:
                continue
            point = points[0]
            return metric, point
    raise ReplayError(f"mutation target {MUTATION_METRIC} is absent")


def mutate(snapshot: dict[str, Any], mode: str) -> None:
    if mode == "valid":
        return
    _, point = find_mutation_target(snapshot)
    attrs = point["attributes"]
    outcome = [item for item in attrs if item.get("key") == "outcome"]
    if len(outcome) != 1:
        raise ReplayError("mutation target must contain exactly one outcome attribute")
    if mode == "type_mismatch":
        outcome[0]["type"] = "int64"
        outcome[0]["value"] = 1
    elif mode == "missing_required_outcome":
        point["attributes"] = [item for item in attrs if item.get("key") != "outcome"]
    else:
        raise ReplayError(f"unknown replay mode {mode!r}")


def any_value(value: Any, kind: str) -> AnyValue:
    result = AnyValue()
    if kind == "bool":
        result.bool_value = value
    elif kind == "int64":
        result.int_value = value
    elif kind == "float64":
        result.double_value = value
    elif kind == "string":
        result.string_value = value
    elif kind == "bytes":
        result.bytes_value = base64.b64decode(value, validate=True)
    elif kind.endswith("[]"):
        element_kind = kind[:-2]
        if not isinstance(value, list):
            raise ReplayError(f"attribute {kind} value is not an array")
        for item in value:
            result.array_value.values.add().CopyFrom(any_value(item, element_kind))
    else:
        raise ReplayError(f"unsupported attribute type {kind!r}")
    return result


def add_attributes(target: Any, attributes: list[dict[str, Any]]) -> None:
    for item in attributes:
        pair = target.add()
        pair.key = item["key"]
        pair.value.CopyFrom(any_value(item["value"], item["type"]))


def request_from_snapshot(snapshot: dict[str, Any]) -> ExportMetricsServiceRequest:
    request = ExportMetricsServiceRequest()
    for entry in snapshot["scope_metrics"]:
        resource_metrics = request.resource_metrics.add()
        resource = resource_metrics.resource
        add_attributes(resource.attributes, snapshot["resource"]["attributes"])
        resource_metrics.schema_url = snapshot["resource"].get("schema_url", "")
        scope_entry = resource_metrics.scope_metrics.add()
        scope = entry["scope"]
        scope_entry.scope.name = scope["name"]
        scope_entry.scope.version = scope.get("version", "")
        add_attributes(scope_entry.scope.attributes, scope.get("attributes", []))
        scope_entry.schema_url = scope.get("schema_url", "")
        for item in entry["metrics"]:
            validate_metric(item)
            metric = scope_entry.metrics.add()
            metric.name = item["name"]
            metric.description = item["description"]
            metric.unit = item["unit"]
            destination = metric.sum if item["data_type"] == "sum[int64]" else metric.gauge
            if item["data_type"] == "sum[int64]":
                destination.aggregation_temporality = AGGREGATION_TEMPORALITY_CUMULATIVE
                destination.is_monotonic = bool(item.get("monotonic", False))
            for point in item["points"]:
                output = destination.data_points.add()
                if item["data_type"] == "gauge[float64]":
                    output.as_double = point["value"]
                else:
                    output.as_int = point["value"]
                output.time_unix_nano = point.get("time_unix_nano", 0)
                output.start_time_unix_nano = point.get("start_time_unix_nano", 0)
                add_attributes(output.attributes, point["attributes"])
    return request


def export_otlp(snapshot: dict[str, Any], endpoint: str) -> None:
    if endpoint.startswith("https://"):
        raise ReplayError("HTTPS OTLP endpoint is not supported by the pinned bridge")
    if endpoint.startswith("http://"):
        endpoint = endpoint[len("http://") :]
    if ":" not in endpoint or endpoint.startswith(":") or endpoint.endswith(":"):
        raise ReplayError("OTLP endpoint must be host:port")
    if "/" in endpoint:
        raise ReplayError("OTLP endpoint must not contain a path")
    channel = grpc.insecure_channel(endpoint)
    try:
        response = MetricsServiceStub(channel).Export(
            request_from_snapshot(snapshot), timeout=30
        )
        if response.partial_success.error_message or response.partial_success.rejected_data_points:
            raise ReplayError(
                "OTLP receiver reported partial success: "
                + response.partial_success.error_message
            )
    finally:
        channel.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        required=True,
        choices=("valid", "type_mismatch", "missing_required_outcome"),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        core = Path(required_env("NETFLOW_CONFORMANCE_CORE")).resolve()
        output = Path(required_env("NETFLOW_CONFORMANCE_OUTPUT")).resolve()
        go = required_env("NETFLOW_CONFORMANCE_GO")
        endpoint = required_env("OTEL_EXPORTER_OTLP_ENDPOINT")
        run_id = required_env("NETFLOW_CONFORMANCE_RUN_ID")
        if not RUN_ID.fullmatch(run_id):
            raise ReplayError("NETFLOW_CONFORMANCE_RUN_ID contains unsafe characters")
        capture = output / "captures" / f"{run_id}-{args.mode}.json"
        go_log = output / "logs" / f"{run_id}-{args.mode}-sdk-probe.log"
        regular_new_file(capture, "capture")
        adapter = core / "integration/conformance/telemetry_snapshot_test.go.in"
        run_go_test(core, capture, go, adapter, go_log)
        snapshot = read_snapshot(capture)
        validate_snapshot(snapshot)
        mutate(snapshot, args.mode)
        export_otlp(snapshot, endpoint)
        print(
            f"replayed mode={args.mode} capture_id={snapshot['capture_id']} "
            f"scopes={snapshot['scope_count']} metrics={len(snapshot['metrics'])}"
        )
        return 0
    except ReplayError as error:
        print(f"conformance replay failed: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, KeyError, AttributeError, grpc.RpcError) as error:
        print(f"conformance replay failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
