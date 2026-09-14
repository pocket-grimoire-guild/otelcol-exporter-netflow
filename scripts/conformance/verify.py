#!/usr/bin/env python3
"""Check the machine-readable evidence produced by one runner invocation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from replay import ReplayError, validate_snapshot

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
    "otelcol_netflow.exporter.templates",
}
TARGET = "otelcol_netflow.exporter.records"


class EvidenceError(RuntimeError):
    """The runner produced incomplete or contradictory evidence."""


def load_json(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise EvidenceError(f"missing regular JSON artifact: {path.name}")
    if not 0 < path.stat().st_size <= 64 << 20:
        raise EvidenceError(f"JSON artifact exceeds the bounded range: {path.name}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"invalid JSON artifact: {path.name}") from error


def check_captures(capture_dir: Path, run_id: str, modes: set[str]) -> None:
    captures: dict[str, dict[str, Any]] = {}
    for mode in modes:
        path = capture_dir / f"{run_id}-{mode}.json"
        snapshot = load_json(path)
        try:
            validate_snapshot(snapshot)
        except (ReplayError, TypeError, KeyError, ValueError) as error:
            raise EvidenceError(f"invalid SDK snapshot {path.name}: {error}") from error
        if snapshot.get("source") != "TestTelemetryConditionalProbe":
            raise EvidenceError(f"{path.name} has the wrong source")
        if snapshot.get("mode") != "actual-sdk-snapshot":
            raise EvidenceError(f"{path.name} is not an SDK snapshot")
        capture_id = snapshot.get("capture_id")
        if not isinstance(capture_id, str) or capture_id in captures:
            raise EvidenceError("capture IDs are missing or repeated")
        captures[capture_id] = snapshot
        if snapshot.get("scope_count", 0) < 1:
            raise EvidenceError(f"{path.name} has no SDK scopes")
        resource = snapshot.get("resource", {})
        attrs = resource.get("attributes", []) if isinstance(resource, dict) else []
        if not attrs or any("value" not in item for item in attrs):
            raise EvidenceError(f"{path.name} does not preserve resource values")
        target = next(
            (item for item in snapshot["metrics"] if item.get("name") == TARGET),
            None,
        )
        if not isinstance(target, dict) or not target.get("points"):
            raise EvidenceError(f"{path.name} has no mutation target point")
        point_attrs = target["points"][0].get("attributes", [])
        outcome = [item for item in point_attrs if item.get("key") == "outcome"]
        if len(outcome) != 1 or outcome[0].get("type") != "string":
            raise EvidenceError(f"{path.name} did not retain the pre-mutation outcome")


def finding_matches(
    finding: Any,
    finding_id: str,
    *,
    attribute_type: str | None = None,
) -> bool:
    if not isinstance(finding, dict):
        return False
    context = finding.get("context")
    return (
        finding.get("id") == finding_id
        and finding.get("signal_type") == "metric"
        and finding.get("signal_name") == TARGET
        and isinstance(context, dict)
        and context.get("attribute_key") == "outcome"
        and (
            attribute_type is None or context.get("attribute_type") == attribute_type
        )
    )


def check_data(data: Any, kind: str) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        raise EvidenceError("runner data file is not an object")
    metrics = data.get("metrics")
    if not isinstance(metrics, list) or set(metrics) != EXPECTED_METRICS:
        raise EvidenceError("runner data file does not cover all 11 signals")
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise EvidenceError("runner data file has no findings list")
    if kind == "custom-valid":
        if findings:
            raise EvidenceError("custom valid baseline unexpectedly has findings")
    elif kind == "custom-controls":
        if len(findings) != 2:
            raise EvidenceError("custom controls must have exactly the two expected findings")
        if not any(finding_matches(item, "type_mismatch", attribute_type="int") for item in findings):
            raise EvidenceError("type control finding lacks metric and outcome attribute")
        if not any(finding_matches(item, "required_attribute_not_present") for item in findings):
            raise EvidenceError("requiredness control finding lacks metric and outcome attribute")
    elif kind == "upstream":
        for metric_name in EXPECTED_METRICS:
            if not any(
                isinstance(item, dict)
                and item.get("signal_type") == "metric"
                and item.get("signal_name") == metric_name
                for item in findings
            ):
                raise EvidenceError(f"upstream finding is absent for {metric_name}")
    else:
        raise EvidenceError(f"unknown evidence kind {kind!r}")
    return findings


def check_reports(
    report_dir: Path, expected_names: set[str], *, require_valid_clean: bool
) -> None:
    if not report_dir.is_dir() or report_dir.is_symlink():
        raise EvidenceError("runner report directory is missing")
    actual = {path.stem for path in report_dir.glob("*.json") if path.is_file()}
    if actual != expected_names:
        raise EvidenceError(f"report set mismatch: expected={expected_names} got={actual}")
    for name in expected_names:
        report = load_json(report_dir / f"{name}.json")
        if not isinstance(report, dict) or not report.get("samples"):
            raise EvidenceError(f"raw report {name} is empty")
        if name == "valid" and require_valid_clean:
            statistics = report.get("statistics")
            if not isinstance(statistics, dict):
                raise EvidenceError("raw valid report has no statistics")
            advice_levels = statistics.get("advice_level_counts")
            if not isinstance(advice_levels, dict):
                raise EvidenceError("raw valid report has no advice-level counts")
            if advice_levels.get("violation", 0) != 0:
                raise EvidenceError("raw valid report contains a violation")


def check_log(log: Path, mode: str) -> None:
    if log.is_symlink() or not log.is_file() or not 0 < log.stat().st_size <= 1 << 20:
        raise EvidenceError("runner log is missing or exceeds 1 MiB")
    try:
        text = log.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise EvidenceError("runner log is unreadable") from error
    expected = {
        "custom-strict": ("valid, status: ok", "type_mismatch_control, status: FAIL", "missing_required_outcome_control, status: FAIL"),
        "custom-report-only": ("valid, status: ok", "type_mismatch_control, status: WARN", "missing_required_outcome_control, status: WARN"),
        "upstream-strict": ("valid, status: FAIL",),
        "upstream-report-only": ("valid, status: WARN",),
    }.get(mode)
    if expected is None:
        raise EvidenceError(f"unknown log mode {mode!r}")
    for marker in expected:
        if marker not in text:
            raise EvidenceError(f"runner log lacks {marker!r}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture-dir", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument(
        "--mode",
        choices=("custom-strict", "custom-report-only", "upstream-strict", "upstream-report-only"),
        required=True,
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.mode.startswith("custom"):
            modes = {"valid", "type_mismatch", "missing_required_outcome"}
            kind = "custom-controls"
            expected_reports = {"valid", "type_mismatch_control", "missing_required_outcome_control"}
        else:
            modes = {"valid"}
            kind = "upstream"
            expected_reports = {"valid"}
        check_captures(args.capture_dir, args.run_id, modes)
        check_data(load_json(args.data), kind)
        check_reports(
            args.report_dir,
            expected_reports,
            require_valid_clean=kind == "custom-controls",
        )
        check_log(args.log, args.mode)
        print(f"verified {args.mode}: captures, all 11 metrics, reports, findings, statuses")
        return 0
    except (EvidenceError, ReplayError, TypeError, KeyError, ValueError) as error:
        print(f"conformance evidence failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
