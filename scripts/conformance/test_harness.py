#!/usr/bin/env python3
"""Focused failure and OTLP identity checks using this run's fresh evidence."""
import copy
import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

import replay
import verify

EVIDENCE = Path(sys.argv.pop(1)).resolve()
ROOT = Path(__file__).resolve().parents[2]

# Independent expected inputs: removing an entry from either runner hash list
# or its preflight guard must make these controls fail.
MAINTAINED_INPUTS = (
    'internal/destination/rejection.go',
    'internal/destination/ledger.go',
    'internal/destination/packer.go',
    'internal/destination/lifetime.go',
    'internal/destination/lifetime_test.go',
    'internal/destination/state.go',
    'internal/destination/lifecycle.go',
    'internal/destination/publication.go',
    'internal/destination/refresh.go',
    'clock.go', 'config.go', 'factory.go', 'exporter.go',
    'telemetry_lifetime.go', 'telemetry_lifetime_test.go', 'clock_test.go',
    'metadata.yaml',
    'documentation.md',
    'telemetry.go',
    'telemetry_acceptance_test.go',
    'telemetry_rejection_test.go',
    'internal/metadata/generated_telemetry.go',
    'internal/metadata/generated_telemetry_test.go',
    'internal/metadatatest/generated_telemetrytest.go',
    'internal/metadatatest/generated_telemetrytest_test.go',
)
RETAINED_INPUTS = (
    'go.mod', 'go.sum', 'telemetry_conditional_test.go',
    'integration/conformance/registry/netflow-extension.yaml',
    'integration/conformance/scenarios/upstream/conformance.yaml',
    'integration/conformance/scenarios/custom/conformance.yaml',
    'integration/conformance/telemetry_snapshot_test.go.in',
    'scripts/ci/capture.py', 'scripts/conformance/replay.py',
    'scripts/conformance/verify.py', 'scripts/conformance/test_harness.py',
    'scripts/conformance/requirements-py3.13.txt', 'scripts/conformance/run.sh',
    'scripts/conformance/go-module-graph.sha256',
)


def copied_inputs(destination):
    for name in RETAINED_INPUTS + MAINTAINED_INPUTS:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)


def snapshot_metrics(snapshot):
    return snapshot['metrics'] + [
        metric for scope in snapshot['scope_metrics'] for metric in scope['metrics']
    ]


class EvidenceGuards(unittest.TestCase):
    def setUp(self):
        self.snapshot = json.loads(
            (EVIDENCE / 'captures/custom-strict-valid.json').read_text()
        )

    def test_otlp_preserves_identity(self):
        request = replay.request_from_snapshot(self.snapshot)
        self.assertEqual(len(request.resource_metrics), self.snapshot['scope_count'])
        for resource, source in zip(request.resource_metrics, self.snapshot['scope_metrics']):
            self.assertEqual(resource.schema_url, self.snapshot['resource'].get('schema_url', ''))
            attrs = {kv.key: kv.value for kv in resource.resource.attributes}
            for attr in self.snapshot['resource']['attributes']:
                self.assertEqual(attrs[attr['key']], replay.any_value(attr['value'], attr['type']))
            scope = resource.scope_metrics[0]
            self.assertEqual(scope.scope.name, source['scope']['name'])
            self.assertEqual(scope.scope.version, source['scope'].get('version', ''))
            self.assertEqual(scope.schema_url, source['scope'].get('schema_url', ''))
            self.assertEqual([m.name for m in scope.metrics], [m['name'] for m in source['metrics']])

    def test_missing_identity_and_duplicate_metrics_fail(self):
        for field in ('resource', 'scope_metrics', 'capture_id'):
            with self.subTest(field=field):
                broken = copy.deepcopy(self.snapshot)
                del broken[field]
                with self.assertRaises(replay.ReplayError):
                    replay.validate_snapshot(broken)
        self.snapshot['scope_metrics'][0]['metrics'].append(
            self.snapshot['scope_metrics'][0]['metrics'][0]
        )
        with self.assertRaises(replay.ReplayError):
            replay.validate_snapshot(self.snapshot)

    def test_lifetime_signal_guards(self):
        replay.validate_snapshot(self.snapshot)
        data = json.loads((EVIDENCE / 'data/custom-strict.json').read_text())
        for name in replay.LIFETIME_TYPES:
            for mutation in ('missing', 'duplicate'):
                with self.subTest(signal=name, mutation=mutation):
                    broken = copy.deepcopy(self.snapshot)
                    for metrics in [broken['metrics']] + [s['metrics'] for s in broken['scope_metrics']]:
                        targets = [m for m in metrics if m['name'] == name]
                        if mutation == 'missing':
                            metrics[:] = [m for m in metrics if m['name'] != name]
                        else:
                            metrics.extend(copy.deepcopy(targets))
                    with self.assertRaises(replay.ReplayError):
                        replay.validate_snapshot(broken)
                    reduced = copy.deepcopy(data)
                    if mutation == 'missing':
                        reduced['metrics'].remove(name)
                    else:
                        reduced['metrics'].append(name)
                    with self.assertRaisesRegex(verify.EvidenceError, 'all 14 signals'):
                        verify.check_data(reduced, 'custom-controls')

    def test_lifetime_metadata_and_attribute_guards(self):
        for name, kind in replay.LIFETIME_TYPES.items():
            for key, value in (
                ('unit', 'By'), ('data_type', 'sum[int64]'),
                ('data_type', 'gauge[int64]' if kind == 'gauge[float64]' else 'gauge[float64]'),
                ('monotonic', False), ('monotonic', True),
                ('temporality', 'CumulativeTemporality'),
            ):
                with self.subTest(signal=name, key=key, value=value):
                    broken = copy.deepcopy(self.snapshot)
                    for metric in snapshot_metrics(broken):
                        if metric['name'] == name:
                            metric[key] = value
                    with self.assertRaises(replay.ReplayError):
                        replay.validate_snapshot(broken)
                    with self.assertRaises(replay.ReplayError):
                        replay.request_from_snapshot(broken)
            for mutation in ('missing', 'extra', 'empty', 'wrong-type', 'duplicate', 'malformed', 'duplicate-point'):
                with self.subTest(signal=name, attributes=mutation):
                    broken = copy.deepcopy(self.snapshot)
                    for metric in snapshot_metrics(broken):
                        if metric['name'] != name:
                            continue
                        attrs = metric['points'][0]['attributes']
                        if mutation == 'missing':
                            attrs.clear()
                        elif mutation == 'extra':
                            attrs.append({'key': 'reason', 'type': 'string', 'value': 'guard-canary'})
                        elif mutation == 'empty':
                            attrs[0]['value'] = ''
                        elif mutation == 'wrong-type':
                            attrs[0].update(type='int64', value=1)
                        elif mutation == 'duplicate':
                            attrs.append(copy.deepcopy(attrs[0]))
                        elif mutation == 'malformed':
                            del attrs[0]['value']
                        else:
                            metric['points'].append(copy.deepcopy(metric['points'][0]))
                    with self.assertRaises(replay.ReplayError):
                        replay.validate_snapshot(broken)

    def test_lifetime_scalar_guards(self):
        for name, kind in replay.LIFETIME_TYPES.items():
            invalid = [True, False, None, '0', -1, -0.001, math.nan, math.inf, -math.inf]
            invalid += [0, 1] if kind == 'gauge[float64]' else [0.0, 1.0, 0.5, 2, 1 << 63]
            for value in invalid:
                with self.subTest(signal=name, value=value):
                    broken = copy.deepcopy(self.snapshot)
                    for metric in snapshot_metrics(broken):
                        if metric['name'] == name:
                            metric['points'][0]['value'] = value
                    with self.assertRaises(replay.ReplayError):
                        replay.validate_snapshot(broken)
            # Validate flat and nested representations separately: Python numeric
            # equality alone considers True == 1 == 1.0 and can mask type drift.
            broken = copy.deepcopy(self.snapshot)
            metric = next(m for m in broken['metrics'] if m['name'] == name)
            metric['points'][0]['value'] = True
            with self.assertRaises(replay.ReplayError):
                replay.validate_snapshot(broken)

    def test_otlp_preserves_gauges_and_exact_sums(self):
        snapshot = copy.deepcopy(self.snapshot)
        # Exercise zero and fractional Float64 encodings, both binary latch
        # values, and integer counters that cannot pass through a float.
        for remaining in (0.0, 0.001, 4294967.296):
            for exhausted in (0, 1):
                for metric in snapshot_metrics(snapshot):
                    if metric['name'].endswith('.uptime_remaining'):
                        for point in metric['points']:
                            point['value'] = remaining
                    elif metric['name'].endswith('.uptime_exhausted'):
                        for point in metric['points']:
                            point['value'] = exhausted
                    elif metric['name'] == replay.MUTATION_METRIC:
                        metric['points'][0]['value'] = (1 << 53) + 1
                replay.validate_snapshot(snapshot)
                request = replay.request_from_snapshot(snapshot)
                actual = {metric.name: metric for resource in request.resource_metrics
                          for scope in resource.scope_metrics for metric in scope.metrics}
                for source in snapshot['metrics']:
                    metric = actual[source['name']]
                    if source['name'] in replay.LIFETIME_TYPES:
                        self.assertEqual(metric.WhichOneof('data'), 'gauge')
                        points = metric.gauge.data_points
                        scalar = 'as_double' if source['data_type'] == 'gauge[float64]' else 'as_int'
                    else:
                        self.assertEqual(metric.WhichOneof('data'), 'sum')
                        self.assertEqual(metric.sum.aggregation_temporality, replay.AGGREGATION_TEMPORALITY_CUMULATIVE)
                        self.assertEqual(metric.sum.is_monotonic, source['monotonic'])
                        points = metric.sum.data_points
                        scalar = 'as_int'
                    self.assertEqual(len(points), len(source['points']))
                    for point, expected in zip(points, source['points']):
                        self.assertEqual(point.WhichOneof('value'), scalar)
                        self.assertEqual(getattr(point, scalar), expected['value'])
                        self.assertEqual(point.start_time_unix_nano, expected.get('start_time_unix_nano', 0))
                        self.assertEqual(point.time_unix_nano, expected.get('time_unix_nano', 0))
                        self.assertEqual({a.key: a.value for a in point.attributes}, {
                            a['key']: replay.any_value(a['value'], a['type']) for a in expected['attributes']})

    def test_stale_capture_fails(self):
        with self.assertRaises(replay.ReplayError):
            replay.regular_new_file(EVIDENCE / 'captures/custom-strict-valid.json', 'capture')

    def test_rejection_signal_guards(self):
        replay.validate_snapshot(self.snapshot)
        for mutation in ('missing', 'duplicate'):
            with self.subTest(mutation=mutation):
                broken = copy.deepcopy(self.snapshot)
                for metrics in [broken['metrics']] + [s['metrics'] for s in broken['scope_metrics']]:
                    targets = [m for m in metrics if m['name'] == replay.REJECTION_METRIC]
                    if mutation == 'missing':
                        metrics[:] = [m for m in metrics if m['name'] != replay.REJECTION_METRIC]
                    else:
                        metrics.extend(copy.deepcopy(targets))
                with self.assertRaisesRegex(replay.ReplayError, 'signal set mismatch|duplicate metric names'):
                    replay.validate_snapshot(broken)
        for mutation in ('unknown', 'missing', 'extra'):
            with self.subTest(reason=mutation):
                broken = copy.deepcopy(self.snapshot)
                for metric in snapshot_metrics(broken):
                    if metric['name'] != replay.REJECTION_METRIC:
                        continue
                    attrs = metric['points'][0]['attributes']
                    if mutation == 'missing':
                        attrs[:] = [a for a in attrs if a['key'] != 'rejection_reason']
                    elif mutation == 'extra':
                        attrs.append({'key': 'raw_record', 'type': 'string', 'value': 'guard-canary'})
                    else:
                        next(a for a in attrs if a['key'] == 'rejection_reason')['value'] = 'guard-unknown'
                with self.assertRaisesRegex(replay.ReplayError, 'rejected_records'):
                    replay.validate_snapshot(broken)
        data = json.loads((EVIDENCE / 'data/custom-strict.json').read_text())
        for mutation in ('missing', 'duplicate'):
            broken = copy.deepcopy(data)
            if mutation == 'missing':
                broken['metrics'].remove(replay.REJECTION_METRIC)
            else:
                broken['metrics'].append(replay.REJECTION_METRIC)
            with self.assertRaisesRegex(verify.EvidenceError, 'all 14 signals'):
                verify.check_data(broken, 'custom-controls')

    def test_rejection_contract_guards(self):
        for key, value in (
            ('unit', 'By'), ('data_type', 'gauge[int64]'),
            ('monotonic', False), ('temporality', 'DeltaTemporality'),
        ):
            with self.subTest(key=key):
                broken = copy.deepcopy(self.snapshot)
                for metric in snapshot_metrics(broken):
                    if metric['name'] == replay.REJECTION_METRIC:
                        metric[key] = value
                with self.assertRaises(replay.ReplayError):
                    replay.validate_snapshot(broken)
        for value in (0, -1, True):
            with self.subTest(value=value):
                broken = copy.deepcopy(self.snapshot)
                for metric in snapshot_metrics(broken):
                    if metric['name'] == replay.REJECTION_METRIC:
                        metric['points'][0]['value'] = value
                with self.assertRaises(replay.ReplayError):
                    replay.validate_snapshot(broken)

    def test_missing_control_and_report_fail(self):
        data = json.loads((EVIDENCE / 'data/custom-strict.json').read_text())
        verify.check_data(data, 'custom-controls')
        data['findings'].pop()
        with self.assertRaises(verify.EvidenceError):
            verify.check_data(data, 'custom-controls')
        with tempfile.TemporaryDirectory() as path:
            with self.assertRaises(verify.EvidenceError):
                verify.check_reports(Path(path), {'valid'}, require_valid_clean=True)

    def test_mutations_change_only_selected_outcome(self):
        for mode in ('type_mismatch', 'missing_required_outcome'):
            mutated = copy.deepcopy(self.snapshot)
            replay.mutate(mutated, mode)
            _, point = replay.find_mutation_target(mutated)
            _, original = replay.find_mutation_target(self.snapshot)
            expected = [attr for attr in original['attributes'] if attr['key'] != 'outcome']
            self.assertEqual([a for a in point['attributes'] if a['key'] != 'outcome'], expected)
            outcomes = [a for a in point['attributes'] if a['key'] == 'outcome']
            self.assertEqual(outcomes, [{'key': 'outcome', 'type': 'int64', 'value': 1}] if mode == 'type_mismatch' else [])

    def test_missing_tool_fails_before_setup(self):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as path:
            for name in ('dirname', 'uname'):
                (Path(path) / name).symlink_to(shutil.which(name))
            environment = os.environ.copy()
            environment['PATH'] = path
            for key in list(environment):
                if key.startswith(('NETFLOW_CONFORMANCE_', 'OTEL_EXPORTER_OTLP_')):
                    del environment[key]
            result = subprocess.run(
                ['/bin/bash', str(root / 'scripts/conformance/run.sh')],
                env=environment, capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn('required tool is missing: git', result.stderr)

    def test_missing_scenario_fails_before_setup(self):
        # A minimal moved checkout intentionally lacks the required scenario.
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as path:
            moved = Path(path)
            script = moved / 'scripts/conformance/run.sh'
            script.parent.mkdir(parents=True)
            script.write_bytes((root / 'scripts/conformance/run.sh').read_bytes())
            registry = moved / 'integration/conformance/registry/netflow-extension.yaml'
            registry.parent.mkdir(parents=True)
            registry.write_bytes((root / 'integration/conformance/registry/netflow-extension.yaml').read_bytes())
            result = subprocess.run(['/bin/bash', str(script)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertIn('scenarios/custom/conformance.yaml', result.stderr)
            self.assertFalse((moved / 'artifacts').exists())

    def test_maintained_input_guards(self):
        with tempfile.TemporaryDirectory() as path:
            moved = Path(path) / 'core'
            copied_inputs(moved)
            output = Path(path) / 'must-not-be-created'
            environment = os.environ.copy()
            # If an input guard regresses, this sentinel still stops the real
            # runner before setup/network; the asserted input error must win.
            environment['NETFLOW_CONFORMANCE_CORE'] = 'preflight-stop-sentinel'
            for name in MAINTAINED_INPUTS:
                target = moved / name
                original = target.read_bytes()
                for mutation in ('missing', 'symlink'):
                    with self.subTest(input=name, mutation=mutation):
                        target.unlink()
                        if mutation == 'symlink':
                            target.symlink_to(ROOT / name)
                        try:
                            result = subprocess.run(
                                ['/bin/bash', str(moved / 'scripts/conformance/run.sh'),
                                 '--output', str(output)],
                                env=environment, capture_output=True, text=True, timeout=10,
                            )
                            self.assertEqual(result.returncode, 2)
                            self.assertIn(f'required harness input is missing or not regular: {name}', result.stderr)
                            self.assertFalse(output.exists())
                        finally:
                            if target.is_symlink():
                                target.unlink()
                            target.write_bytes(original)

    def test_maintained_input_drift(self):
        runner = (ROOT / 'scripts/conformance/run.sh').read_text()
        baseline_start = 'source_hashes=$output_root/pins/source-sha256.txt\n'
        after_start = 'source_hashes_after=$work/source-sha256.after.txt\n'
        for anchor in (baseline_start, '\nold_path=$PATH\n', after_start,
                       '\ncat > "$output_root/report.md" <<EOF\n'):
            self.assertEqual(runner.count(anchor), 1, f'runner block anchor changed: {anchor}')
        baseline = runner[runner.index(baseline_start):runner.index('\nold_path=$PATH\n')]
        comparator = runner[runner.index(after_start):runner.index('\ncat > "$output_root/report.md" <<EOF\n')]
        with tempfile.TemporaryDirectory() as path:
            temporary = Path(path)
            moved = temporary / 'core'
            copied_inputs(moved)
            output = temporary / 'output'
            (output / 'pins').mkdir(parents=True)
            work = temporary / 'work'
            work.mkdir()
            environment = os.environ.copy()
            environment.update(
                repo=str(moved), output_root=str(output), work=str(work),
                source_hashes=str(output / 'pins/source-sha256.txt'),
            )

            def run_block(block):
                return subprocess.run(
                    ['/bin/bash', '-euo', 'pipefail', '-c', block], env=environment,
                    capture_output=True, text=True, timeout=10,
                )

            self.assertEqual(run_block(baseline).returncode, 0)
            result = run_block(comparator)
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in MAINTAINED_INPUTS:
                target = moved / name
                original = target.read_bytes()
                for mutation in ('modify', 'replace'):
                    with self.subTest(input=name, mutation=mutation):
                        self.assertEqual(run_block(baseline).returncode, 0)
                        try:
                            if mutation == 'modify':
                                target.write_bytes(original + b'\n# drift guard\n')
                            else:
                                replacement = temporary / 'replacement'
                                replacement.write_bytes(b'regular replacement after baseline\n')
                                os.replace(replacement, target)
                            self.assertTrue(target.is_file())
                            self.assertFalse(target.is_symlink())
                            result = run_block(comparator)
                            self.assertEqual(result.returncode, 1)
                            self.assertIn('source hashes changed during the harness run', result.stderr)
                        finally:
                            target.write_bytes(original)


if __name__ == '__main__':
    unittest.main()
