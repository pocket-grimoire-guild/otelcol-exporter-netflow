#!/usr/bin/env python3
"""Focused failure and OTLP identity checks using this run's fresh evidence."""
import copy
import json
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

    def test_stale_capture_fails(self):
        with self.assertRaises(replay.ReplayError):
            replay.regular_new_file(EVIDENCE / 'captures/custom-strict-valid.json', 'capture')

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


if __name__ == '__main__':
    unittest.main()
