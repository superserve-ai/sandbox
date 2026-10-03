import copy
import json
import os
import re
from pathlib import Path
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import staging_rollup_diagnostic as diagnostic
import staging_rollup_pause as pause


class StagingRollupOperationsTest(unittest.TestCase):
    def test_auxiliary_workflow_groups_cannot_replace_pending_seed(self):
        workflow = (Path(__file__).resolve().parents[1]/'.github/workflows/seed-templates.yml').read_text()
        expression = re.search(r'^  group: \$\{\{ (.+) \}\}$', workflow, re.M)[1]
        modes = ('smoke_preflight', 'receiver_diagnostic', 'rollup_diagnostic', 'rollup_pause')

        def group(event, mode=None, run_id=123):
            context = dict(github=SimpleNamespace(event_name=event, run_id=run_id),
                           inputs=SimpleNamespace(**{name: name == mode for name in modes}),
                           format=lambda template, *args: template.format(*args))
            return eval(expression.replace('&&', ' and ').replace('||', ' or '),
                        {'__builtins__': {}}, context)

        self.assertEqual(group('push'), 'seed-templates')
        self.assertEqual(group('workflow_dispatch'), 'seed-templates')
        for mode in modes:
            with self.subTest(mode=mode):
                self.assertNotEqual(group('workflow_dispatch', mode), 'seed-templates')
                self.assertNotEqual(group('workflow_dispatch', mode, 123), group('workflow_dispatch', mode, 124))
                self.assertEqual(group('push', mode), 'seed-templates')
        pause_job = workflow.split('  rollup-pause:\n')[1].split('\n  rollup-diagnostic:', 1)[0]
        self.assertRegex(pause_job, r'concurrency:\n      group: control-plane-deploy\n      queue: max\n      cancel-in-progress: false')

    def test_requested_fixed_hour_controls_diagnostic_completeness(self):
        for requested, error, expected in (
            ('', None, 'observed'),
            ('2026-10-03T04:00:00Z', None, 'observed'),
            ('2026-10-03T04:00:00Z', TimeoutError(), 'partial'),
            ('2026-99-03T04:00:00Z', None, 'partial'),
            ('invalid', None, 'partial'),
        ):
            with self.subTest(requested=requested, error=error), tempfile.TemporaryDirectory() as directory:
                result_path = Path(directory)/'result.json'
                real_path = Path
                def path(value):
                    return result_path if value == 'staging-rollup-diagnostic/result.json' else real_path(value)
                with patch.dict(os.environ, GCP_PROJECT=diagnostic.PROJECT, ROLLUP_FIXED_HOUR=requested), \
                     patch('sys.argv', ['diagnostic']), patch.object(diagnostic, 'Path', side_effect=path), \
                     patch.object(diagnostic, 'check_dispatch', return_value='a'*40), \
                     patch.object(diagnostic, 'service_baseline', return_value={'status': 'observed'}), \
                     patch.object(diagnostic, 'monitoring', return_value={'status': 'observed'}), \
                     patch.object(diagnostic, 'logging', return_value={'status': 'observed'}), \
                     patch.object(diagnostic, 'database', return_value={'status': 'observed'}), \
                     patch.object(diagnostic, 'sql', side_effect=error, return_value={'unequal_teams': 2}) as sql:
                    self.assertEqual(diagnostic.main(), 0)
                result = json.loads(result_path.read_text())
                self.assertEqual(result['status'], expected)
                if not requested:
                    self.assertNotIn('fixed_hour', result['capabilities'])
                    sql.assert_not_called()
                else:
                    self.assertEqual(result['capabilities']['fixed_hour'], 'observed' if expected == 'observed' else 'unknown')
                    if expected == 'observed':
                        self.assertEqual(result['fixed_hour']['unequal_teams'], 2)

    def test_wrong_database_project_never_connects(self):
        for value in ('postgresql://user:example@db.other.supabase.co/postgres',
                      'postgresql://user:example@db.rifhalqzxgskwajjgipj.supabase.co/postgres?host=other'):
            with self.subTest(value=value), patch.dict(os.environ, DATABASE_URL=value), patch.object(diagnostic, 'command') as command:
                with self.assertRaisesRegex(diagnostic.DiagnosticError, 'staging_database_identity_unverified'):
                    diagnostic.sql(diagnostic.Reader(time.monotonic()+30), 'SELECT 1')
                command.assert_not_called()

    def test_unarmed_baseline_does_not_deploy_during_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            baseline = Path(directory)/'baseline.json'
            baseline.write_text(json.dumps({'mutation_started': False}))
            with patch.object(pause, 'BASELINE', baseline), patch.object(pause, 'RESULT', Path(directory)/'result.json'), \
                 patch.dict(os.environ, GCP_PROJECT=pause.PROJECT), patch('sys.argv', ['pause', '--restore']), \
                 patch.object(pause, 'gate', return_value='a'*40), patch.object(pause, 'restore') as restore, \
                 patch.object(pause, 'service') as service:
                self.assertEqual(pause.main(), 0)
                restore.assert_not_called()
                service.assert_not_called()

    def test_ready_unrouted_revision_does_not_require_serving_pointer(self):
        service = {'metadata': {'generation': 2}, 'status': {'observedGeneration': 2,
                   'latestCreatedRevisionName': 'new', 'latestReadyRevisionName': 'old'}}
        revision = {'metadata': {'generation': 1}, 'status': {'observedGeneration': 1,
                    'imageDigest': pause.IMAGE, 'conditions': [{'type': 'Ready', 'status': 'True', 'reason': 'Retired'}]}}
        with patch.object(pause, 'service', return_value=service), patch.object(pause, 'same_configuration', return_value=True), \
             patch.object(pause, 'flag', return_value='true'), patch.object(diagnostic, 'cloud', return_value=revision):
            self.assertEqual(pause.wait_ready(pause.Reader(time.monotonic()+30), 'new', {}, 'true'), service)

    def test_inactive_and_unreconciled_are_not_retired(self):
        row = {'metadata': {'generation': 1}, 'status': {'observedGeneration': 1,
               'conditions': [{'type': 'Active', 'status': 'False', 'reason': 'Retired'}]}}
        self.assertTrue(pause.retired(row))
        changed = copy.deepcopy(row)
        changed['status']['observedGeneration'] = 0
        self.assertFalse(pause.retired(changed))
        row['status']['conditions'][0]['reason'] = 'Retiring'
        self.assertFalse(pause.retired(row))


if __name__ == '__main__':
    unittest.main()
