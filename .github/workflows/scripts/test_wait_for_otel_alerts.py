import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name('wait-for-otel-alerts.py')
SPEC = importlib.util.spec_from_file_location('wait_for_otel_alerts', SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class AlertRolloutGateTests(unittest.TestCase):
    required = ['Apply production/us-east4', 'Apply production/us-west2']

    def ready(self, jobs, status='in_progress', runs=None):
        if runs is None:
            runs = [{'id': 123, 'head_sha': 'current', 'head_branch': 'main', 'status': status}]
        pages = [[{'workflow_runs': runs}], [{'workflow_runs': runs}],
                 [{'jobs': jobs}], [{'workflow_runs': runs}]]
        with patch.object(MODULE, 'api', side_effect=pages) as api:
            result = MODULE.alert_applies_ready('example/repository', 'current', self.required)
        self.assertIn('head_sha=current&event=push&branch=main', api.call_args_list[0].args[0])
        return result

    def jobs(self, conclusion='success', status='completed'):
        return [{'name': name, 'status': status, 'conclusion': conclusion} for name in self.required]

    def test_requires_both_cell_applies_but_not_unrelated_api_jobs(self):
        self.assertTrue(self.ready(self.jobs()))
        self.assertFalse(self.ready(self.jobs()[:1]))
        self.assertFalse(self.ready(self.jobs(None, 'in_progress')))

    def test_missing_run_or_different_revision_never_authorizes_rollout(self):
        self.assertFalse(self.ready([], runs=[]))
        self.assertFalse(self.ready(self.jobs(), runs=[
            {'id': 1, 'head_sha': 'old', 'head_branch': 'main', 'status': 'completed'},
            {'id': 2, 'head_sha': 'current', 'head_branch': 'feature', 'status': 'completed'},
        ]))

    def test_failed_cancelled_skipped_or_missing_apply_fails_closed(self):
        for conclusion in ('failure', 'cancelled', 'skipped', 'timed_out'):
            with self.subTest(conclusion=conclusion), self.assertRaisesRegex(RuntimeError, 'refusing'):
                self.ready(self.jobs(conclusion))
        with self.assertRaisesRegex(RuntimeError, 'without all required'):
            self.ready(self.jobs()[:1], status='completed')

    def test_latest_run_is_authoritative(self):
        runs = [{'id': i, 'head_sha': 'current', 'head_branch': 'main', 'status': 'in_progress'} for i in (1, 2)]
        with patch.object(MODULE, 'api', side_effect=[
            [{'workflow_runs': runs}], [{'workflow_runs': runs[::-1]}], [{'jobs': []}]
        ]) as api:
            self.assertFalse(MODULE.alert_applies_ready('example/repository', 'current', self.required))
        self.assertIn('/runs/2/jobs?', api.call_args_list[2].args[0])

    def test_older_successful_apply_cannot_authorize_after_newer_revision(self):
        old = {'id': 1, 'head_sha': 'current', 'head_branch': 'main', 'status': 'completed'}
        newer = dict(old, id=2, head_sha='newer')
        for status in ('queued', 'in_progress', 'completed'):
            with self.subTest(status=status), patch.object(MODULE, 'api', side_effect=[
                [{'workflow_runs': [old]}], [{'workflow_runs': [dict(newer, status=status)]}]
            ]) as api, self.assertRaisesRegex(RuntimeError, 'stale rollout'):
                MODULE.alert_applies_ready('example/repository', 'current', self.required)
            self.assertEqual(api.call_count, 2)  # Old successful jobs cannot bypass freshness.

    def test_new_revision_during_success_check_fails_closed(self):
        old = {'id': 1, 'head_sha': 'current', 'head_branch': 'main', 'status': 'completed'}
        newer = dict(old, id=2, head_sha='newer')
        with patch.object(MODULE, 'api', side_effect=[
            [{'workflow_runs': [old]}], [{'workflow_runs': [old]}],
            [{'jobs': self.jobs()}], [{'workflow_runs': [newer]}],
        ]), self.assertRaisesRegex(RuntimeError, 'changed during'):
            MODULE.alert_applies_ready('example/repository', 'current', self.required)

    def test_latest_lookup_does_not_scan_history_or_filter_by_sha(self):
        with patch.object(MODULE, 'api', return_value=[{'workflow_runs': []}]) as api:
            self.assertIsNone(MODULE.latest_alert_run('example/repository'))
        api.assert_called_once_with(
            'repos/example/repository/actions/workflows/terraform-cd.yml/runs?event=push&branch=main&per_page=1',
            paginate=False,
        )

    def test_polling_honors_enabled_cells_and_times_out_closed(self):
        env = {'GITHUB_REPOSITORY': 'example/repository', 'GITHUB_SHA': 'current', 'OTEL_USE4_ENABLED': 'enabled'}
        with patch.dict(os.environ, env, clear=True), patch.object(MODULE, 'time') as timer, \
             patch.object(MODULE, 'alert_applies_ready', side_effect=[False, True]) as ready, patch('builtins.print'):
            MODULE.main()
            ready.assert_called_with('example/repository', 'current', self.required[:1])
            timer.sleep.assert_called_once_with(20)
        with patch.dict(os.environ, env, clear=True), patch.object(MODULE, 'time'), \
             patch.object(MODULE, 'alert_applies_ready', return_value=False), patch('builtins.print'), \
             self.assertRaisesRegex(RuntimeError, 'Timed out'):
            MODULE.main()

    def test_gate_wiring_and_terraform_push_paths_cover_collector_changes(self):
        workflow = (SCRIPT.parents[1] / 'deploy-otel-collector.yml').read_text()
        production = workflow.split('  deploy-production:', 1)[1]
        self.assertIn('actions: read', production)
        self.assertIn('needs: [deploy-staging]', production)
        self.assertIn('group: otel-collector-production', production)
        self.assertIn('cancel-in-progress: false', production)
        for cell in ('use4', 'usw2'):
            step = production.split(f'- name: Deploy OTEL Collector to {cell} cell VMD instances', 1)[1].split('- name:', 1)[0]
            self.assertIn('python3 .github/workflows/scripts/wait-for-otel-alerts.py\n          python3 .github/workflows/scripts/deploy-otel-collector.py', step)
        self.assertLess(production.index('python3 .github/workflows/scripts/wait-for-otel-alerts.py'),
                        production.index('python3 .github/workflows/scripts/deploy-otel-collector.py'))
        gate = production.split('- name: Wait for same-revision production alert applies', 1)[1].split('- name:', 1)[0]
        self.assertNotIn('if:', gate)  # Manual production dispatches must pass the same gate.
        terraform = (SCRIPT.parents[1] / 'terraform-cd.yml').read_text()
        self.assertNotIn('group: otel-collector-production', terraform)
        collector_paths = workflow.split('    paths:', 1)[1].split('jobs:', 1)[0]
        for line in collector_paths.splitlines():
            if line.strip().startswith('- '):
                self.assertIn(line.strip(), terraform.split('jobs:', 1)[0])


if __name__ == '__main__':
    unittest.main()
