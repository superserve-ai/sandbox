import datetime
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock

spec = importlib.util.spec_from_file_location('migration', Path(__file__).with_name('host_logging_legacy_migration.py'))
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)


class LegacyMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        for name, path in [('STATE', root / 'state'), ('SYSTEMD', root / 'systemd'), ('CONFIG', root / 'config.yaml'), ('IDENTITY', root / 'identity.json')]:
            patcher = patch.object(migration, name, path)
            patcher.start()
            self.addCleanup(patcher.stop)
        migration.STATE.mkdir()
        migration.IDENTITY.write_text(json.dumps({'instance_id': '123'}))
        self.baseline = json.dumps({'metrics': {'service': {'pipelines': {'custom': {'receivers': ['hostmetrics']}}}}, 'logging': {'service': {'pipelines': {'extra': {'receivers': ['custom']}}}}})
        retired = json.loads(self.baseline)
        retired['logging']['service']['pipelines']['default_pipeline'] = {'receivers': []}
        retired['logging']['service']['pipelines']['extra'] = {'receivers': []}
        self.target = {'phase': 'overlap', 'baseline': self.baseline, 'retired': json.dumps(retired), 'deadline': (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ'), 'instance_ids': ['123'], 'verified_instance_ids': ['123'], 'drained_instance_ids': ['123']}
        migration.CONFIG.write_text(self.baseline)
        self.running = {migration.OPS, migration.LOGS, migration.HEARTBEAT}
        self.calls = []
        def control(*args, check=True):
            self.calls.append(args)
            if args[0] == 'is-active':
                return args[-1] in self.running
            if args[0] in ('enable', 'restart'):
                self.running.add(args[-1])
            elif args[0] == 'disable':
                self.running.difference_update(args[2:])
            return True
        patcher = patch.object(migration, 'control', side_effect=control)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_action(self, action):
        (migration.STATE / 'legacy-migration.json').write_text(json.dumps(self.target))
        with patch('sys.argv', ['migration', action]):
            return migration.main()

    def test_preserve_stops_only_new_writer_without_audited_config(self):
        self.target.update(phase='preserve', baseline=None)
        self.assertEqual(self.run_action('--check'), 101)
        self.assertEqual(self.run_action('--enforce'), 100)
        self.assertEqual(self.running, {migration.OPS})
        self.assertEqual(migration.CONFIG.read_text(), self.baseline)

    def test_overlap_has_deadline_and_expiry_blocks_restart(self):
        self.assertEqual(self.run_action('--enforce'), 100)
        self.assertIn(migration.EXPIRY, self.running)
        self.assertTrue((migration.SYSTEMD / (migration.LOGS + '.d') / '40-legacy-migration.conf').exists())
        before = list(self.calls)
        self.assertEqual(self.run_action('--enforce'), 100)
        self.assertEqual([c for c in self.calls[len(before):] if c[0] != 'is-active'], [])
        self.target['deadline'] = '2000-01-01T00:00:00Z'
        self.assertEqual(self.run_action('--expire'), 0)
        self.assertNotIn(migration.LOGS, self.running)
        self.assertIn(migration.OPS, self.running)
        self.assertEqual(self.run_action('--guard'), 1)

    def test_retire_preserves_metrics_and_rollback_restores_exact_baseline(self):
        self.run_action('--enforce')
        self.target['phase'] = 'retire'
        with patch.object(migration, 'assert_exporter_healthy') as health:
            self.assertEqual(self.run_action('--enforce'), 100)
        health.assert_called_once_with()
        retired = json.loads(migration.CONFIG.read_text())
        self.assertEqual(retired['metrics'], json.loads(self.baseline)['metrics'])
        self.assertEqual(retired['logging']['service']['pipelines']['extra'], {'receivers': []})
        self.assertEqual(retired['logging']['service']['pipelines']['default_pipeline'], {'receivers': []})
        self.target['phase'] = 'preserve'
        with self.assertRaises(ValueError):
            self.run_action('--preflight')
        self.target['phase'] = 'rollback'
        self.assertEqual(self.run_action('--enforce'), 100)
        self.assertEqual(migration.CONFIG.read_text(), self.baseline)
        self.assertNotIn(migration.LOGS, self.running)
        self.assertIn(migration.OPS, self.running)

    def test_unknown_baseline_instance_or_drain_fails_before_changes(self):
        for change in [{'baseline': 'unknown'}, {'instance_ids': ['456']}, {'phase': 'retire', 'drained_instance_ids': []}, {'deadline': '2099-01-01T00:00:00Z'}]:
            original = self.target.copy()
            self.target.update(change)
            with self.assertRaises(ValueError):
                self.run_action('--enforce')
            self.assertEqual(migration.CONFIG.read_text(), self.baseline)
            self.assertFalse(any(c[0] in ('restart', 'enable', 'disable') for c in self.calls))
            self.target = original

    def test_absent_config_requires_explicit_current_instance_initialization(self):
        migration.CONFIG.unlink()
        with self.assertRaises(ValueError):
            self.run_action('--preflight')
        self.target['initialize_instance_ids'] = ['other-instance']
        with self.assertRaises(ValueError):
            self.run_action('--preflight')
        self.target['initialize_instance_ids'] = ['123']
        self.assertEqual(self.run_action('--preflight'), 0)
        self.assertFalse(migration.CONFIG.exists())
        self.assertEqual(self.run_action('--enforce'), 100)
        self.assertEqual(migration.CONFIG.read_text(), self.baseline)
        self.assertTrue((migration.STATE / 'legacy-baseline.json').exists())

    def test_initialization_never_overwrites_existing_unknown_config(self):
        self.target['initialize_instance_ids'] = ['123']
        migration.CONFIG.write_text('unknown operator configuration')
        with self.assertRaises(ValueError):
            self.run_action('--enforce')
        self.assertEqual(migration.CONFIG.read_text(), 'unknown operator configuration')

    def test_fresh_instance_cannot_inherit_retirement(self):
        migration.CONFIG.unlink()
        self.target.update(phase='retire', initialize_instance_ids=['123'])
        with self.assertRaises(ValueError):
            self.run_action('--enforce')
        self.assertFalse(migration.CONFIG.exists())

    def test_rollback_starts_inactive_legacy_before_stopping_otel(self):
        for config in (self.baseline, self.target['retired']):
            with self.subTest(config=config):
                self.running = {migration.LOGS, migration.HEARTBEAT}
                migration.CONFIG.write_text(config)
                self.calls.clear()
                self.target['phase'] = 'rollback'
                self.assertEqual(self.run_action('--check'), 101)
                self.assertEqual(self.run_action('--guard'), 0)
                self.assertEqual(self.run_action('--enforce'), 100)
                self.assertIn(migration.OPS, self.running)
                self.assertNotIn(migration.LOGS, self.running)
                self.assertEqual(migration.CONFIG.read_text(), self.baseline)
                start = self.calls.index(('restart', migration.OPS))
                stop = self.calls.index(('disable', '--now', migration.LOGS, migration.HEARTBEAT))
                self.assertLess(start, stop)
                self.assertEqual(self.run_action('--guard'), 1)

    def test_rollback_start_failure_leaves_otel_and_its_restart_path_available(self):
        real_control = migration.control
        def fail_restart(*args, check=True):
            if args == ('restart', migration.OPS):
                return True  # Starting may return success before the unit fails.
            return real_control(*args, check=check)
        for config in (self.baseline, self.target['retired']):
            with self.subTest(config=config):
                self.running = {migration.LOGS, migration.HEARTBEAT}
                migration.CONFIG.write_text(config)
                self.calls.clear()
                self.target['phase'] = 'rollback'
                with patch.object(migration, 'control', side_effect=fail_restart):
                    with self.assertRaises(ValueError):
                        self.run_action('--enforce')
                    self.assertEqual(self.run_action('--guard'), 0)
                self.assertIn(migration.LOGS, self.running)
                self.assertIn(migration.HEARTBEAT, self.running)
                self.assertFalse(any(call[0] == 'disable' for call in self.calls))

    def test_rollback_is_not_converged_with_both_writers_stopped(self):
        self.target['phase'] = 'rollback'
        self.running.clear()
        self.assertEqual(self.run_action('--check'), 101)
        self.assertEqual(self.run_action('--enforce'), 100)
        self.assertEqual(self.running, {migration.OPS})

    def test_unhealthy_exporter_keeps_legacy_configuration(self):
        self.run_action('--enforce')
        self.target['phase'] = 'retire'
        with patch.object(migration, 'assert_exporter_healthy', side_effect=ValueError('outage')):
            with self.assertRaises(ValueError):
                self.run_action('--enforce')
        self.assertEqual(migration.CONFIG.read_text(), self.baseline)
        self.assertFalse((migration.STATE / 'legacy-retired.json').exists())
        self.assertIn(migration.OPS, self.running)

    def test_retire_guard_requires_new_success_and_empty_queue(self):
        initial = {'sent': 12, 'failed': 0, 'rejected': 0, 'queued': 1, 'capacity': 100, 'inflight': 0}
        pending = dict(initial, sent=13, queued=0, inflight=1)
        success = dict(pending, inflight=0)
        with patch.object(migration, 'read_export_metrics', side_effect=[initial, pending, success]) as read, patch.object(migration, 'collector_invocation', return_value='a' * 32), patch.object(migration.subprocess, 'run') as command, patch.object(migration.time, 'sleep'):
            migration.assert_exporter_healthy()
        self.assertEqual(read.call_count, 3)
        command.assert_called_once()
        self.assertIn('superserve-host-logging-heartbeat.service', command.call_args.args[0])

    def test_retire_guard_rejects_queue_pressure_export_errors_and_restart(self):
        initial = {'sent': 12, 'failed': 0, 'rejected': 0, 'queued': 0, 'capacity': 100, 'inflight': 0}
        for changed in [dict(initial, failed=1), dict(initial, rejected=1), dict(initial, sent=0)]:
            with patch.object(migration, 'read_export_metrics', side_effect=[initial, changed]), patch.object(migration, 'collector_invocation', return_value='a' * 32), patch.object(migration.subprocess, 'run'), patch.object(migration.time, 'sleep'):
                with self.assertRaises(ValueError):
                    migration.assert_exporter_healthy()
        with patch.object(migration, 'read_export_metrics', return_value=dict(initial, queued=100)), patch.object(migration, 'collector_invocation', return_value='a' * 32), patch.object(migration.subprocess, 'run') as command:
            with self.assertRaises(ValueError):
                migration.assert_exporter_healthy()
            command.assert_not_called()
        with patch.object(migration, 'read_export_metrics', side_effect=[initial, dict(initial, sent=13)]), patch.object(migration, 'collector_invocation', side_effect=['a' * 32, 'b' * 32]), patch.object(migration.subprocess, 'run'), patch.object(migration.time, 'sleep'):
            with self.assertRaises(ValueError):
                migration.assert_exporter_healthy()

    def test_retire_guard_times_out_without_success(self):
        initial = {'sent': 12, 'failed': 0, 'rejected': 0, 'queued': 0, 'capacity': 100, 'inflight': 0}
        with patch.object(migration, 'read_export_metrics', return_value=initial), patch.object(migration, 'collector_invocation', return_value='a' * 32), patch.object(migration.subprocess, 'run'), patch.object(migration.time, 'monotonic', side_effect=[0, 21]):
            with self.assertRaises(ValueError):
                migration.assert_exporter_healthy()

    def test_metric_reader_selects_only_expected_exporter_and_fails_closed(self):
        raw = b'\n'.join([
            b'otelcol_exporter_sent_log_records_total{exporter="other"} 999',
            b'otelcol_exporter_sent_log_records_total{exporter="otlp_http/cloud",service_name="otelcol"} 4',
            b'otelcol_exporter_queue_size{exporter="otlp_http/cloud"} 0',
            b'otelcol_exporter_queue_capacity{exporter="otlp_http/cloud"} 100',
            b'otelcol_exporter_in_flight_requests{exporter="otlp_http/cloud"} 0',
        ])
        response = MagicMock()
        response.__enter__.return_value.read.return_value = raw
        with patch.object(migration.urllib.request, 'urlopen', return_value=response):
            self.assertEqual(migration.read_export_metrics(), {'sent': 4, 'failed': 0, 'rejected': 0, 'queued': 0, 'capacity': 100, 'inflight': 0})
            response.__enter__.return_value.read.return_value = b'no exporter metrics'
            with self.assertRaises(ValueError):
                migration.read_export_metrics()

    def test_agent_restart_failure_restores_previous_config(self):
        with patch.object(migration, 'control', side_effect=[False, False, True]):
            with self.assertRaises(ValueError):
                migration.set_legacy_config(self.target['retired'])
        self.assertEqual(migration.CONFIG.read_text(), self.baseline)


if __name__ == '__main__':
    unittest.main()
