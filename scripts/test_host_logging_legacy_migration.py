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
        self.inject_patch = patch.object(migration, 'inject_heartbeat', return_value='b' * 32)
        self.inject = self.inject_patch.start()
        self.addCleanup(self.inject_patch.stop)
        self.request_patch = patch.object(migration, 'receipt_request', return_value=('request', {}, 'log'))
        self.request = self.request_patch.start()
        self.addCleanup(self.request_patch.stop)
        self.received_patch = patch.object(migration, 'heartbeat_received', return_value=True)
        self.received = self.received_patch.start()
        self.addCleanup(self.received_patch.stop)
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
        health.assert_called_once_with(self.target)
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
            migration.assert_exporter_healthy(self.target)
        self.assertEqual(read.call_count, 3)
        self.inject.assert_called_once()
        self.received.assert_called_once()

    def test_retire_guard_rejects_queue_pressure_export_errors_and_restart(self):
        initial = {'sent': 12, 'failed': 0, 'rejected': 0, 'queued': 0, 'capacity': 100, 'inflight': 0}
        for changed in [dict(initial, failed=1), dict(initial, rejected=1), dict(initial, sent=0)]:
            with patch.object(migration, 'read_export_metrics', side_effect=[initial, changed]), patch.object(migration, 'collector_invocation', return_value='a' * 32), patch.object(migration.subprocess, 'run'), patch.object(migration.time, 'sleep'):
                with self.assertRaises(ValueError):
                    migration.assert_exporter_healthy(self.target)
        with patch.object(migration, 'read_export_metrics', return_value=dict(initial, queued=100)), patch.object(migration, 'collector_invocation', return_value='a' * 32), patch.object(migration.subprocess, 'run') as command:
            with self.assertRaises(ValueError):
                migration.assert_exporter_healthy(self.target)
            command.assert_not_called()
        with patch.object(migration, 'read_export_metrics', side_effect=[initial, dict(initial, sent=13)]), patch.object(migration, 'collector_invocation', side_effect=['a' * 32, 'b' * 32]), patch.object(migration.subprocess, 'run'), patch.object(migration.time, 'sleep'):
            with self.assertRaises(ValueError):
                migration.assert_exporter_healthy(self.target)

    def test_retire_guard_times_out_without_success(self):
        initial = {'sent': 12, 'failed': 0, 'rejected': 0, 'queued': 0, 'capacity': 100, 'inflight': 0}
        with patch.object(migration, 'read_export_metrics', return_value=initial), patch.object(migration, 'collector_invocation', return_value='a' * 32), patch.object(migration.subprocess, 'run'), patch.object(migration.time, 'monotonic', side_effect=[0, 31]):
            with self.assertRaises(ValueError):
                migration.assert_exporter_healthy(self.target)

    def test_old_queue_success_does_not_acknowledge_injected_heartbeat(self):
        initial = {'sent': 12, 'failed': 0, 'rejected': 0, 'queued': 1, 'capacity': 100, 'inflight': 0}
        delivered_old = dict(initial, sent=13, queued=0)
        self.received.return_value = False
        with patch.object(migration, 'read_export_metrics', side_effect=[initial, delivered_old]), patch.object(migration, 'collector_invocation', return_value='a' * 32), patch.object(migration.time, 'sleep'), patch.object(migration.time, 'monotonic', side_effect=[0, 1, 31]), patch.object(migration.subprocess, 'run'):
            with self.assertRaisesRegex(ValueError, 'acknowledge'):
                migration.assert_exporter_healthy(self.target)
        self.received.assert_called_once()

    def test_heartbeat_probe_rejects_old_journal_invocation(self):
        self.inject_patch.stop()
        old = {'_SYSTEMD_UNIT': 'superserve-host-logging-heartbeat.service', '_SYSTEMD_INVOCATION_ID': 'b' * 32, '__REALTIME_TIMESTAMP': '999999'}
        fresh = dict(old, __REALTIME_TIMESTAMP='1000001', _SYSTEMD_INVOCATION_ID='c' * 32)
        with patch.object(migration.time, 'time_ns', return_value=1000000000), patch.object(migration.time, 'sleep'), patch.object(migration.subprocess, 'run', side_effect=[MagicMock(), MagicMock(stdout=json.dumps(old)), MagicMock(stdout=json.dumps(fresh))]) as run:
            self.assertEqual(migration.inject_heartbeat(), 'c' * 32)
        self.assertEqual(run.call_args_list[0].args[0], ['systemctl', 'restart', 'superserve-host-logging-heartbeat.service'])

    def test_receipt_query_is_restricted_and_bound_to_host_incarnation(self):
        self.request_patch.stop()
        migration.IDENTITY.write_text(json.dumps({'instance_id': '123', 'incarnation_id': 'inc-1'}))
        target = {'heartbeat_receipt_view': 'projects/example-project/locations/global/buckets/_Default/views/example-heartbeats'}
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b'{"access_token":"synthetic-fixture-token"}'
        with patch.object(migration.urllib.request, 'build_opener') as opener:
            opener.return_value.open.return_value = response
            request, labels, name = migration.receipt_request(target, 'b' * 32)
        payload = json.loads(request.data)
        self.assertEqual(payload['resourceNames'], [target['heartbeat_receipt_view']])
        self.assertEqual(payload['pageSize'], 1)
        self.assertIn('labels.heartbeat_invocation_id="' + 'b' * 32 + '"', payload['filter'])
        self.assertIn('labels.incarnation="inc-1"', payload['filter'])
        self.assertIn('labels.provider_instance_id="123"', payload['filter'])
        self.assertEqual(name, 'projects/example-project/logs/superserve_host_logs')
        with self.assertRaises(ValueError):
            migration.receipt_request({'heartbeat_receipt_view': 'projects/example-project'}, 'b' * 32)

    def test_cloud_receipt_must_match_exact_invocation_and_identity(self):
        self.received_patch.stop()
        expected = {'heartbeat_invocation_id': 'b' * 32, 'provider_instance_id': '123', 'incarnation': 'inc-1'}
        response = MagicMock()
        with patch.object(migration.urllib.request, 'urlopen', return_value=response):
            for changed in ({'heartbeat_invocation_id': 'c' * 32}, {'provider_instance_id': '456'}, {'incarnation': 'inc-2'}):
                response.__enter__.return_value.read.return_value = json.dumps({'entries': [{'logName': 'log', 'labels': dict(expected, **changed)}]}).encode()
                self.assertFalse(migration.heartbeat_received('request', expected, 'log'))
            response.__enter__.return_value.read.return_value = json.dumps({'entries': [{'logName': 'log', 'labels': expected}]}).encode()
            self.assertTrue(migration.heartbeat_received('request', expected, 'log'))
            response.__enter__.return_value.read.return_value = b'X' * 65537
            with self.assertRaises(ValueError):
                migration.heartbeat_received('request', expected, 'log')

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
