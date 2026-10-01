import datetime
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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
        self.assertEqual(self.run_action('--enforce'), 100)
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

    def test_agent_restart_failure_restores_previous_config(self):
        with patch.object(migration, 'control', side_effect=[False, False, True]):
            with self.assertRaises(ValueError):
                migration.set_legacy_config(self.target['retired'])
        self.assertEqual(migration.CONFIG.read_text(), self.baseline)


if __name__ == '__main__':
    unittest.main()
