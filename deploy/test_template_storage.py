import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('template_storage', Path(__file__).with_name('template-storage.py'))
STORAGE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(STORAGE)


class TemplateStorageTest(unittest.TestCase):
    def test_generated_units_persist_ordering_and_gate_both_consumers(self):
        for has_data_service in (False, True):
            units = STORAGE.unit_files(has_data_service)
            prepare = units[STORAGE.PREPARE]
            self.assertIn('RequiresMountsFor=/mnt/sandbox-data', prepare)
            self.assertEqual('Requires=sandbox-data.service' in prepare, has_data_service)
            for tree, name in zip(STORAGE.TREES, STORAGE.MOUNTS):
                mount = units[name]
                self.assertIn('After=' + STORAGE.PREPARE, mount)
                self.assertIn('Requires=' + STORAGE.PREPARE, mount)
                self.assertIn('WantedBy=multi-user.target', mount)
                self.assertIn('DefaultDependencies=no', mount)
                self.assertIn('Before=umount.target', mount)
                self.assertIn(f'What=/mnt/sandbox-data/templates/{tree}', mount)
                self.assertIn(f'Where=/var/lib/sandbox/{tree}/templates', mount)
                self.assertIn('Options=bind', mount)
            for kind in ('service', 'socket'):
                dropin = units[f'superserve-vmd.{kind}.d/40-template-storage.conf']
                self.assertIn('BindsTo=' + ' '.join(STORAGE.MOUNTS), dropin)
                self.assertIn('After=' + ' '.join(STORAGE.MOUNTS), dropin)
                self.assertIn('ExecStartPre=' + STORAGE.CHECKER + ' check', dropin)
            self.assertIn('DefaultDependencies=no', units['superserve-vmd.socket.d/40-template-storage.conf'])

    def fixture(self, root):
        root = root.resolve()
        (root/'data').mkdir(parents=True, exist_ok=True)
        patcher = patch.object(STORAGE, 'DATA', root/'data')
        patcher.start()
        self.addCleanup(patcher.stop)
        return {tree: (root/'data/templates'/tree, root/'runtime'/tree/'templates') for tree in STORAGE.TREES}

    def test_prepare_idempotent_and_never_moves_general_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mapping = self.fixture(root)
            general = root/'runtime/rundir/active-guest'
            general.parent.mkdir(parents=True)
            general.write_text('untouched')
            with patch.object(STORAGE, 'check_data'), patch.object(STORAGE, 'paths', side_effect=mapping.__getitem__), patch.object(STORAGE, 'mounted', return_value=False):
                STORAGE.prepare()
                (mapping['rundir'][0]/'template').write_text('preserved')
                STORAGE.prepare()
            self.assertEqual(general.read_text(), 'untouched')
            self.assertEqual((mapping['rundir'][0]/'template').read_text(), 'preserved')
            self.assertEqual(list(mapping['rundir'][1].iterdir()), [])

    def test_refuses_to_hide_root_templates(self):
        with tempfile.TemporaryDirectory() as tmp:
            mapping = self.fixture(Path(tmp))
            target = mapping['snapshots'][1]
            target.mkdir(parents=True)
            (target/'existing').write_text('never hide')
            with patch.object(STORAGE, 'check_data'), patch.object(STORAGE, 'paths', side_effect=mapping.__getitem__), patch.object(STORAGE, 'mounted', return_value=False):
                with self.assertRaisesRegex(RuntimeError, 'migrate explicitly'):
                    STORAGE.prepare()
            self.assertFalse(mapping['rundir'][0].exists())
            self.assertEqual((target/'existing').read_text(), 'never hide')

    def test_existing_manual_mounts_are_adopted_and_wrong_mounts_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            mapping = self.fixture(Path(tmp))
            for source, target in mapping.values():
                source.mkdir(parents=True)
                target.mkdir(parents=True)
            with patch.object(STORAGE, 'check_data'), patch.object(STORAGE, 'paths', side_effect=mapping.__getitem__), patch.object(STORAGE, 'mounted', return_value=True), patch.object(STORAGE.os.path, 'samefile', return_value=True):
                STORAGE.prepare()
                STORAGE.check()
            with patch.object(STORAGE, 'check_data'), patch.object(STORAGE, 'paths', side_effect=mapping.__getitem__), patch.object(STORAGE, 'mounted', return_value=True):
                with self.assertRaisesRegex(RuntimeError, 'unexpected source'):
                    STORAGE.prepare()
                with self.assertRaisesRegex(RuntimeError, 'refusing root-disk fallback'):
                    STORAGE.check()

    def test_data_mount_absent_blocks_before_writes(self):
        with patch.object(STORAGE, 'mounted', return_value=False), patch.object(Path, 'mkdir') as mkdir:
            with self.assertRaisesRegex(RuntimeError, 'mounted as XFS'):
                STORAGE.prepare()
            mkdir.assert_not_called()

    def test_install_refuses_running_vmd_before_any_storage_changes(self):
        with patch.object(STORAGE, 'run', return_value='active'), patch.object(STORAGE, 'prepare') as prepare:
            with self.assertRaisesRegex(RuntimeError, 'stop/drain'):
                STORAGE.install()
            prepare.assert_not_called()

    def test_install_is_repeatable_and_enables_only_mounts(self):
        from subprocess import CompletedProcess
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            calls = []
            def run(*args):
                calls.append(args)
                if 'ActiveState' in args:
                    return 'inactive'
                if 'LoadState' in args:
                    return 'loaded'
                return ''
            with patch.object(STORAGE, 'CHECKER', str(root/'checker')), patch.object(STORAGE, 'SYSTEMD_DIR', root/'units'), patch.object(STORAGE, 'run', side_effect=run), patch.object(STORAGE.subprocess, 'run', return_value=CompletedProcess([], 1)), patch.object(STORAGE, 'prepare'), patch.object(STORAGE, 'check') as check:
                STORAGE.install()
                before = {str(p): p.read_bytes() for p in (root/'units').rglob('*') if p.is_file()}
                STORAGE.install()
                after = {str(p): p.read_bytes() for p in (root/'units').rglob('*') if p.is_file()}
                self.assertEqual(before, after)
                self.assertEqual(check.call_count, 2)
            self.assertIn(('systemctl', 'enable', *STORAGE.MOUNTS), calls)
            self.assertIn(('systemctl', 'start', *STORAGE.MOUNTS), calls)
            self.assertFalse(any('stop' in call or 'umount' in call for call in calls))
            self.assertEqual((root/'checker').stat().st_mode & 0o777, 0o755)

    def test_root_filesystem_cannot_masquerade_as_data_mount(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(STORAGE, 'DATA', Path(tmp).resolve()), patch.object(STORAGE, 'mounted', return_value=True), patch.object(STORAGE, 'run', return_value='xfs'):
                with self.assertRaisesRegex(RuntimeError, 'root filesystem'):
                    STORAGE.check_data()

    def test_deploy_and_bootstrap_wire_installer_without_global_serving_unit_changes(self):
        root = Path(__file__).parents[1]
        deploy = (root/'.github/workflows/scripts/deploy-vmd.py').read_text()
        bootstrap = (root/'deploy/bootstrap-host2.py').read_text()
        self.assertIn('if [ "$SECRETSPROXY_FRESH" = 1 ]; then\n                sudo python3 {extract_dir}/deploy/template-storage.py install', deploy)
        self.assertIn('sudo python3 {upload_dir}/template-storage.py install', bootstrap)
        self.assertNotIn('template-storage', (root/'deploy/superserve-vmd.service').read_text())
