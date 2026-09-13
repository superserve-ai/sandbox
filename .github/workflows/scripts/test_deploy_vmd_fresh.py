"""Execute fresh-host initialization and fail-closed daemon ordering in a fake host."""
import ast
import importlib.util
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import textwrap
import unittest

SOURCE = Path(__file__).with_name('deploy-vmd.py').read_text()
spec = importlib.util.spec_from_file_location('deploy_vmd_fresh', Path(__file__).with_name('deploy-vmd.py'))
deploy_vmd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy_vmd)


def block(start, end):
    return textwrap.dedent(SOURCE[SOURCE.index(start):SOURCE.index(end, SOURCE.index(start))])


BOOTSTRAP = block('# Fresh-host env bootstrap:', '# End fresh-host env bootstrap.')
HOST_ID = block("if ! sudo grep -q '^HOST_ID='", '# Upsert SECRETSPROXY_SOCKET')
CONTROL = block('if [ -n {q_cpu} ]; then', '# Upsert the guest DNS redirect port')
TOKENS = block('if [ -n {q_token} ]; then', '# Fresh-host runtime preflight.\n')
READY = block('# Fresh-host runtime preflight.\n', '# End fresh-host runtime preflight.')


class FreshHostTest(unittest.TestCase):
    def exercise(self, missing=('vmd', 'secretsproxy'), fail_daemon=False, missing_input=False, assets=True, ca_missing=(), custom_paths=False, configure_kernel=True, missing_artifact=None, configured=False, host_id="existing-host", region="us-central1", existing_region=None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            envdir = root / 'etc/sandbox'
            envdir.mkdir(parents=True)
            for name in ('vmd', 'secretsproxy'):
                if name not in missing:
                    (envdir / (name + '.env')).write_text('HOST_ID=' + host_id + '\nCUSTOM=preserve\n')
            if configured:
                for name in ('vmd', 'secretsproxy'):
                    with (envdir / (name + '.env')).open('a') as env:
                        env.write('CONTROL_PLANE_URL=https://old.example.test\nDATABASE_URL=postgres://old.example.test/db\nINTERNAL_API_TOKEN=old-token\nDAEMON_AUTH_TOKEN=old-token\n')
            if existing_region is not None:
                with (envdir / 'vmd.env').open('a') as env:
                    env.write('HOST_REGION=' + existing_region + '\nSANDBOX_ID_REGION=legacy-fallback\n')
            ca_dir = root / 'var/lib/secretsproxy'
            ca_dir.mkdir(parents=True)
            for name in ('ca.crt', 'ca.key'):
                if name not in ca_missing:
                    (ca_dir / name).write_text('existing-cell-' + name)
            kernel = '/var/lib/sandbox/kernel/approved-kernel'
            base = '/var/lib/sandbox/rootfs/base.ext4'
            if custom_paths:
                kernel, base = '/var/lib/custom/kernel', '/var/lib/custom/rootfs'
            with (envdir / 'vmd.env').open('a') as env:
                if configure_kernel:
                    env.write('KERNEL_PATH=' + str(root) + kernel + '\n')
                if custom_paths:
                    env.write('BASE_ROOTFS_PATH=' + str(root) + base + '\n')
            if assets:
                for name in (kernel, base):
                    if name == (kernel if missing_artifact == 'kernel' else base if missing_artifact == 'rootfs' else None):
                        continue
                    asset = root / name.lstrip('/')
                    asset.parent.mkdir(parents=True, exist_ok=True)
                    asset.write_text('approved artifact')
            supplied = {}
            values = {'host_capacity': deploy_vmd.capacity_script('110000', '32'), 'service': 'superserve-vmd.service', 'q_host_id_line': shlex.quote('HOST_ID=example-host'), 'q_host_region_line': shlex.quote('HOST_REGION=' + deploy_vmd.deployment_host_region(region, region + '-a'))}
            for key, name, value in [('cpu', 'CONTROL_PLANE_URL', 'https://example.test'),
                                     ('token', 'INTERNAL_API_TOKEN', 'example-token'),
                                     ('db', 'DATABASE_URL', 'postgres://example.test/db')]:
                supplied[key] = '' if missing_input in (name, 'all') or (missing_input is True and key == 'token') else value
                values['q_' + key] = shlex.quote(supplied[key])
                values['q_' + key + '_line'] = shlex.quote(name + '=' + value)
            values['q_iat_line'] = shlex.quote('INTERNAL_API_TOKEN=example-token')
            values['q_dat_line'] = shlex.quote('DAEMON_AUTH_TOKEN=example-token')
            script = '\n'.join((BOOTSTRAP, HOST_ID, CONTROL, TOKENS, READY))
            script = ast.literal_eval('"""' + script + '"""').format(**values)
            script = deploy_vmd.runtime_input_preflight(supplied['cpu'], supplied['db'], supplied['token']) + deploy_vmd.legacy_vmd_enrollment() + script
            script = script.replace('/etc/systemd', str(root / 'etc/systemd')).replace('/etc/sandbox', str(envdir)).replace('/var/lib/', str(root / 'var/lib') + '/')
            prelude = '''set -eu
sudo() { if [ "$1" = chown ]; then return; fi; "$@"; }
seq() { echo 1; }
sleep() { :; }
pgrep() { return 1; }
ss() { :; }
systemctl() {
    if [ "$1" = list-units ]; then return; fi
    case "$*" in *agentbox-vmd.service*) echo not-found; return;; esac
    if [ "$1" = restart ]; then
        echo restart-secretsproxy >> "$CALLS"
        if [ "$FAIL_DAEMON" = 1 ]; then return 1; fi
        mkdir -p "$CA_DIR"
        test -e "$CA_DIR/ca.crt" || echo generated-by-service > "$CA_DIR/ca.crt"
        test -e "$CA_DIR/ca.key" || echo generated-by-service > "$CA_DIR/ca.key"
    elif [ "$1" = show ]; then echo current-invocation; fi
}
curl() { test -s "$CA_DIR/ca.crt" && test -s "$CA_DIR/ca.key"; }
journalctl() { :; }
'''
            # Ownership is exercised by Linux CI (root); avoid changing ownership in local tests.
            script = script.replace('-o root -g root ', '')
            before = {str(p.relative_to(root)): (p.read_bytes(), p.stat().st_mode) for p in root.rglob('*') if p.is_file()}
            result = subprocess.run(['bash', '-c', prelude + script + '\necho vmd-may-start\n'],
                text=True, capture_output=True, env=dict(os.environ, CALLS=str(root/'calls'),
                CA_DIR=str(root/'var/lib/secretsproxy'), FAIL_DAEMON=str(int(fail_daemon))))
            if missing_input and not configured:
                after = {str(p.relative_to(root)): (p.read_bytes(), p.stat().st_mode) for p in root.rglob('*') if p.is_file()}
                self.assertEqual(before, after, 'missing input must not mutate the host')
            for name in ('ca.crt', 'ca.key'):
                if name not in ca_missing:
                    self.assertEqual((ca_dir / name).read_text(), 'existing-cell-' + name)
            if configured:
                self.assertFalse((root / 'calls').exists(), 'configured hosts retain normal restart ordering')
            if ca_missing:
                self.assertFalse((root / 'calls').exists(), 'must fail before secretsproxy starts')
            if not assets:
                guard = root / 'etc/systemd/system/superserve-vmd.service.d/05-fresh-runtime.conf'
                self.assertIn('\nConditionPathExists=!', guard.read_text())
                self.assertTrue((envdir / '.runtime-bootstrap-pending').exists())
            return result, {p.name: p.read_text() for p in envdir.glob('*.env')}, {
                p.name: p.stat().st_mode & 0o777 for p in envdir.glob('*.env')}

    def test_missing_env_files_converge_without_replacing_existing_content(self):
        for missing in [('vmd',), ('secretsproxy',), ('vmd', 'secretsproxy')]:
            with self.subTest(missing=missing):
                result, envs, modes = self.exercise(missing)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('HOST_ID=' + ('example-host' if 'vmd' in missing else 'existing-host'), envs['vmd.env'])
                for name in ('vmd', 'secretsproxy'):
                    if name not in missing:
                        self.assertIn('CUSTOM=preserve', envs[name+'.env'])
                    self.assertEqual(modes[name+'.env'], 0o644 if name == 'vmd' else 0o600)
                self.assertIn('DAEMON_AUTH_TOKEN=example-token', envs['secretsproxy.env'])
                self.assertIn('DATABASE_URL=postgres://example.test/db', envs['secretsproxy.env'])
                self.assertIn('vmd-may-start', result.stdout)

    def test_missing_settings_or_daemon_failure_block_vmd(self):
        for options, message in [({'missing_input': True}, 'requires INTERNAL_API_TOKEN'),
                                 ({'fail_daemon': True}, 'secretsproxy provisioning/readiness failed'),
                                 ({'assets': False}, 'provisioned kernel/base-rootfs')]:
            with self.subTest(options=options):
                result, _, _ = self.exercise(**options)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertNotIn('vmd-may-start', result.stdout)

    def test_named_hosts_get_deployment_region_without_manual_setting(self):
        for region in ('us-central1', 'us-east4', 'us-west2'):
            for missing in (('vmd', 'secretsproxy'), ()):
                result, envs, _ = self.exercise(missing=missing, region=region)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('HOST_REGION=' + region + '\n', envs['vmd.env'])

    def test_named_host_explicit_region_is_preserved_and_empty_region_is_filled(self):
        for value in ('explicit-region', 'us-west2', '', '   ', '\"\"', "''"):
            result, envs, _ = self.exercise(missing=(), configured=True, existing_region=value)
            self.assertEqual(result.returncode, 0, result.stderr)
            expected = value if value in ('explicit-region', 'us-west2') else 'us-central1'
            self.assertIn('HOST_REGION=' + expected + '\n', envs['vmd.env'])
            self.assertEqual(envs['vmd.env'].count('HOST_REGION='), 1)
            self.assertIn('HOST_ID=existing-host\n', envs['vmd.env'])

    def test_legacy_default_identity_does_not_gain_region(self):
        result, envs, _ = self.exercise(missing=(), configured=True, host_id='default')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('HOST_ID=default\n', envs['vmd.env'])
        self.assertNotIn('HOST_REGION=', envs['vmd.env'])
        result, envs, _ = self.exercise(missing=(), configured=True, host_id='default', existing_region='legacy-region')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('HOST_REGION=legacy-region\n', envs['vmd.env'])
        self.assertIn('SANDBOX_ID_REGION=legacy-fallback\n', envs['vmd.env'])

    def test_region_fallback_and_mismatch_validation(self):
        self.assertEqual(deploy_vmd.deployment_host_region('', 'projects/example/zones/us-west2-a'), 'us-west2')
        for region, zone in [('us-central1', 'us-west2-a'), ('', 'invalid')]:
            with self.assertRaises(ValueError):
                deploy_vmd.deployment_host_region(region, zone)

    def test_each_missing_input_fails_without_host_mutation(self):
        for name in ('CONTROL_PLANE_URL', 'DATABASE_URL', 'INTERNAL_API_TOKEN'):
            with self.subTest(name=name):
                result, _, _ = self.exercise(missing_input=name)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('requires ' + name, result.stderr)
                self.assertNotIn('vmd-may-start', result.stdout)

    def test_configured_hosts_preserve_omitted_inputs_and_reconcile_supplied_ones(self):
        for omitted in ('all', False):
            result, envs, _ = self.exercise(missing=(), configured=True, missing_input=omitted)
            self.assertEqual(result.returncode, 0, result.stderr)
            expected = 'https://old.example.test' if omitted else 'https://example.test'
            self.assertIn('CONTROL_PLANE_URL=' + expected, envs['vmd.env'])
            self.assertIn('DATABASE_URL=' + ('postgres://old.example.test/db' if omitted else 'postgres://example.test/db'), envs['vmd.env'])
            self.assertIn('DAEMON_AUTH_TOKEN=' + ('old-token' if omitted else 'example-token'), envs['secretsproxy.env'])
            self.assertIn('HOST_ID=existing-host', envs['vmd.env'])
            self.assertNotIn('restart-secretsproxy', result.stdout)

    def test_preflight_precedes_bundle_upload_and_remote_mutations(self):
        self.assertLess(SOURCE.index('runtime input preflight")'), SOURCE.index('"compute", "scp"'))
        self.assertLess(SOURCE.index('inject_script = input_preflight +'), SOURCE.index('sudo install -d'))

    def test_blank_vmd_env_requires_explicit_kernel_selection(self):
        result, envs, modes = self.exercise(configure_kernel=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('KERNEL_PATH must name a provisioned', result.stderr)
        self.assertEqual(modes['vmd.env'], 0o644)
        self.assertEqual(modes['secretsproxy.env'], 0o600)
        self.assertIn('/var/lib/sandbox/rootfs/base.ext4', envs['vmd.env'])

    def test_each_missing_artifact_blocks_activation(self):
        for artifact in ('kernel', 'rootfs'):
            result, _, _ = self.exercise(missing_artifact=artifact)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('vmd-may-start', result.stdout)

    def test_shared_ca_required_including_partial_pairs(self):
        for missing in [('ca.crt',), ('ca.key',), ('ca.crt', 'ca.key')]:
            result, _, _ = self.exercise(ca_missing=missing)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('requires the restored cell secretsproxy CA pair', result.stderr)
            self.assertNotIn('vmd-may-start', result.stdout)

    def test_explicit_artifact_paths_are_preserved(self):
        result, envs, _ = self.exercise(custom_paths=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(envs['vmd.env'], r'BASE_ROOTFS_PATH=.*/var/lib/custom/rootfs')

    def test_fresh_readiness_precedes_any_vmd_restart_and_no_ca_copy(self):
        gate = SOURCE.index('# CD targets existing cells:')
        self.assertLess(gate, SOURCE.index('sudo systemctl restart {service}'))
        self.assertLess(SOURCE.index('# Fresh-host env bootstrap:'), SOURCE.index('sudo sed -i'))
        self.assertNotIn('gen-secretsproxy-ca', SOURCE)
        self.assertNotIn('openssl req', SOURCE)
        self.assertIn('SECRETSPROXY_FRESH" = 1', SOURCE)


if __name__ == '__main__':
    unittest.main()
