"""Execute fresh-host initialization and fail-closed daemon ordering in a fake host."""
import ast
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import textwrap
import unittest

SOURCE = Path(__file__).with_name('deploy-vmd.py').read_text()


def block(start, end):
    return textwrap.dedent(SOURCE[SOURCE.index(start):SOURCE.index(end, SOURCE.index(start))])


BOOTSTRAP = block('# Fresh-host env bootstrap:', '# End fresh-host env bootstrap.')
HOST_ID = block("if ! sudo grep -q '^HOST_ID='", '# Upsert SECRETSPROXY_SOCKET')
CONTROL = block('if [ -n {q_cpu} ]; then', '# Upsert the guest DNS redirect port')
TOKENS = block('if [ -n {q_token} ]; then', '# Fresh-host runtime preflight.\n')
READY = block('# Fresh-host runtime preflight.\n', '# End fresh-host runtime preflight.')


class FreshHostTest(unittest.TestCase):
    def exercise(self, missing=('vmd', 'secretsproxy'), fail_daemon=False, missing_input=False, assets=True):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            envdir = root / 'etc/sandbox'
            envdir.mkdir(parents=True)
            for name in ('vmd', 'secretsproxy'):
                if name not in missing:
                    (envdir / (name + '.env')).write_text('HOST_ID=existing-host\nCUSTOM=preserve\n')
            if assets:
                (root / 'var/lib/sandbox').mkdir(parents=True)
                for name in ('vmlinux', 'base.ext4'):
                    (root / 'var/lib/sandbox' / name).write_text('approved artifact')
            values = {'service': 'superserve-vmd.service', 'q_host_id_line': shlex.quote('HOST_ID=example-host')}
            for key, name, value in [('cpu', 'CONTROL_PLANE_URL', 'https://example.test'),
                                     ('token', 'INTERNAL_API_TOKEN', 'example-token'),
                                     ('db', 'DATABASE_URL', 'postgres://example.test/db')]:
                values['q_' + key] = shlex.quote('' if missing_input and key == 'token' else value)
                values['q_' + key + '_line'] = shlex.quote(name + '=' + value)
            values['q_iat_line'] = shlex.quote('INTERNAL_API_TOKEN=example-token')
            values['q_dat_line'] = shlex.quote('DAEMON_AUTH_TOKEN=example-token')
            script = '\n'.join((BOOTSTRAP, HOST_ID, CONTROL, TOKENS, READY))
            script = ast.literal_eval('"""' + script + '"""').format(**values)
            script = script.replace('/etc/systemd', str(root / 'etc/systemd')).replace('/etc/sandbox', str(envdir)).replace('/var/lib/', str(root / 'var/lib') + '/')
            prelude = '''set -eu
sudo() { if [ "$1" = chown ]; then return; fi; "$@"; }
seq() { echo 1; }
sleep() { :; }
systemctl() {
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
            result = subprocess.run(['bash', '-c', prelude + script + '\necho vmd-may-start\n'],
                text=True, capture_output=True, env=dict(os.environ, CALLS=str(root/'calls'),
                CA_DIR=str(root/'var/lib/secretsproxy'), FAIL_DAEMON=str(int(fail_daemon))))
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
                    self.assertEqual(modes[name+'.env'], 0o600)
                self.assertIn('DAEMON_AUTH_TOKEN=example-token', envs['secretsproxy.env'])
                self.assertIn('DATABASE_URL=postgres://example.test/db', envs['secretsproxy.env'])
                self.assertIn('vmd-may-start', result.stdout)

    def test_missing_settings_or_daemon_failure_block_vmd(self):
        for options, message in [({'missing_input': True}, 'requires DAEMON_AUTH_TOKEN'),
                                 ({'fail_daemon': True}, 'secretsproxy provisioning/readiness failed'),
                                 ({'assets': False}, 'provisioned kernel/base-rootfs')]:
            with self.subTest(options=options):
                result, _, _ = self.exercise(**options)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertNotIn('vmd-may-start', result.stdout)

    def test_fresh_readiness_precedes_any_vmd_restart_and_no_ca_copy(self):
        gate = SOURCE.index('# NewCA in the daemon is authoritative')
        self.assertLess(gate, SOURCE.index('sudo systemctl restart {service}'))
        self.assertLess(SOURCE.index('# Fresh-host env bootstrap:'), SOURCE.index('sudo sed -i'))
        self.assertNotIn('gen-secretsproxy-ca', SOURCE)
        self.assertNotIn('openssl req', SOURCE)
        self.assertIn('SECRETSPROXY_FRESH" = 1', SOURCE)


if __name__ == '__main__':
    unittest.main()
