import configparser
import importlib.util
import json
import os
import ssl
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ROOT = Path(__file__).resolve().parents[1]
REFRESH = load('refresh_peer', ROOT / 'deploy/refresh-peer-credentials.py')
CONFIGURE = load('configure_peer', ROOT / 'infra/modules/peer-identity/configure.py')
BOOTSTRAP = load('bootstrap_peer', ROOT / 'deploy/bootstrap-host2.py')


class PeerCertificateTest(unittest.TestCase):
    def test_reject_wrong_identity_key_and_untrusted_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            def generate(prefix, identity):
                subprocess.run([
                    'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-keyout', str(directory / (prefix + '.key')),
                    '-out', str(directory / (prefix + '.crt')),
                    '-subj', '/CN=example-peer', '-addext', f'subjectAltName=URI:{identity}',
                    '-addext', 'extendedKeyUsage=serverAuth,clientAuth',
                ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            identity = 'spiffe://example.test/ns/vmd/sa/vmd-peer-proxy'
            generate('tls', identity)
            generate('other', identity)
            (directory / 'ca.crt').write_bytes((directory / 'tls.crt').read_bytes())
            REFRESH.validate(directory, identity)
            with self.assertRaisesRegex(ValueError, 'URI SAN'):
                REFRESH.validate(directory, 'spiffe://other.example.test/peer')
            original = (directory / 'tls.key').read_bytes()
            (directory / 'tls.key').write_bytes((directory / 'other.key').read_bytes())
            with self.assertRaisesRegex(ValueError, 'key changed'):
                REFRESH.validate(directory, identity)
            (directory / 'tls.key').write_bytes(original)
            (directory / 'ca.crt').write_bytes((directory / 'other.crt').read_bytes())
            with self.assertRaises(subprocess.CalledProcessError):
                REFRESH.validate(directory, identity)

    def test_bad_generation_does_not_replace_current(self):
        with tempfile.TemporaryDirectory() as tmp:
            peer, source = Path(tmp) / 'peer', Path(tmp) / 'source'
            peer.mkdir(); source.mkdir()
            (peer / 'old').mkdir()
            (peer / 'current').symlink_to('old')
            (peer / 'identity.json').write_text(json.dumps({'spiffe_uri': 'spiffe://example.test/peer'}))
            for name in ('certificates.pem', 'private_key.pem', 'ca_certificates.pem'):
                (source / name).write_text('invalid')
            real_open = Path.open
            def open_file(path, *args, **kwargs):
                if str(path) == '/run/lock/vmd-peer-credentials.lock':
                    path = Path(tmp) / 'refresh.lock'
                return real_open(path, *args, **kwargs)
            old_umask = os.umask(0o077)
            try:
                with patch.object(Path, 'open', open_file), self.assertRaises(ssl.SSLError):
                    REFRESH.refresh(peer, source)
            finally:
                os.umask(old_umask)
            self.assertEqual(os.readlink(peer / 'current'), 'old')
            self.assertEqual(list(peer.glob('generation-*')), [])
            self.assertEqual(source.stat().st_mode & 0o777, 0o700)


class ManagedIdentityTest(unittest.TestCase):
    def test_retry_reuses_pool_and_reconciles_exact_instance_attestation(self):
        config = {
            'project_id': 'example-project', 'project_number': '123456789012', 'region': 'us-west2',
            'pool_id': 'vmd-peer-example', 'ca_pool': 'projects/example-project/locations/us-west2/caPools/peer',
            'namespace': 'vmd', 'identity': 'vmd-peer-proxy', 'instance_id': '1234567890',
            'zone': 'us-west2-a', 'instance_name': 'example-host-2',
            'runtime_email': 'vmd@example-project.iam.gserviceaccount.com',
            'spiffe_uri': 'spiffe://vmd-peer-example.global.123456789012.workload.id.goog/ns/vmd/sa/vmd-peer-proxy',
        }
        calls, policies = [], []
        instance_identity = {}
        def run(args, **kwargs):
            calls.append(args)
            output = None
            if 'list' in args:
                if 'namespaces' in args:
                    output = [{'name': 'namespaces/vmd'}]
                elif 'managed-identities' in args:
                    output = [{'name': 'identities/vmd-peer-proxy'}]
                else:
                    output = [{'name': 'pools/vmd-peer-example', 'mode': 'TRUST_DOMAIN', 'state': 'ACTIVE'}]
            if 'set-attestation-rules' in args:
                path = next(a.split('=', 1)[1] for a in args if a.startswith('--policy-file='))
                policies.append(json.loads(Path(path).read_text()))
            if args[1:4] == ['compute', 'instances', 'describe']:
                output = {'id': config['instance_id'], 'serviceAccounts': [{'email': config['runtime_email']}],
                          'workloadIdentityConfig': instance_identity}
            if args[1:4] == ['compute', 'instances', 'update']:
                instance_identity.update(identity=config['spiffe_uri'][9:], identityCertificateEnabled=True)
            return subprocess.CompletedProcess(args, 0, json.dumps(output), '')
        with patch.object(CONFIGURE.subprocess, 'run', side_effect=run):
            CONFIGURE.configure(config)
            CONFIGURE.configure(config)
        self.assertFalse(any('create' in args for args in calls))
        self.assertEqual(policies, [{'attestationRules': [{'googleCloudResource':
            '//compute.googleapis.com/projects/123456789012/zones/us-west2-a/instances/1234567890'}]}] * 2)
        bindings = [c for c in calls if c[1:4] == ['privateca', 'pools', 'add-iam-policy-binding']]
        self.assertEqual(bindings, [
            ['gcloud', 'privateca', 'pools', 'add-iam-policy-binding',
             'projects/example-project/locations/us-west2/caPools/peer', '--location=us-west2',
             '--member=principalSet://iam.googleapis.com/projects/123456789012/locations/global/'
             'workloadIdentityPools/vmd-peer-example/*', f'--role={role}',
             '--project=example-project', '--quiet', '--format=json']
            for role in ('roles/privateca.workloadCertificateRequester', 'roles/privateca.poolReader')
        ] * 2)
        for args in calls:
            self.assertNotIn('stop', args)
            self.assertNotIn('start', args)
            self.assertNotIn('delete', args)
        updates = [c for c in calls if c[1:4] == ['compute', 'instances', 'update']]
        self.assertEqual(len(updates), 1)
        self.assertIn('--identity=' + config['spiffe_uri'][9:], updates[0])
        self.assertIn('--most-disruptive-allowed-action=RESTART', updates[0])

    def test_bootstrap_shell_parses_and_never_stops_another_vm(self):
        config = {'instance_name': 'superserve-vmd-usw2-2', 'host_id': 'usw2-2',
                  'project_id': 'example-project', 'zone': 'us-west2-a', 'instance_id': '1234567890',
                  'spiffe_uri': 'spiffe://example.test/peer',
                  'internal_ip': '192.0.2.3', 'runtime_email': 'vmd@example-project.iam.gserviceaccount.com'}
        scripts, commands = [], []
        def run(args, **kwargs):
            commands.append(args)
            output = ''
            if args[1:4] == ['compute', 'instances', 'describe']:
                output = json.dumps({'id': config['instance_id'], 'status': 'RUNNING',
                                     'workloadIdentityConfig': {'identity': 'example.test/peer',
                                                                'identityCertificateEnabled': True},
                                     'networkInterfaces': [{'networkIP': config['internal_ip']}],
                                     'serviceAccounts': [{'email': config['runtime_email']}]})
            elif args[1:3] == ['compute', 'ssh']:
                script = args[args.index('--command') + 1]
                scripts.append(script)
                if 'mktemp -d' in script:
                    output = '/tmp/vmd-peer.ABCDEFGH\n'
            return subprocess.CompletedProcess(args, 0, output, '')
        with patch.object(BOOTSTRAP.subprocess, 'run', side_effect=run):
            BOOTSTRAP.bootstrap(config)
            BOOTSTRAP.bootstrap(config, verify_only=True)
        for script in scripts:
            subprocess.run(['bash', '-n'], input=script, check=True, text=True, capture_output=True)
        for command in commands:
            self.assertIn('superserve-vmd-usw2-2', ' '.join(command))
            self.assertNotIn('stop', command)
            self.assertNotIn('delete', command)
            self.assertNotIn('add-metadata', command)

        install = next(script for script in scripts if "sudo python3 - <<'PY'" in script)
        update = install.split("sudo python3 - <<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
        restart = next(script for script in scripts if 'coreplugin restart' in script)
        self.assertLess(scripts.index(install), scripts.index(restart))
        self.assertLess(restart.index('coreplugin restart'), restart.index('start vmd-peer-credentials.timer'))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'instance_configs.cfg'
            for initial in (None, '[Accounts]\nuseradd_cmd = useradd %s\n',
                            '[Accounts]\nuseradd_cmd = useradd %s\n[MWLID]\nenabled=false\ncredential_refresh_minutes=5\n'):
                with self.subTest(initial=initial):
                    path.unlink(missing_ok=True)
                    if initial is not None:
                        path.write_text(initial)
                    for _ in range(2):
                        exec(update.replace('/etc/default/instance_configs.cfg', str(path)), {})
                        result = configparser.ConfigParser(interpolation=None)
                        result.read(path)
                        self.assertTrue(result.getboolean('MWLID', 'enabled'))
                        if initial is not None:
                            self.assertEqual(result.get('Accounts', 'useradd_cmd'), 'useradd %s')
                        if initial and 'credential_refresh_minutes' in initial:
                            self.assertEqual(result.get('MWLID', 'credential_refresh_minutes'), '5')

            verify = scripts[-1].split('sudo /usr/local/sbin/refresh-peer-credentials --check', 1)[0]
            verify = verify.replace('/run/secrets/workload-spiffe-credentials', tmp).replace('sudo test', 'test')
            names = ('certificates.pem', 'private_key.pem', 'ca_certificates.pem')
            for name in names:
                (Path(tmp) / name).write_text('credential')
            subprocess.run(['bash', '-c', verify], check=True)
            for name in names:
                credential = Path(tmp) / name
                credential.write_text('')
                self.assertNotEqual(subprocess.run(['bash', '-c', verify]).returncode, 0)
                credential.unlink()
                self.assertNotEqual(subprocess.run(['bash', '-c', verify]).returncode, 0)
                credential.write_text('credential')

    def test_serving_host_cannot_enter_bootstrap(self):
        with patch.object(BOOTSTRAP.subprocess, 'run') as run:
            with self.assertRaises(ValueError):
                BOOTSTRAP.bootstrap({'instance_name': 'example-host-1', 'host_id': 'example-host-1'})
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
