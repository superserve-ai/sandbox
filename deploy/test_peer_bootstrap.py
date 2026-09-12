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
        instance_labels = {}
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
                          'workloadIdentityConfig': instance_identity, 'labels': instance_labels}
            if args[1:4] == ['compute', 'instances', 'update']:
                instance_identity.update(identity=config['spiffe_uri'][9:], identityCertificateEnabled=True)
            return subprocess.CompletedProcess(args, 0, json.dumps(output), '')
        with patch.object(CONFIGURE.subprocess, 'run', side_effect=run):
            CONFIGURE.configure(config)
            CONFIGURE.configure(config)
        self.assertFalse(any('create' in args for args in calls))
        self.assertEqual(policies, [{'attestationRules': [{'googleCloudResource':
            '//compute.googleapis.com/projects/123456789012/uid/zones/us-west2-a/instances/1234567890'}]}] * 2)
        bindings = [c for c in calls if c[1:4] == ['privateca', 'pools', 'add-iam-policy-binding']]
        self.assertEqual(bindings, [
            ['gcloud', 'privateca', 'pools', 'add-iam-policy-binding',
             'projects/example-project/locations/us-west2/caPools/peer', '--location=us-west2',
             '--member=principal://iam.googleapis.com/projects/123456789012/name/locations/global/'
             'workloadIdentityPools/vmd-peer-example', f'--role={role}',
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

        for labels in ({'sandbox_status': 'ready'}, {'component': 'vmd'}):
            instance_identity.clear()
            instance_labels.clear()
            instance_labels.update(labels)
            calls.clear()
            with patch.object(CONFIGURE.subprocess, 'run', side_effect=run):
                with self.assertRaisesRegex(RuntimeError, 'ready/serving discovery'):
                    CONFIGURE.configure(config)
            self.assertFalse(any(c[1:4] == ['compute', 'instances', 'update'] for c in calls))

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
                                     'labels': {'component': 'vmd-usw2-standby'},
                                     'workloadIdentityConfig': {'identity': 'example.test/peer',
                                                                'identityCertificateEnabled': True},
                                     'networkInterfaces': [{'networkIP': config['internal_ip']}],
                                     'serviceAccounts': [{'email': config['runtime_email']}]})
            elif args[1:3] == ['compute', 'ssh']:
                script = args[args.index('--command') + 1]
                scripts.append(script)
                if script == BOOTSTRAP.MANAGED_CREDENTIALS_CHECK:
                    output = 'ready\n'
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

    def test_deployment_discovery_labels_block_migration_before_mutation(self):
        for name, host_id in [('superserve-vmd-staging-2', 'superserve-vmd-staging-2'),
                              ('superserve-vmd-usw2-2', 'usw2-2')]:
            config = {'instance_name': name, 'host_id': host_id,
                      'project_id': 'example-project', 'zone': 'us-west2-a',
                      'instance_id': '1234567890', 'internal_ip': '192.0.2.3',
                      'runtime_email': 'vmd@example-project.iam.gserviceaccount.com'}
            for labels in ({'component': 'vmd'},
                           {'component': 'vmd', 'sandbox_status': 'provisioning'},
                           {'sandbox_status': 'ready'},
                           {'component': 'vmd-usw2-standby', 'sandbox_status': 'ready'},
                           {'component': 'vmd', 'sandbox_status': 'ready'}):
                with self.subTest(name=name, labels=labels):
                    instance = {'id': config['instance_id'], 'status': 'TERMINATED',
                                'labels': labels,
                                'networkInterfaces': [{'networkIP': config['internal_ip']}],
                                'serviceAccounts': [{'email': config['runtime_email']}]}
                    with patch.object(BOOTSTRAP.subprocess, 'run', return_value=
                                      subprocess.CompletedProcess([], 0, json.dumps(instance), '')) as run:
                        with self.assertRaisesRegex(ValueError, 'deployment discovery'):
                            BOOTSTRAP.bootstrap(config)
                        run.assert_called_once()
                        self.assertEqual(run.call_args.args[0][1:4], ['compute', 'instances', 'describe'])

    def test_serving_host_cannot_enter_bootstrap(self):
        with patch.object(BOOTSTRAP.subprocess, 'run') as run:
            with self.assertRaises(ValueError):
                BOOTSTRAP.bootstrap({'instance_name': 'example-host-1', 'host_id': 'example-host-1'})
            run.assert_not_called()


class BootstrapActivationTest(unittest.TestCase):
    def exercise(self, active=False, initially_stopped=False, fail_publication=False,
                 admission_at=None, stop_fails=False, transient_active=False):
        config = {'instance_name': 'superserve-vmd-staging-2', 'host_id': 'superserve-vmd-staging-2',
                  'project_id': 'example-project', 'zone': 'us-central1-a', 'instance_id': '1234567890',
                  'spiffe_uri': 'spiffe://example.test/peer', 'internal_ip': '192.0.2.3',
                  'runtime_email': 'vmd@example-project.iam.gserviceaccount.com'}
        commands, scripts = [], []
        status = 'TERMINATED' if initially_stopped else 'RUNNING'
        describes = 0
        probes = 0
        activated = initially_stopped
        def run(args, **kwargs):
            nonlocal status, describes, probes, activated
            commands.append(args)
            operation = args[1:4]
            output = ''
            if operation == ['compute', 'instances', 'describe']:
                describes += 1
                labels = {'component': 'vmd-staging-standby', 'sandbox_status': 'provisioning'}
                if admission_at == describes:
                    labels['sandbox_status'] = 'ready'
                output = json.dumps({'id': config['instance_id'], 'status': status, 'labels': labels,
                    'workloadIdentityConfig': {'identity': 'example.test/peer', 'identityCertificateEnabled': True},
                    'networkInterfaces': [{'networkIP': config['internal_ip']}],
                    'serviceAccounts': [{'email': config['runtime_email']}]})
            elif operation == ['compute', 'instances', 'stop']:
                self.assertIn('--discard-local-ssd=False', args)
                if stop_fails:
                    raise subprocess.CalledProcessError(1, args)
                status = 'TERMINATED'
            elif operation == ['compute', 'instances', 'start']:
                status = 'RUNNING'
                activated = True
            elif args[1:3] == ['compute', 'ssh']:
                script = args[args.index('--command') + 1]
                scripts.append(script)
                if script == BOOTSTRAP.MANAGED_CREDENTIALS_CHECK:
                    probes += 1
                    output = 'ready' if active or (activated and probes >= 3) else 'pending'
                    if transient_active and probes == 2:
                        output = 'pending'
                elif script == 'echo ready':
                    output = 'ready'
                elif 'mktemp -d' in script:
                    output = '/tmp/vmd-peer.ABCDEFGH'
                elif 'start vmd-peer-credentials.service' in script and fail_publication:
                    raise subprocess.CalledProcessError(1, args)
            return subprocess.CompletedProcess(args, 0, output, '')
        import io
        output = io.StringIO()
        error = None
        with patch.object(BOOTSTRAP.subprocess, 'run', side_effect=run), \
             patch.object(BOOTSTRAP.time, 'sleep'), patch('sys.stdout', output):
            try:
                BOOTSTRAP.bootstrap(config)
            except (ValueError, subprocess.CalledProcessError) as exc:
                error = exc
        for script in scripts:
            subprocess.run(['bash', '-n'], input=script, check=True, text=True, capture_output=True)
        return commands, scripts, output.getvalue(), error

    def test_missing_credentials_require_full_stop_start_then_publication(self):
        commands, scripts, output, error = self.exercise()
        self.assertIsNone(error)
        power = [c[3] for c in commands if c[1:3] == ['compute', 'instances'] and c[3] in ('stop', 'start')]
        self.assertEqual(power, ['stop', 'start'])
        for command in commands:
            self.assertNotIn('reset', command)
            self.assertNotIn('set-labels', command)
        self.assertGreaterEqual(scripts.count(BOOTSTRAP.MANAGED_CREDENTIALS_CHECK), 3)
        publication = scripts[-1]
        self.assertLess(publication.index('start vmd-peer-credentials.service'),
                        publication.index('test -d /etc/superserve/peer/current'))
        self.assertIn('refresh-peer-credentials --check', publication)
        self.assertIn('Host 2 peer bootstrap installed', output)
        install = next(s for s in scripts if 'ConditionPathExists=' in s)
        self.assertIn('bootstrap-pending', install)
        self.assertIn('bootstrap-pending', publication)

    def test_active_credentials_avoid_power_cycle(self):
        commands, _, output, error = self.exercise(active=True)
        self.assertIsNone(error)
        self.assertFalse(any(c[1:4] in (['compute', 'instances', 'stop'], ['compute', 'instances', 'start']) for c in commands))
        self.assertIn('Host 2 peer bootstrap installed', output)

    def test_guest_refresh_does_not_power_cycle_previously_active_credentials(self):
        commands, scripts, _, error = self.exercise(active=True, transient_active=True)
        self.assertIsNone(error)
        self.assertGreaterEqual(scripts.count(BOOTSTRAP.MANAGED_CREDENTIALS_CHECK), 3)
        self.assertFalse(any(c[1:4] in (['compute', 'instances', 'stop'], ['compute', 'instances', 'start']) for c in commands))

    def test_publication_shell_requires_current_even_when_service_succeeds(self):
        _, scripts, _, error = self.exercise(active=True)
        self.assertIsNone(error)
        publication = scripts[-1]
        block = publication[publication.index('sudo systemctl start vmd-peer-credentials.service'):publication.index('sudo rm -f')]
        with tempfile.TemporaryDirectory() as tmp:
            script = ('set -eu\n' + block).replace('sudo systemctl start vmd-peer-credentials.service', 'true')
            script = script.replace('sudo test', 'test').replace('/etc/superserve/peer/current', tmp + '/current')
            script = script.replace('sudo /usr/local/sbin/refresh-peer-credentials --check', 'echo validated')
            result = subprocess.run(['bash', '-c', script], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('validated', result.stdout)
            (Path(tmp) / 'current').mkdir()
            result = subprocess.run(['bash', '-c', script], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            self.assertIn('validated', result.stdout)

    def test_initially_stopped_host_is_started_only_once(self):
        commands, _, _, error = self.exercise(initially_stopped=True)
        self.assertIsNone(error)
        self.assertEqual([c[3] for c in commands if c[1:3] == ['compute', 'instances'] and c[3] in ('stop', 'start')], ['start'])

    def test_publication_failure_cannot_report_success(self):
        _, _, output, error = self.exercise(active=True, fail_publication=True)
        self.assertIsInstance(error, subprocess.CalledProcessError)
        self.assertNotIn('Host 2 peer bootstrap installed', output)

    def test_rechecks_admission_before_each_power_operation(self):
        for admission_at, expected_power in ((1, []), (2, []), (3, ['stop'])):
            commands, _, output, error = self.exercise(admission_at=admission_at)
            self.assertIsInstance(error, ValueError)
            self.assertEqual([c[3] for c in commands if c[1:3] == ['compute', 'instances'] and c[3] in ('stop', 'start')], expected_power)
            self.assertNotIn('Host 2 peer bootstrap installed', output)

    def test_stop_failure_never_starts_or_claims_success(self):
        commands, _, output, error = self.exercise(stop_fails=True)
        self.assertIsInstance(error, subprocess.CalledProcessError)
        self.assertFalse(any(c[1:4] == ['compute', 'instances', 'start'] for c in commands))
        self.assertNotIn('Host 2 peer bootstrap installed', output)

    def test_wait_is_bounded_and_retries_ssh_and_missing_files(self):
        clock = [0]
        def sleep(seconds):
            clock[0] += seconds
        for responses, succeeds in (([subprocess.CalledProcessError(1, ['ssh']), 'pending', 'ready'], True),
                                    (['pending'] * 3, False)):
            with patch.object(BOOTSTRAP.time, 'monotonic', side_effect=lambda: clock[0]), \
                 patch.object(BOOTSTRAP.time, 'sleep', side_effect=sleep):
                probe = unittest.mock.Mock(side_effect=responses)
                if succeeds:
                    BOOTSTRAP.wait_for_managed_credentials(probe, timeout=15)
                else:
                    with self.assertRaisesRegex(TimeoutError, 'managed workload credentials'):
                        BOOTSTRAP.wait_for_managed_credentials(probe, timeout=15)
                self.assertEqual(probe.call_count, 3)
                for call in probe.call_args_list:
                    self.assertGreater(call.kwargs['timeout'], 0)
                    self.assertLessEqual(call.kwargs['timeout'], 15)

    def test_probe_requires_every_nonempty_managed_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = BOOTSTRAP.MANAGED_CREDENTIALS_CHECK.replace('/run/secrets/workload-spiffe-credentials', tmp).replace('sudo test', 'test')
            names = ('certificates.pem', 'private_key.pem', 'ca_certificates.pem')
            def probe():
                return subprocess.check_output(['bash', '-c', script], text=True).strip()
            self.assertEqual(probe(), 'pending')
            for name in names:
                (Path(tmp) / name).write_text('example credential')
            self.assertEqual(probe(), 'ready')
            for name in names:
                (Path(tmp) / name).write_text('')
                self.assertEqual(probe(), 'pending')
                (Path(tmp) / name).write_text('example credential')


if __name__ == '__main__':
    unittest.main()
