import configparser
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import threading
import textwrap
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('host_identity', Path(__file__).with_name('install-host-identity.py'))
identity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identity)


class HostIdentityTests(unittest.TestCase):
    def test_partial_reinstall_preserves_transition_and_rebind_output(self):
        original = identity.choose_identity('example-project', '100', 'example-region-2', None)
        base_argv = ['install-host-identity.py', '--project=example-project',
                     '--zone=example-zone', '--instance=example-vm', '--slot=example-region-2',
                     '--fencing-control-plane-ready']
        reinstall = ['--reinstall', '--expected-incarnation=' + original['incarnation_id']]
        for copied_local in (False, True):
            with self.subTest(copied_local=copied_local):
                provider = dict(original)
                local = dict(original)
                failing = True

                def run(args, **kwargs):
                    nonlocal provider, local
                    output = ''
                    if args[1:4] == ['compute', 'instances', 'describe']:
                        output = json.dumps({'id': '100', 'metadata': {'items': [
                            {'key': identity.KEY, 'value': json.dumps(provider)}]}})
                    elif args[1:4] == ['compute', 'instances', 'add-metadata']:
                        path = next(a.split('=', 2)[2] for a in args if a.startswith('--metadata-from-file='))
                        provider = json.loads(Path(path).read_text())
                    elif args[1:3] == ['compute', 'ssh']:
                        self.assertIn('--tunnel-through-iap', args)
                        script = next(a[len('--command='):] for a in args if a.startswith('--command='))
                        if script.startswith('if sudo test -f'):
                            output = json.dumps(local)
                        elif script.startswith('systemctl show --property=ActiveState --value '):
                            output = 'inactive'
                        elif script.startswith('set -eu\n'):
                            if copied_local or not failing:
                                payload = next(line for line in script.splitlines() if line.startswith("printf '%s'"))
                                local = json.loads(shlex.split(payload)[2])
                            if failing:
                                raise subprocess.CalledProcessError(1, args)
                        else:
                            self.assertIn(script, (f'sudo mkdir {identity.LOCK}', f'sudo rmdir {identity.LOCK}'))
                    else:
                        self.fail(f'unexpected command: {args}')
                    return subprocess.CompletedProcess(args, 0, stdout=output)

                with patch.object(identity.subprocess, 'run', side_effect=run), \
                        patch('builtins.print') as printed:
                    with patch('sys.argv', base_argv + reinstall):
                        with self.assertRaises(subprocess.CalledProcessError):
                            identity.main()
                        persisted = dict(provider)
                        self.assertEqual(provider['previous_incarnation_id'], original['incarnation_id'])
                        self.assertNotEqual(provider['incarnation_id'], original['incarnation_id'])
                        self.assertFalse(printed.called)
                        failing = False
                        with patch('sys.argv', base_argv if copied_local else base_argv + reinstall):
                            identity.main()
                    # A retry without --reinstall must also retain the instruction.
                    with patch('sys.argv', base_argv + reinstall if copied_local else base_argv):
                        identity.main()
                    self.assertEqual(provider, persisted)
                    self.assertEqual(local, persisted)
                    rebinds = [call.args[0] for call in printed.call_args_list
                               if call.args[0].startswith('Before restarting VMD:')]
                    self.assertEqual(rebinds, [f"Before restarting VMD: hostctl rebind {original['host_id']} "
                                              f"{original['incarnation_id']} {persisted['incarnation_id']}"] * 2)

    def test_reinstall_requires_service_and_socket_stopped(self):
        original = identity.choose_identity('example-project', '100', 'example-region-2', None)
        argv = ['install-host-identity.py', '--project=example-project',
                '--zone=example-zone', '--instance=example-vm', '--slot=example-region-2',
                '--reinstall', '--expected-incarnation=' + original['incarnation_id'],
                '--fencing-control-plane-ready']
        for unit in ('superserve-vmd.service', 'superserve-vmd.socket'):
            for state in ('active', 'activating', 'deactivating', 'reloading', ''):
                with self.subTest(unit=unit, state=state):
                    def run(args, **kwargs):
                        output = ''
                        if args[1:4] == ['compute', 'instances', 'describe']:
                            output = json.dumps({'id': '100', 'metadata': {'items': [
                                {'key': identity.KEY, 'value': json.dumps(original)}]}})
                        elif args[1:3] == ['compute', 'ssh']:
                            self.assertIn('--tunnel-through-iap', args)
                            script = next(a[len('--command='):] for a in args if a.startswith('--command='))
                            if script.startswith('if sudo test -f'):
                                output = json.dumps(original)
                            elif script.startswith('systemctl show --property=ActiveState --value '):
                                output = state if script.endswith(unit) else 'inactive'
                            else:
                                self.assertIn(script, (f'sudo mkdir {identity.LOCK}', f'sudo rmdir {identity.LOCK}'))
                        else:
                            self.fail(f'identity must not be written: {args}')
                        return subprocess.CompletedProcess(args, 0, stdout=output)

                    with patch('sys.argv', argv), patch.object(identity.subprocess, 'run', side_effect=run):
                        with self.assertRaisesRegex(ValueError, 'requires VMD stopped'):
                            identity.main()

    def test_new_machine_retry_after_local_install_failure(self):
        provider = None
        local = None
        fail_install = True
        service_active = False
        metadata_writes = []
        argv = ['install-host-identity.py', '--project=example-project',
                '--zone=example-zone', '--instance=example-vm', '--slot=example-region-2',
                '--fencing-control-plane-ready']

        def run(args, **kwargs):
            nonlocal provider, local
            output = ''
            if args[1:4] == ['compute', 'instances', 'describe']:
                items = [] if provider is None else [
                    {'key': identity.KEY, 'value': json.dumps(provider)}]
                output = json.dumps({'id': '100', 'metadata': {'items': items}})
            elif args[1:4] == ['compute', 'instances', 'add-metadata']:
                path = next(a.split('=', 2)[2] for a in args if a.startswith('--metadata-from-file='))
                provider = json.loads(Path(path).read_text())
                metadata_writes.append(dict(provider))
            elif args[1:3] == ['compute', 'ssh']:
                self.assertIn('--tunnel-through-iap', args)
                script = next(a[len('--command='):] for a in args if a.startswith('--command='))
                if script in (f'sudo mkdir {identity.LOCK}', f'sudo rmdir {identity.LOCK}'):
                    pass
                elif script.startswith('if sudo test -f'):
                    output = json.dumps(local) if local else ''
                elif script.startswith('systemctl show --property=ActiveState --value '):
                    output = 'active' if service_active else 'inactive'
                elif script.startswith('set -eu\n'):
                    if fail_install:
                        raise subprocess.CalledProcessError(1, args)
                    payload = next(line for line in script.splitlines() if line.startswith("printf '%s'"))
                    local = json.loads(shlex.split(payload)[2])
                else:
                    self.fail(f'unexpected SSH command: {script}')
            else:
                self.fail(f'unexpected command: {args}')
            return subprocess.CompletedProcess(args, 0, stdout=output)

        with patch.object(identity.subprocess, 'run', side_effect=run), \
                patch('builtins.print') as printed:
            with patch('sys.argv', argv + ['--new-machine']):
                with self.assertRaises(subprocess.CalledProcessError):
                    identity.main()
            original = dict(provider)
            self.assertIsNone(local)
            fail_install = False
            # Missing local state still requires explicit operator attestation.
            with patch('sys.argv', argv):
                with self.assertRaisesRegex(ValueError, 'explicit --reinstall'):
                    identity.main()
            with patch('sys.argv', argv + ['--new-machine']):
                service_active = True
                with self.assertRaisesRegex(ValueError, 'requires VMD stopped'):
                    identity.main()
                self.assertEqual(metadata_writes, [original])
                service_active = False
                identity.main()
            self.assertEqual(local, original)
            self.assertEqual(metadata_writes, [original, original])
            self.assertFalse(any('hostctl rebind' in call.args[0] for call in printed.call_args_list))

    def test_boot_gate_preserves_installed_host_activation(self):
        modules = Path(__file__).resolve().parents[1] / 'infra/modules'
        for module in ('sandbox-host', 'managed-identity-host'):
            source = (modules / module / 'main.tf').read_text()
            script = textwrap.dedent(source.split('host_identity_prerequisite = <<-EOT\n', 1)[1]
                                     .split('\n  EOT', 1)[0])
            for json_state, env_state in [('installed', 'installed'), (None, None),
                                          (None, 'installed'), ('installed', None),
                                          ('', 'installed'), ('installed', '')]:
                with self.subTest(module=module, json=json_state, env=env_state), \
                        tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    (root / 'etc/sandbox').mkdir(parents=True)
                    for suffix, state in [('json', json_state), ('env', env_state)]:
                        if state is not None:
                            (root / f'etc/sandbox/host-identity.{suffix}').write_text(state)
                    systemctl = root / 'systemctl'
                    systemctl.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\n')
                    systemctl.chmod(0o755)
                    calls = root / 'calls'
                    subprocess.run(['sh', '-eu', '-c', script.replace('/etc/', tmp + '/etc/')],
                                   check=True, capture_output=True, text=True,
                                   env={**os.environ, 'PATH': tmp + os.pathsep + os.environ['PATH'],
                                        'CALLS': str(calls)})
                    commands = calls.read_text().splitlines()
                    if json_state and env_state:
                        self.assertEqual(commands, ['daemon-reload'])
                    else:
                        self.assertEqual(commands, ['cat superserve-vmd.socket',
                                                    'stop superserve-vmd.socket',
                                                    'cat superserve-vmd.service',
                                                    'stop superserve-vmd.service',
                                                    'daemon-reload'])
                    for unit in ('socket', 'service'):
                        self.assertTrue((root / 'etc/systemd/system' /
                                         f'superserve-vmd.{unit}.d/10-identity-required.conf').is_file())

    def test_concurrent_reinstall_is_locked_through_local_install(self):
        original = identity.choose_identity('example-project', '100', 'example-region-2', None)
        provider = dict(original)
        local = dict(original)
        metadata_written = threading.Event()
        finish_install = threading.Event()
        calls = []
        argv = ['install-host-identity.py', '--project=example-project',
                '--zone=example-zone', '--instance=example-vm', '--slot=example-region-2',
                '--reinstall', '--expected-incarnation='+original['incarnation_id'],
                '--fencing-control-plane-ready']

        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / 'install.lock'

            def run(args, **kwargs):
                nonlocal provider, local
                calls.append(args)
                output = ''
                if args[1:4] == ['compute', 'instances', 'describe']:
                    output = json.dumps({'id': '100', 'metadata': {'items': [
                        {'key': identity.KEY, 'value': json.dumps(provider)}]}})
                elif args[1:4] == ['compute', 'instances', 'add-metadata']:
                    path = next(a.split('=', 2)[2] for a in args if a.startswith('--metadata-from-file='))
                    provider = json.loads(Path(path).read_text())
                elif args[1:3] == ['compute', 'ssh']:
                    self.assertIn('--tunnel-through-iap', args)
                    script = next(a[len('--command='):] for a in args if a.startswith('--command='))
                    if script == f'sudo mkdir {identity.LOCK}':
                        try:
                            lock.mkdir()
                        except FileExistsError:
                            raise subprocess.CalledProcessError(1, args)
                    elif script == f'sudo rmdir {identity.LOCK}':
                        lock.rmdir()
                    elif script.startswith('if sudo test -f'):
                        output = json.dumps(local)
                    elif script.startswith('systemctl show --property=ActiveState --value '):
                        output = 'inactive'
                    elif script.startswith('set -eu\n'):
                        # The provider write and post-write check have completed;
                        # local state must still be protected against competitors.
                        metadata_written.set()
                        if not finish_install.wait(10):
                            raise TimeoutError('test did not release local installation')
                        payload_line = next(line for line in script.splitlines() if line.startswith("printf '%s'"))
                        local = json.loads(shlex.split(payload_line)[2])
                    else:
                        self.fail(f'unexpected SSH command: {script}')
                else:
                    self.fail(f'unexpected command: {args}')
                return subprocess.CompletedProcess(args, 0, stdout=output)

            with patch.object(identity.subprocess, 'run', side_effect=run), \
                    patch('sys.argv', argv), patch('builtins.print') as printed, \
                    ThreadPoolExecutor(max_workers=1) as pool:
                first = pool.submit(identity.main)
                try:
                    self.assertTrue(metadata_written.wait(10))
                    self.assertNotEqual(provider, local)
                    before = len(calls)
                    with self.assertRaises(subprocess.CalledProcessError):
                        identity.main()
                    # A failed acquisition must neither read provider state nor
                    # release the first installer's lock.
                    self.assertEqual(len(calls), before + 1)
                    self.assertTrue(lock.is_dir())
                finally:
                    finish_install.set()
                first.result(timeout=10)
                self.assertEqual(provider, local)
                self.assertFalse(lock.exists())
                self.assertEqual(provider['host_id'], original['host_id'])
                self.assertNotEqual(provider['incarnation_id'], original['incarnation_id'])
                installed = dict(provider)
                identity.main()
                self.assertEqual(provider, installed)
                self.assertFalse(lock.exists())
                rebinds = [call.args[0] for call in printed.call_args_list
                           if call.args[0].startswith('Before restarting VMD:')]
                self.assertEqual(rebinds, [f"Before restarting VMD: hostctl rebind {original['host_id']} "
                                          f"{original['incarnation_id']} {provider['incarnation_id']}"] * 2)

    def test_baked_units_gate_start_before_cloud_init(self):
        deploy = Path(__file__).parent
        service = configparser.ConfigParser(strict=False, interpolation=None)
        service.read(deploy / 'superserve-vmd.service')
        # The last environment file overrides the ordinary image-baked HOST_ID.
        self.assertEqual(service['Service']['EnvironmentFile'], '/etc/sandbox/host-identity.env')
        self.assertEqual(service['Service']['Environment'], 'HOST_IDENTITY_REQUIRED=1')
        self.assertEqual(service['Service']['ExecStartPre'], '/usr/bin/test -s /etc/sandbox/host-identity.json')
        self.assertEqual(service['Unit']['Requires'], 'superserve-vmd.socket')

        # Both conditions must live in the image unit, not a cloud-init drop-in.
        socket = (deploy / 'superserve-vmd.socket').read_text().split('[Socket]')[0]
        self.assertIn('\nConditionPathExists=/etc/sandbox/host-identity.json\n', socket)
        self.assertIn('\nConditionPathExists=/etc/sandbox/host-identity.env\n', socket)

    def test_restart_rebuild_and_replacement(self):
        first = identity.choose_identity('example-project', '100', 'example-region-2', None)
        self.assertEqual(first, identity.choose_identity('example-project', '100', 'example-region-2', first))
        rebuild = identity.choose_identity('example-project', '100', 'example-region-2', first, reinstall=True)
        self.assertEqual(first['host_id'], rebuild['host_id'])
        self.assertNotEqual(first['incarnation_id'], rebuild['incarnation_id'])
        replacement = identity.choose_identity('example-project', '101', 'example-region-2', None)
        self.assertNotEqual(first['host_id'], replacement['host_id'])
        with self.assertRaises(ValueError):
            identity.choose_identity('example-project', '101', 'example-region-2', first)

    def test_legacy_identity_and_missing_provider_record(self):
        first = dict(project_id='example-project', instance_id='100',
                     host_id='example-legacy', incarnation_id='73863d7a-26f8-4a41-9d89-d458421935e7')
        self.assertEqual(first, identity.choose_identity(
            'example-project', '100', 'example-region-2', first, legacy_host_id='example-legacy'))
        for project, machine in [('example-project', '101'), ('other-project', '100')]:
            with self.subTest(project=project, machine=machine):
                with self.assertRaisesRegex(ValueError, 'cloned machine metadata'):
                    identity.choose_identity(project, machine, 'example-region-2', first,
                                             legacy_host_id='example-legacy')
        with self.assertRaisesRegex(ValueError, 'full host ID is immutable'):
            identity.choose_identity('example-project', '100', 'example-region-2', first,
                                     legacy_host_id='another-legacy')
        with self.assertRaisesRegex(ValueError, 'existing same-VM provider identity record'):
            identity.choose_identity('example-project', '101', 'example-region-2', None,
                                     legacy_host_id='example-legacy')
        with self.assertRaises(ValueError):
            identity.choose_identity('example-project', '100', 'example-region-2', None, reinstall=True)

    def test_legacy_adoption_without_provenance_does_not_write_identity(self):
        argv = ['install-host-identity.py', '--project=example-project',
                '--zone=example-zone', '--instance=example-vm', '--slot=example-region-2',
                '--legacy-host-id=example-legacy', '--fencing-control-plane-ready']

        def run(args, **kwargs):
            output = ''
            if args[1:4] == ['compute', 'instances', 'describe']:
                output = json.dumps({'id': '101'})
            elif args[1:3] == ['compute', 'ssh']:
                self.assertIn('--tunnel-through-iap', args)
                script = next(a[len('--command='):] for a in args if a.startswith('--command='))
                self.assertIn(script, [f'sudo mkdir {identity.LOCK}', f'sudo rmdir {identity.LOCK}',
                                      f'if sudo test -f {identity.STATE}; then sudo cat {identity.STATE}; fi'])
            else:
                self.fail(f'unexpected command: {args}')
            return subprocess.CompletedProcess(args, 0, stdout=output)

        for extra in [[], ['--new-machine']]:
            with self.subTest(extra=extra), patch('sys.argv', argv + extra), \
                    patch.object(identity.subprocess, 'run', side_effect=run):
                with self.assertRaisesRegex(ValueError, 'existing same-VM provider identity record'):
                    identity.main()
