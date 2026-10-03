"""Validate the fixed probe without connecting to a host or running systemd."""

import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import recovery_guest_probe as probe


class GuestProbeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        def write(path, data):
            target = self.root / path.lstrip('/')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(data)
        write('/proc/sys/kernel/random/boot_id', 'boot')
        write('/etc/sandbox/vmd.env', 'CONTROL_PLANE_URL=https://api.example.test\nINTERNAL_API_TOKEN=private-value\n')
        write('/etc/sandbox/secretsproxy.env', 'CONTROL_PLANE_URL=https://api.example.test\nDATABASE_URL=private-value\n')
        write('/etc/sandbox/host-identity.env', 'HOST_ID=example\n')
        self.properties, self.units = {}, {}
        for pid, (unit, (binary, env)) in enumerate(probe.SERVICES.items(), 1):
            fragment = '/etc/systemd/system/' + unit
            text = f'[Service]\nExecStart=/usr/local/bin/{binary}\nEnvironmentFile={env}\n'
            files = env + ' (ignore_errors=no)'
            if binary == 'vmd':
                text += 'Environment=HOST_IDENTITY_REQUIRED=1\nEnvironmentFile=/etc/sandbox/host-identity.env\n'
                files += ' /etc/sandbox/host-identity.env (ignore_errors=no)'
            self.units[unit] = text
            write(fragment, text)
            write('/usr/local/bin/'+binary, binary)
            dropins = []
            if binary == 'vmd':
                for name, guard in probe.DROPINS.items():
                    path = fragment + '.d/' + name
                    write(path, name)
                    dropins.append(path)
                    if guard:
                        write('/usr/local/bin/'+guard, guard)
            self.properties[unit] = {'MainPID': str(pid), 'InvocationID': 'instance-'+str(pid),
                 'ExecStart': f'{{ path=/usr/local/bin/{binary} ; argv[]=/usr/local/bin/{binary} ; }}',
                 'EnvironmentFiles': files, 'Environment': 'HOST_IDENTITY_REQUIRED=1' if binary == 'vmd' else '',
                 'DropInPaths': ' '.join(dropins), 'FragmentPath': fragment, 'ActiveState': 'active', 'NeedDaemonReload': 'no'}

    def run_probe(self):
        def path(value):
            return self.root / str(value).lstrip('/')
        def digest(value):
            return hashlib.sha256(path(value).read_bytes()).hexdigest()
        def command(args):
            if args[1] == 'show':
                # systemctl's array-of-struct printer repeats this property.
                return '\n'.join(k+'='+v.replace(') ', ')\nEnvironmentFiles=')
                                 if k == 'EnvironmentFiles' else k+'='+v
                                 for k, v in self.properties[args[2]].items())
            return self.units[args[2]]
        def process(pid):
            binary = 'vmd' if pid == 1 else 'secretsproxy'
            return {'pid': pid, 'start_ticks': '100', 'executable_sha256': digest('/usr/local/bin/'+binary),
                    'routing': {'origin': 'https://api.example.test', 'resolved_addresses': ['192.0.2.1']},
                    'established_peers': []}
        with patch.object(probe, 'Path', side_effect=path), patch.object(probe, 'digest', side_effect=digest), \
             patch.object(probe, 'command', side_effect=command), patch.object(probe, 'process', side_effect=process), \
             patch.object(probe.socket, 'getaddrinfo', return_value=[(None, None, None, None, ('192.0.2.1', 443))]):
            return probe.probe()

    def test_audited_dropins_are_reported_without_secret_values(self):
        result = self.run_probe()
        self.assertEqual(set(result['services'][0]['dropins']), set(probe.DROPINS))
        self.assertEqual(len(result['services'][0]['guards']), 4)
        self.assertNotIn('private-value', repr(result))
        self.assertNotIn('DATABASE_URL', repr(result))

    def add_extra(self, name):
        unit = 'superserve-vmd.service'
        path = '/etc/systemd/system/'+unit+'.d/'+name
        (self.root/path.lstrip('/')).write_text(probe.EXTRA_DROPINS[name])
        self.properties[unit]['DropInPaths'] += ' '+path
        self.units[unit] += probe.EXTRA_DROPINS[name]
        if name == 'identity.conf':
            self.properties[unit]['EnvironmentFiles'] += ' /etc/sandbox/host-identity.env (ignore_errors=no)'
        for line in probe.EXTRA_DROPINS[name].splitlines():
            if line.startswith('Environment='):
                self.properties[unit]['Environment'] += ' '+line.removeprefix('Environment=')

    def test_observed_host_variants_require_exact_contents_and_loaded_settings(self):
        for name in probe.EXTRA_DROPINS:
            self.add_extra(name)
        result = self.run_probe()
        self.assertEqual(set(result['services'][0]['dropins']), set(probe.DROPINS) | set(probe.EXTRA_DROPINS))
        unit = 'superserve-vmd.service'
        original = copy.deepcopy(self.properties)
        for field, suffix in [('Environment', ' CONTROL_PLANE_URL=private-value'),
                              ('Environment', ' VMD_SYSTEMD_DBUS=false'),
                              ('EnvironmentFiles', ' /etc/sandbox/host-identity.env (ignore_errors=no)')]:
            self.properties = copy.deepcopy(original)
            self.properties[unit][field] += suffix
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.run_probe()
        self.properties = original
        for name in probe.EXTRA_DROPINS:
            path = self.root/'etc/systemd/system'/f'{unit}.d'/name
            path.write_text(probe.EXTRA_DROPINS[name]+'Environment=CONTROL_PLANE_URL=private-value\n')
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.run_probe()
            path.write_text(probe.EXTRA_DROPINS[name])

    def test_actual_east_and_west_environment_file_and_flag_sets(self):
        original_properties, original_units = copy.deepcopy(self.properties), copy.deepcopy(self.units)
        for extras in (
            ('20-localssd-storage.conf', 'dbus.conf', 'dirty-session.conf', 'identity.conf', 'tap-reset.conf'),
            ('dirty-session.conf', 'identity.conf', 'sandbox-data.conf', 'sandbox-localssd.conf'),
        ):
            self.properties, self.units = copy.deepcopy(original_properties), copy.deepcopy(original_units)
            for name in extras:
                self.add_extra(name)
            with self.subTest(extras=extras):
                result = self.run_probe()
                self.assertEqual(set(result['services'][0]['dropins']), set(probe.DROPINS) | set(extras))

    def test_loaded_override_pending_reload_and_extra_guard_reject(self):
        original = copy.deepcopy(self.properties)
        for key, value in [('NeedDaemonReload', 'yes'), ('Environment', 'CONTROL_PLANE_URL=https://elsewhere.test'),
                           ('EnvironmentFiles', '/etc/elsewhere (ignore_errors=no)'),
                           ('DropInPaths', '/run/systemd/system/superserve-vmd.service.d/evil.conf'),
                           ('ExecStart', '{ path=/usr/local/bin/vmd ; argv[]=/usr/local/bin/vmd --other ; }')]:
            self.properties = copy.deepcopy(original)
            self.properties['superserve-vmd.service'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.run_probe()

    def test_routing_rejects_credentials_redirect_parts_and_proxy(self):
        for value in ['http://api.example.test', 'https://user:private-value@api.example.test',
                      'https://api.example.test/path', 'https://api.example.test#private-value']:
            with self.assertRaises(ValueError) as caught:
                probe.origin(value)
            self.assertNotIn('private-value', str(caught.exception))
        with self.assertRaises(ValueError):
            probe.routing({'CONTROL_PLANE_URL': 'https://api.example.test', 'HTTPS_PROXY': 'private-value'})

    def test_digest_streams_on_supported_guest_python(self):
        path = self.root/'sample'
        path.write_bytes(b'example' * 200000)
        self.assertEqual(probe.digest(path), hashlib.sha256(path.read_bytes()).hexdigest())

    def test_failure_identifies_static_check_without_exception_payload(self):
        self.properties['superserve-vmd.service']['Environment'] = 'private-value'
        with self.assertRaises(ValueError) as caught:
            self.run_probe()
        result = probe.failure(caught.exception)
        self.assertEqual(result['check'], 'loaded-environment')
        self.assertEqual(result['service'], 'vmd')
        self.assertEqual(result['error_type'], 'ValueError')
        self.assertNotIn('private-value', repr(probe.failure(PermissionError('private-value'))))
        private_error = type('private-value', (Exception,), {})('private-value')
        self.assertEqual(probe.failure(private_error)['error_type'], 'OtherError')
        self.assertNotIn('private-value', repr(probe.failure(private_error)))


if __name__ == '__main__':
    unittest.main()
