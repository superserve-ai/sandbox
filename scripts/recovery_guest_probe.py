#!/usr/bin/env python3
"""Fixed read-only Linux observation. Outputs no credentials or guest payloads."""

import hashlib
import json
from pathlib import Path
import re
import shlex
import socket
import subprocess
from urllib.parse import urlsplit


SERVICES = {'superserve-vmd.service': ('vmd', '/etc/sandbox/vmd.env'),
            'superserve-secretsproxy.service': ('secretsproxy', '/etc/sandbox/secretsproxy.env')}
DROPINS = {'10-rollback-guard.conf': 'vmd-rollback-guard',
           '20-start-generation.conf': None,
           '30-wake-floor-guard.conf': 'vmd-wake-floor-guard',
           '31-staged-intent-floor-guard.conf': 'vmd-staged-intent-floor-guard',
           '32-snapshot-backup-floor-guard.conf': 'vmd-snapshot-backup-floor-guard'}
# Exact generated recipes from the audited host source. The West mount-only
# variant was reconstructed and matched byte-for-byte by its observed SHA256.
EXTRA_DROPINS = {
    'identity.conf': '[Service]\nEnvironmentFile=/etc/sandbox/host-identity.env\n',
    'dirty-session.conf': '[Service]\nEnvironment=VMD_DIRTY_TRACKING_SESSION=true\n',
    'dbus.conf': '[Service]\nEnvironment=VMD_SYSTEMD_DBUS=true\n',
    'tap-reset.conf': '[Service]\nEnvironment=VMD_RECYCLE_TAP_RESET=true\n',
    'sandbox-localssd.conf': '[Unit]\nRequires=sandbox-localssd.service\nAfter=sandbox-localssd.service\n',
    'sandbox-data.conf': '[Unit]\nRequires=sandbox-data.service\nAfter=sandbox-data.service\n',
    '20-localssd-storage.conf': '[Unit]\nRequiresMountsFor=/var/lib/sandbox/snapshots /var/lib/sandbox/rundir\n',
}

CHECK = 'startup'
SERVICE = None
CHECKS = frozenset({'startup', 'boot-identity', 'loaded-service-properties',
    'service-active-and-reconciled', 'loaded-dropins', 'loaded-environment', 'main-process',
    'loaded-executable-command', 'process-identity', 'process-sockets', 'process-executable',
    'process-routing', 'process-stability', 'installed-executable-match', 'restart-environment',
    'restart-routing', 'restart-destination-match', 'unit-restart-settings',
    'identity-routing-overrides', 'unit-and-guard-hashes', 'additional-reporters',
    'reporter-and-boot-stability', 'final-process-stability'})
ERROR_TYPES = frozenset({'ValueError', 'KeyError', 'FileNotFoundError', 'PermissionError',
    'TimeoutExpired', 'AttributeError', 'UnicodeDecodeError', 'gaierror', 'OSError', 'OtherError'})


def failure(error):
    # Never emit exception text: subprocess/configuration failures can contain secrets.
    kind = type(error).__name__
    if kind not in ERROR_TYPES:
        kind = 'OtherError'
    return {'error': 'Guest observation incomplete; no configuration values emitted',
            'check': CHECK, 'service': SERVICE, 'error_type': kind}


def command(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise ValueError('read failed')
    return result.stdout


def digest(path):
    with open(path, 'rb') as source:
        value = hashlib.sha256()
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            value.update(chunk)
        return value.hexdigest()


def origin(value):
    url = urlsplit(value)
    if (url.scheme != 'https' or not url.hostname or url.username or url.password
            or url.port not in (None, 443) or url.path not in ('', '/') or url.query or url.fragment):
        raise ValueError('unsupported endpoint')
    return 'https://' + url.hostname


def routing(env):
    if any(env.get(name) for name in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy')):
        raise ValueError('unclassified proxy')
    endpoint = origin(env.get('CONTROL_PLANE_URL', ''))
    addresses = sorted({item[4][0] for item in socket.getaddrinfo(urlsplit(endpoint).hostname, 443,
                                                                type=socket.SOCK_STREAM)})
    return {'origin': endpoint, 'resolved_addresses': addresses}


def environment_file(path):
    values = {}
    for line in Path(path).read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        parts = shlex.split(line, comments=False)
        if len(parts) != 1 or '=' not in parts[0]:
            raise ValueError('unsupported environment syntax')
        name, value = parts[0].split('=', 1)
        if name in values:
            raise ValueError('ambiguous environment')
        values[name] = value
    return values


def process(pid):
    global CHECK
    CHECK = 'process-identity'
    root = Path('/proc') / str(pid)
    before = (root / 'stat').read_text().rsplit(')', 1)[1].split()[19]
    env = dict(entry.split('=', 1) for entry in (root / 'environ').read_bytes().decode().split('\0')
               if '=' in entry)
    CHECK = 'process-sockets'
    sockets = set()
    for descriptor in (root / 'fd').iterdir():
        try:
            link = str(descriptor.readlink())
        except FileNotFoundError:
            continue
        if link.startswith('socket:['):
            sockets.add(link[8:-1])
    peers = []
    for table in ('tcp', 'tcp6'):
        for row in (root / 'net' / table).read_text().splitlines()[1:]:
            parts = row.split()
            if parts[9] not in sockets or parts[3] != '01':
                continue
            address, port = parts[2].split(':')
            words = [bytes.fromhex(address[i:i+8])[::-1] for i in range(0, len(address), 8)]
            remote = socket.inet_ntop(socket.AF_INET if table == 'tcp' else socket.AF_INET6, b''.join(words))
            peers.append({'address': remote, 'port': int(port, 16)})
    CHECK = 'process-executable'
    executable = digest(root / 'exe')
    CHECK = 'process-routing'
    route = routing(env)
    result = {'pid': pid, 'start_ticks': before, 'executable_sha256': executable,
              'routing': route, 'established_peers': sorted(peers, key=lambda p: (p['address'], p['port']))}
    CHECK = 'process-stability'
    after = (root / 'stat').read_text().rsplit(')', 1)[1].split()[19]
    if before != after:
        raise ValueError('process changed')
    return result


def probe():
    global CHECK, SERVICE
    CHECK, SERVICE = 'boot-identity', None
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    observations = []
    seen = set()
    for unit, (binary, env_path) in SERVICES.items():
        SERVICE = binary
        CHECK = 'loaded-service-properties'
        properties = command(['systemctl', 'show', unit, '--property=MainPID,InvocationID,ExecStart,Environment,EnvironmentFiles,DropInPaths,FragmentPath,ActiveState,NeedDaemonReload'])
        fields = {}
        for line in properties.splitlines():
            if '=' not in line:
                continue
            name, value = line.split('=', 1)
            # systemctl emits one EnvironmentFiles= line per file, including
            # repeated files. Preserve their order instead of keeping only last.
            if name == 'EnvironmentFiles' and name in fields:
                fields[name] += ' ' + value
            elif name in fields:
                raise ValueError('ambiguous loaded service property')
            else:
                fields[name] = value
        CHECK = 'service-active-and-reconciled'
        if fields.get('ActiveState') != 'active' or fields.get('NeedDaemonReload') != 'no':
            raise ValueError('service inactive or loaded unit differs from disk')
        CHECK = 'loaded-dropins'
        dropins = shlex.split(fields.get('DropInPaths', ''))
        directory = '/etc/systemd/system/' + unit + '.d/'
        expected_dropins = {directory + name for name in DROPINS} if binary == 'vmd' else set()
        permitted_extra = {directory + name for name in EXTRA_DROPINS} if binary == 'vmd' else set()
        if (not expected_dropins <= set(dropins) or not set(dropins) <= expected_dropins | permitted_extra
                or len(dropins) != len(set(dropins))):
            raise ValueError('unreviewed restart drop-in')
        extras = {Path(path).name for path in set(dropins) - expected_dropins}
        for name in extras:
            if Path(directory + name).read_bytes() != EXTRA_DROPINS[name].encode():
                raise ValueError('unreviewed restart drop-in contents')
        CHECK = 'loaded-environment'
        expected_files = [env_path, '/etc/sandbox/host-identity.env'] if binary == 'vmd' else [env_path]
        if 'identity.conf' in extras:
            expected_files.append('/etc/sandbox/host-identity.env')
        expected_file_tokens = [token for path in expected_files for token in (path, '(ignore_errors=no)')]
        expected_environment = {'HOST_IDENTITY_REQUIRED=1'} if binary == 'vmd' else set()
        for name in extras:
            expected_environment.update(line.removeprefix('Environment=') for line in EXTRA_DROPINS[name].splitlines()
                                        if line.startswith('Environment='))
        loaded_environment = shlex.split(fields.get('Environment', ''))
        if (shlex.split(fields.get('EnvironmentFiles', '')) != expected_file_tokens
                or set(loaded_environment) != expected_environment or len(loaded_environment) != len(expected_environment)):
            raise ValueError('loaded environment override')
        CHECK = 'main-process'
        pid = int(fields['MainPID'])
        if pid <= 0 or pid in seen:
            raise ValueError('service process ambiguous')
        seen.add(pid)
        CHECK = 'loaded-executable-command'
        expected = '/usr/local/bin/' + binary
        if (not re.search(r'path=' + re.escape(expected) + r'\s*;', fields['ExecStart'])
                or not re.search(r'argv\[\]=' + re.escape(expected) + r'\s*;', fields['ExecStart'])):
            raise ValueError('service executable changed')
        running = process(pid)
        CHECK = 'installed-executable-match'
        installed = digest(expected)
        if running['executable_sha256'] != installed:
            raise ValueError('installed and running executable differ')
        CHECK = 'restart-environment'
        restart_env = environment_file(env_path)
        CHECK = 'restart-routing'
        restart = routing(restart_env)
        CHECK = 'restart-destination-match'
        if restart['origin'] != running['routing']['origin']:
            raise ValueError('restart destination differs')
        # Full unit bytes are hashed locally, never emitted. Inline settings and
        # alternate files need explicit review, even if current process matches.
        CHECK = 'unit-restart-settings'
        unit_text = command(['systemctl', 'cat', unit])
        env_files = re.findall(r'^EnvironmentFile=(.*)$', unit_text, re.M)
        allowed = {env_path, '/etc/sandbox/host-identity.env'} if binary == 'vmd' else {env_path}
        if env_files != expected_files or re.search(r'^Environment=.*(?:CONTROL_PLANE_URL|PROXY)', unit_text, re.M):
            raise ValueError('restart routing override')
        CHECK = 'identity-routing-overrides'
        for path in allowed - {env_path}:
            identity = environment_file(path)
            if any('PROXY' in key.upper() or key == 'CONTROL_PLANE_URL' for key in identity):
                raise ValueError('identity file overrides routing')
        CHECK = 'unit-and-guard-hashes'
        observations.append({'service': unit, 'binary': binary, 'invocation': fields['InvocationID'],
                             'unit_sha256': digest(fields['FragmentPath']),
                             'dropins': {Path(path).name: digest(path) for path in dropins},
                             'guards': {guard: digest('/usr/local/bin/' + guard) for guard in DROPINS.values()
                                        if guard and binary == 'vmd'},
                             'installed_sha256': installed, 'restart_routing': restart, 'process': running})
    CHECK, SERVICE = 'additional-reporters', None
    unexpected = []
    for root in Path('/proc').iterdir():
        if not root.name.isdecimal() or int(root.name) in seen:
            continue
        try:
            name = (root / 'exe').readlink().name.removesuffix(' (deleted)')
        except FileNotFoundError:
            continue
        if name in {'vmd', 'agentbox-vmd', 'secretsproxy', 'controlplane'}:
            unexpected.append(int(root.name))
    CHECK = 'reporter-and-boot-stability'
    if unexpected or boot != Path('/proc/sys/kernel/random/boot_id').read_text().strip():
        raise ValueError('additional reporter or host restart')
    for observation in observations:
        SERVICE = observation['binary']
        again = process(observation['process']['pid'])
        # Ordinary request connections can change while the same process and
        # immutable routing configuration stay alive.
        CHECK = 'final-process-stability'
        if {k:v for k,v in again.items() if k != 'established_peers'} != {
                k:v for k,v in observation['process'].items() if k != 'established_peers'}:
            raise ValueError('process changed during observation')
    return {'schema': 1, 'boot_id': boot, 'services': observations,
            'additional_managed_reporters': []}


if __name__ == '__main__':
    try:
        print(json.dumps(probe(), sort_keys=True))
    except Exception as error:
        print(json.dumps(failure(error)))
        raise SystemExit(1)
