#!/usr/bin/env python3
"""Operator-only installation of provider-bound host identity; never starts VMD."""
import argparse
from contextlib import contextmanager
import json
import re
import shlex
import subprocess
import tempfile
import uuid
from pathlib import Path


KEY = 'sandbox-host-identity'
STATE = '/etc/sandbox/host-identity.json'
LOCK = '/run/lock/sandbox-host-identity.install'


@contextmanager
def installation_lock(ssh):
    # Atomic on the target VM, including installers on different operator machines.
    # A killed installer leaves the lock behind: investigate before removing it.
    ssh(f'sudo mkdir {LOCK}')
    try:
        yield
    finally:
        ssh(f'sudo rmdir {LOCK}')


def choose_identity(project, machine, slot, stored, legacy_host_id=None, reinstall=False):
    if stored:
        if stored['project_id'] != project or stored['instance_id'] != machine:
            raise ValueError('cloned machine metadata: do not reuse the accepted host identity')
        identity = dict(stored)
        if legacy_host_id and identity['host_id'] != legacy_host_id:
            raise ValueError('existing full host ID is immutable')
        if reinstall:
            identity['previous_incarnation_id'] = stored['incarnation_id']
            identity['incarnation_id'] = str(uuid.uuid4())
        return identity
    if reinstall:
        raise ValueError('reinstallation requires the existing provider identity record')
    if legacy_host_id:
        raise ValueError('legacy adoption requires the existing same-VM provider identity record')
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,180}', slot):
        raise ValueError('invalid host ID or regional slot')
    return dict(project_id=project, instance_id=machine,
                host_id=f'{slot}-{uuid.uuid4().hex}',
                incarnation_id=str(uuid.uuid4()))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('project', 'zone', 'instance', 'slot'):
        p.add_argument('--'+name, required=True)
    p.add_argument('--new-machine', action='store_true', help='attest this replacement/new VM has never registered a host ID')
    p.add_argument('--legacy-host-id', help='reuse a host ID from an existing same-VM provider identity record')
    p.add_argument('--reinstall', action='store_true', help='authorize new install identity after state loss or in-place rebuild')
    p.add_argument('--expected-incarnation', help='required with --reinstall; current provider-record incarnation')
    p.add_argument('--fencing-control-plane-ready', action='store_true', required=True,
                   help='attest all serving control planes enforce incarnation fencing')
    a = p.parse_args()
    flags = ['--project='+a.project, '--zone='+a.zone, '--quiet']

    def run(*args):
        return subprocess.run(['gcloud', *args], check=True, capture_output=True, text=True).stdout

    def describe():
        return json.loads(run('compute', 'instances', 'describe', a.instance, *flags, '--format=json'))

    def ssh(script):
        return run('compute', 'ssh', a.instance, *flags, '--tunnel-through-iap', '--command='+script)

    with installation_lock(ssh):
        machine = describe()
        items = {i['key']: i['value'] for i in machine.get('metadata', {}).get('items', [])}
        stored = json.loads(items[KEY]) if KEY in items else None
        resuming = bool(a.reinstall and stored and a.expected_incarnation and
                        a.expected_incarnation == stored.get('previous_incarnation_id'))
        if a.reinstall and (not stored or not resuming and a.expected_incarnation != stored['incarnation_id']):
            raise ValueError('reinstallation requires the expected current incarnation')
        local = ssh(f'if sudo test -f {STATE}; then sudo cat {STATE}; fi').strip()
        if stored and not local and not (a.reinstall or a.new_machine):
            raise ValueError('local state lost: explicit --reinstall and operator rebind required')
        if local and (not stored or json.loads(local) != stored):
            old_local = json.loads(local)
            if not (resuming and old_local.get('incarnation_id') == a.expected_incarnation and
                    all(old_local.get(key) == stored[key] for key in ('project_id', 'instance_id', 'host_id'))):
                raise ValueError('local/provider identity mismatch: investigate before installation')
        identity = choose_identity(a.project, str(machine['id']), a.slot, stored, a.legacy_host_id,
                                   a.reinstall and not resuming)
        if not stored and not a.new_machine:
            raise ValueError('initial install requires --new-machine')
        if a.new_machine or a.reinstall or identity.get('previous_incarnation_id'):
            for unit in ('superserve-vmd.service', 'superserve-vmd.socket'):
                state = ssh(f'systemctl show --property=ActiveState --value {unit}').strip()
                if state not in ('inactive', 'failed'):
                    raise ValueError(f'identity installation requires VMD stopped, including its socket: {unit} is {state!r}')
        # A never-registered new-machine retry reuses provider metadata after a
        # failed local install. Previously registered machines require reinstallation.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'identity.json'
            path.write_text(json.dumps(identity))
            run('compute', 'instances', 'add-metadata', a.instance, *flags,
                '--metadata-from-file='+KEY+'='+str(path))
        current = describe()
        if str(current['id']) != identity['instance_id']:
            raise ValueError('VM replaced during identity installation')
        current_items = {i['key']: i['value'] for i in current.get('metadata', {}).get('items', [])}
        if json.loads(current_items[KEY]) != identity:
            raise ValueError('concurrent identity installation; retry after investigating')
        payload = shlex.quote(json.dumps(identity))
        env = shlex.quote(f"HOST_ID={identity['host_id']}\nHOST_IDENTITY_FILE={STATE}\n")
        unit = shlex.quote('[Service]\nEnvironmentFile=/etc/sandbox/host-identity.env\n')
        ssh(f'''set -eu
sudo install -d -m 0755 /etc/sandbox /etc/systemd/system/superserve-vmd.service.d
printf '%s' {payload} | sudo tee {STATE}.new >/dev/null
sudo chmod 0600 {STATE}.new
sudo mv {STATE}.new {STATE}
printf '%s' {env} | sudo tee /etc/sandbox/host-identity.env >/dev/null
sudo chmod 0600 /etc/sandbox/host-identity.env
printf '%s' {unit} | sudo tee /etc/systemd/system/superserve-vmd.service.d/identity.conf >/dev/null
sudo sync
sudo systemctl daemon-reload
''')
        print(json.dumps(identity, indent=2))
        if identity.get('previous_incarnation_id'):
            print(f"Before restarting VMD: hostctl rebind {identity['host_id']} {identity['previous_incarnation_id']} {identity['incarnation_id']}")
        print('Identity installed; VMD was not restarted or activated.')


if __name__ == '__main__':
    main()
