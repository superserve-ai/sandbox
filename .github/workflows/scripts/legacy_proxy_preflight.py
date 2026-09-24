#!/usr/bin/env python3
"""Refuse legacy proxy updates while a generation or advertisement needs recovery."""

import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import urllib.request


ROOT = Path('/var/lib/proxy-rollout')
LEGACY = dict(id='', unit='proxy.service', ports=dict(public=5007, redirect=5008, peer=5009, local=5010))


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def environment(path):
    values = {}
    for line in path.read_text().splitlines():
        if line and not line.startswith('#') and '=' in line:
            key, value = line.split('=', 1)
            tokens = shlex.split(value)
            values[key] = tokens[0] if tokens else ''
    return values


def check_state(root=ROOT, marker=Path('/run/proxy-generation-migration-hold')):
    if marker.exists():
        raise RuntimeError('Finish the active proxy migration before a legacy deployment')
    path = root / 'state.json'
    if path.exists():
        state = json.loads(path.read_text())
        active = state.get('active', {})
        if (state.get('phase') not in ('complete', 'rolled_back')
                or (state.get('bootstrap') and state.get('phase') != 'rolled_back')
                or state.get('_credential_recovery')
                or any(active.get(key) != value for key, value in LEGACY.items())):
            raise RuntimeError('Legacy deployment requires a completed rollback to proxy.service')
    private = root / 'private.json'
    if private.exists():
        active = json.loads(private.read_text())
        if any(active.get(key) != value for key, value in LEGACY.items()):
            raise RuntimeError('Private traffic still targets a proxy generation')
    units = command('systemctl', 'list-units', '--type=service', '--state=activating,active,deactivating',
                    '--no-legend', '--plain', 'proxy-*.service')
    if re.search(r'\bproxy-[0-9a-f]{20}\.service\b', units):
        raise RuntimeError('A proxy generation is still running')


def resolve_listener(requested, running, saved, ip):
    desired = ip + ':5009' if requested == 'auto' else requested
    if any(env.get('PEER_PROXY_LISTEN_ADDR', '') != desired for env in (running, saved)):
        raise RuntimeError('Peer advertisement must already match; proxy deployment cannot restart VMD')
    return desired


def main(requested, service):
    check_state()
    command('systemctl', 'is-active', service)
    pid = command('systemctl', 'show', '-p', 'MainPID', '--value', service)
    if not pid.isdecimal() or pid == '0':
        raise RuntimeError('VMD must be running')
    # Hosts predating managed identity retain their installed peer settings.
    if not Path('/etc/superserve/peer/identity.json').exists():
        return ''
    running = dict(entry.split('=', 1) for entry in Path('/proc', pid, 'environ').read_text().split('\0') if '=' in entry)
    saved = environment(Path('/etc/sandbox/vmd.env'))
    ip = ''
    if requested == 'auto':
        request = urllib.request.Request(
            'http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/ip',
            headers={'Metadata-Flavor': 'Google'})
        ip = urllib.request.urlopen(request, timeout=5).read().decode()
    return resolve_listener(requested, running, saved, ip)


if __name__ == '__main__':
    print(main(*sys.argv[1:]))
