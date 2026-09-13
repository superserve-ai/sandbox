#!/usr/bin/env python3
"""Provision only the two canonical template bind mounts; never migrate data."""
import argparse
from pathlib import Path
import os
import subprocess

DATA = Path('/mnt/sandbox-data')
TREES = ('rundir', 'snapshots')
PREPARE = 'sandbox-template-storage.service'
MOUNTS = tuple(f'var-lib-sandbox-{tree}-templates.mount' for tree in TREES)
CHECKER = '/usr/local/sbin/sandbox-template-storage'
SYSTEMD_DIR = Path('/etc/systemd/system')


def run(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout.strip()


def mounted(path):
    if not Path(path).exists():
        return False
    result = subprocess.run(['mountpoint', '-q', str(path)])
    if result.returncode not in (0, 32):
        raise RuntimeError(f'cannot inspect mount point {path}')
    return result.returncode == 0


def paths(tree):
    return DATA / 'templates' / tree, Path('/var/lib/sandbox') / tree / 'templates'


def no_symlinks(path):
    for item in (path, *path.parents):
        if item.is_symlink():
            raise RuntimeError(f'refusing symlink in template storage path: {item}')


def check_data():
    no_symlinks(DATA)
    if not mounted(DATA) or run('findmnt', '-rn', '-M', str(DATA), '-o', 'FSTYPE') != 'xfs':
        raise RuntimeError('sandbox data must be mounted as XFS before template provisioning')
    if DATA.stat().st_dev == Path('/').stat().st_dev:
        raise RuntimeError('sandbox data resolves to the root filesystem')


def prepare():
    check_data()
    # Check both destinations before creating directories. Never hide root-disk
    # templates or reinterpret an existing mount as the requested mapping.
    for tree in TREES:
        source, target = paths(tree)
        no_symlinks(source)
        no_symlinks(target)
        if source.exists() and source.stat().st_dev != DATA.stat().st_dev:
            raise RuntimeError(f'{source} is not on the sandbox data filesystem')
        if mounted(target):
            if not source.exists() or not os.path.samefile(source, target):
                raise RuntimeError(f'{target} is mounted from an unexpected source')
        elif target.exists() and any(target.iterdir()):
            raise RuntimeError(f'{target} contains root/parent-backed data; drain and migrate explicitly')
    for tree in TREES:
        source, target = paths(tree)
        source.mkdir(parents=True, exist_ok=True)
        target.mkdir(parents=True, exist_ok=True)


def check():
    check_data()
    for tree in TREES:
        source, target = paths(tree)
        no_symlinks(source)
        no_symlinks(target)
        if source.exists() and source.stat().st_dev != DATA.stat().st_dev:
            raise RuntimeError(f'{source} is not on the sandbox data filesystem')
        if not mounted(target) or not source.exists() or not os.path.samefile(source, target):
            raise RuntimeError(f'{target} must be bind-mounted from {source}; refusing root-disk fallback')


def unit_files(data_service=False):
    # Existing staging mounts via a device-bound service; production can supply
    # the data mount through fstab/native units. The preparation check enforces
    # an actual separate XFS mount even when RequiresMountsFor finds no unit.
    dependency = 'Requires=sandbox-data.service\nAfter=sandbox-data.service\n' if data_service else ''
    units = {PREPARE: f'''[Unit]
Description=Validate and prepare sandbox template storage
RequiresMountsFor=/mnt/sandbox-data /var/lib/sandbox/rundir /var/lib/sandbox/snapshots
After=local-fs.target
{dependency}[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={CHECKER} prepare
'''}
    for tree, unit in zip(TREES, MOUNTS):
        source, target = paths(tree)
        units[unit] = f'''[Unit]
Description=Sandbox {tree} templates on data storage
DefaultDependencies=no
Conflicts=umount.target
Before=umount.target
Requires={PREPARE}
After={PREPARE}
RequiresMountsFor=/mnt/sandbox-data /var/lib/sandbox/{tree}
[Mount]
What={source}
Where={target}
Type=none
Options=bind
[Install]
WantedBy=multi-user.target
'''
    dependencies = ' '.join(MOUNTS)
    for unit in ('superserve-vmd.service', 'superserve-vmd.socket'):
        section = 'Service' if unit.endswith('.service') else 'Socket'
        # A late data-mount service may start after basic.target. Do not make
        # this socket hold sockets.target (and hence basic.target) waiting on it.
        late_socket = 'DefaultDependencies=no\nConflicts=shutdown.target\nBefore=shutdown.target\n' if section == 'Socket' else ''
        units[f'{unit}.d/40-template-storage.conf'] = f'''[Unit]
{late_socket}BindsTo={dependencies}
After={dependencies}
[{section}]
ExecStartPre={CHECKER} check
'''
    return units


def install():
    # Installation is an explicit enrollment operation, not a serving-host migration.
    for unit in ('superserve-vmd.service', 'superserve-vmd.socket', 'agentbox-vmd.service'):
        state = run('systemctl', 'show', '-p', 'ActiveState', '--value', unit)
        if state not in ('inactive', 'failed', ''):
            raise RuntimeError(f'stop/drain {unit} before template-storage enrollment')
    guests = subprocess.run(['pgrep', '-f', '^([^ ]*/)?(firecracker|template-builder)([[:space:]]|$)'])
    if guests.returncode != 1:
        raise RuntimeError('guest/build processes remain or cannot be inspected; drain before enrollment')
    prepare()
    destination = Path(CHECKER)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if Path(__file__).resolve() != destination:
        destination.write_bytes(Path(__file__).read_bytes())
    destination.chmod(0o755)
    state = run('systemctl', 'show', '-p', 'LoadState', '--value', 'sandbox-data.service')
    if state not in ('loaded', 'not-found'):
        raise RuntimeError('cannot determine sandbox-data.service ordering')
    for name, content in unit_files(state == 'loaded').items():
        path = SYSTEMD_DIR / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    run('systemctl', 'daemon-reload')
    # Re-run preparation even if a previous invocation remained active.
    run('systemctl', 'restart', PREPARE)
    run('systemctl', 'enable', *MOUNTS)
    run('systemctl', 'start', *MOUNTS)
    check()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('install', 'prepare', 'check'))
    args = parser.parse_args()
    try:
        globals()[args.action]()
    except (RuntimeError, OSError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f'template storage: {exc}\n')
