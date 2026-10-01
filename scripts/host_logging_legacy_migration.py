#!/usr/bin/env python3
"""Reconcile the audited Ops Agent logging cutover without removing its package."""
import datetime
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys

STATE = Path('/var/lib/superserve/host-logging')
CONFIG = Path('/etc/google-cloud-ops-agent/config.yaml')
IDENTITY = Path('/etc/sandbox/host-identity.json')
SYSTEMD = Path('/etc/systemd/system')
LOGS = 'superserve-otel-logs.service'
HEARTBEAT = 'superserve-host-logging-heartbeat.timer'
EXPIRY = 'superserve-host-logging-overlap.timer'
OPS = 'google-cloud-ops-agent.service'


def control(*args, check=True):
    return subprocess.run(['systemctl', *args], check=check, capture_output=True).returncode == 0


def active(unit):
    return control('is-active', '--quiet', unit, check=False)


def atomic(path, content, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.candidate')
    tmp.write_text(content)
    tmp.chmod(mode)
    os.replace(tmp, path)


def expired(target):
    deadline = datetime.datetime.fromisoformat(target['deadline'].replace('Z', '+00:00'))
    now = datetime.datetime.now(datetime.timezone.utc)
    if deadline.tzinfo is None or deadline > now + datetime.timedelta(hours=24):
        raise ValueError('overlap deadline must be timezone-aware and within 24 hours')
    return deadline <= now


def stop_logs():
    control('disable', '--now', LOGS, HEARTBEAT, check=False)


def verify(target):
    phase = target['phase']
    if phase == 'preserve':
        if (STATE / 'legacy-retired.json').exists():
            raise ValueError('retired logging must be restored using rollback')
        return
    if phase not in {'overlap', 'verify', 'drain', 'retire', 'rollback'}:
        raise ValueError('unknown migration phase')
    if not isinstance(target['baseline'], str):
        raise ValueError('missing audited legacy configuration')
    instance = json.loads(IDENTITY.read_text())['instance_id']
    if instance not in target['instance_ids']:
        raise ValueError('migration evidence does not cover this instance')
    if phase == 'retire' and (instance not in target['verified_instance_ids'] or instance not in target['drained_instance_ids']):
        raise ValueError('missing receipt or drain evidence')
    snapshot = STATE / 'legacy-baseline.json'
    expected = {'baseline': target['baseline'], 'instance_id': instance, 'legacy_policy_name': target.get('legacy_policy_name')}
    if snapshot.exists() and json.loads(snapshot.read_text()) != expected:
        raise ValueError('migration baseline or instance changed; restore original migration first')
    if phase == 'retire' and not snapshot.exists():
        raise ValueError('retirement requires an established overlap baseline')
    if CONFIG.exists():
        if CONFIG.read_text() not in (target['baseline'], target['retired']):
            raise ValueError('legacy configuration differs from the audited baseline')
    elif phase not in {'overlap', 'rollback'} or instance not in target.get('initialize_instance_ids', []):
        raise ValueError('missing legacy configuration requires explicit instance initialization')
    if not active(OPS):
        raise ValueError('legacy agent must be healthy before migration')
    if phase in {'overlap', 'verify', 'drain'} and expired(target):
        raise ValueError('overlap expired; use rollback or retire with evidence')


def deadline_files(target):
    # The guard also prevents OTel restarting after the one-shot deadline fired.
    command = '/usr/bin/python3 /var/lib/superserve/host-logging/legacy-migration.py'
    calendar = datetime.datetime.fromisoformat(target["deadline"].replace("Z", "+00:00")).astimezone(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return {
        SYSTEMD / 'superserve-host-logging-overlap.service':
            f'[Unit]\nDescription=End bounded host logging overlap\n[Service]\nType=oneshot\nExecStart={command} --expire\n',
        SYSTEMD / EXPIRY:
            f'[Unit]\nDescription=Bound host logging overlap\n[Timer]\nOnCalendar={calendar}\nPersistent=true\nUnit=superserve-host-logging-overlap.service\n[Install]\nWantedBy=timers.target\n',
        SYSTEMD / (LOGS + '.d') / '40-legacy-migration.conf':
            f'[Service]\nExecStartPre={command} --guard\n',
    }


def converged(target):
    phase = target['phase']
    if phase in {'preserve', 'rollback'}:
        stopped = not active(LOGS) and not active(HEARTBEAT) and not active(EXPIRY)
        return stopped and (phase == 'preserve' or (CONFIG.read_text() if CONFIG.exists() else '') == target['baseline'])
    if phase == 'retire':
        return CONFIG.exists() and CONFIG.read_text() == target['retired'] and not active(EXPIRY)
    return (CONFIG.read_text() if CONFIG.exists() else '') == target['baseline'] and active(EXPIRY) and all(p.exists() and p.read_text() == content for p, content in deadline_files(target).items())


def set_legacy_config(content):
    old = CONFIG.read_text() if CONFIG.exists() else None
    if old == content:
        return
    if old is None:
        # Publish without replacing a configuration created after preflight.
        candidate = CONFIG.with_name(CONFIG.name + '.initialize')
        atomic(candidate, content)
        try:
            os.link(candidate, CONFIG)
        finally:
            candidate.unlink(missing_ok=True)
    else:
        atomic(CONFIG, content)
    try:
        control('restart', OPS)
        if not active(OPS):
            raise ValueError('Ops Agent failed to start')
    except Exception:
        if old is None:
            CONFIG.unlink(missing_ok=True)
        else:
            atomic(CONFIG, old)
        control('restart', OPS, check=False)
        raise


def enforce(target):
    phase = target['phase']
    if phase == 'preserve':
        stop_logs()
        control('disable', '--now', EXPIRY, check=False)
        return
    if phase == 'rollback':
        # Restore legacy first so rollback never deliberately removes both writers.
        set_legacy_config(target['baseline'])
        stop_logs()
        (STATE / 'legacy-retired.json').unlink(missing_ok=True)
        (STATE / 'legacy-baseline.json').unlink(missing_ok=True)
    elif phase == 'retire':
        if not active(LOGS):
            raise ValueError('OTel must be healthy before retiring legacy logging')
        atomic(STATE / 'legacy-retired.json', json.dumps({'baseline': target['baseline']}))
        set_legacy_config(target['retired'])
    else:
        if not CONFIG.exists():
            set_legacy_config(target['baseline'])
        if CONFIG.read_text() != target['baseline']:
            raise ValueError('restore legacy before entering overlap')
        snapshot = {'baseline': target['baseline'], 'instance_id': json.loads(IDENTITY.read_text())['instance_id'], 'legacy_policy_name': target.get('legacy_policy_name')}
        atomic(STATE / 'legacy-baseline.json', json.dumps(snapshot))
        for path, content in deadline_files(target).items():
            atomic(path, content, 0o644)
        control('daemon-reload')
        control('enable', '--now', EXPIRY)
        control('restart', EXPIRY)
        return
    control('disable', '--now', EXPIRY, check=False)
    for path in deadline_files(dict(target, deadline='1970-01-01T00:00:00Z')):
        path.unlink(missing_ok=True)
    control('daemon-reload')


def reconcile():
    target = json.loads((STATE / 'legacy-migration.json').read_text())
    action = sys.argv[1]
    if action == '--phase':
        print(target['phase'])
        return 0
    if action == '--expire':
        if target['phase'] in {'overlap', 'verify', 'drain'} and expired(target):
            stop_logs()
            if active(LOGS) or active(HEARTBEAT):
                raise ValueError('unable to stop expired overlap')
        return 0
    if action == '--guard':
        if target['phase'] in {'preserve', 'rollback'}:
            return 1
        if target['phase'] in {'overlap', 'verify', 'drain'} and expired(target):
            return 1
        return 0
    verify(target)
    if action == '--preflight':
        return 0
    if action == '--check':
        return 100 if converged(target) else 101
    if action != '--enforce':
        raise ValueError('unknown action')
    if not converged(target):
        enforce(target)
    return 100 if converged(target) else 1


def main():
    STATE.mkdir(parents=True, exist_ok=True)
    with (STATE / 'legacy-migration.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return reconcile()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
        # Audited configuration can contain credentials; never print config bodies.
        print(f'legacy migration failed: {type(exc).__name__}', file=sys.stderr)
        sys.exit(1)
