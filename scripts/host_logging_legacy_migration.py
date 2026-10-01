#!/usr/bin/env python3
"""Reconcile the audited Ops Agent logging cutover without removing its package."""
import datetime
import fcntl
import json
import math
import re
import time
import urllib.request
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
    if phase != 'rollback' and not active(OPS):
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
        return stopped and (phase == 'preserve' or ((CONFIG.read_text() if CONFIG.exists() else '') == target['baseline'] and active(OPS)))
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


def collector_invocation():
    result = subprocess.run(['systemctl', 'show', LOGS, '--property=InvocationID', '--value'], check=True, capture_output=True, text=True, timeout=2)
    value = result.stdout.strip()
    if not re.fullmatch(r'[0-9a-f]{32}', value):
        raise ValueError('collector invocation identity unavailable')
    return value


def read_export_metrics():
    names = {
        'otelcol_exporter_sent_log_records': 'sent',
        'otelcol_exporter_send_failed_log_records': 'failed',
        'otelcol_exporter_enqueue_failed_log_records': 'rejected',
        'otelcol_exporter_queue_size': 'queued',
        'otelcol_exporter_queue_capacity': 'capacity',
        'otelcol_exporter_in_flight_requests': 'inflight',
    }
    with urllib.request.urlopen('http://127.0.0.1:18888/metrics', timeout=2) as response:
        raw = response.read(1048577)
    if len(raw) > 1048576:
        raise ValueError('collector self-metrics exceed bound')
    values = {'failed': 0.0, 'rejected': 0.0}
    for line in raw.decode('utf-8').splitlines():
        match = re.fullmatch(r'(otelcol_exporter_[a-z_]+)\{([^}]+)\}\s+([0-9.eE+-]+)(?:\s+[0-9]+)?', line)
        if not match or not re.search(r'(?:^|,)\s*exporter="otlp_http/cloud"(?:,|$)', match[2]):
            continue
        name = match[1].removesuffix('_total')
        if name not in names:
            continue
        value = float(match[3])
        if not math.isfinite(value) or value < 0:
            raise ValueError('invalid collector metric')
        key = names[name]
        if key in values and key not in {'failed', 'rejected'}:
            raise ValueError('ambiguous collector metric')
        values[key] = value
    if not {'sent', 'queued', 'capacity', 'inflight'} <= values.keys() or values['capacity'] <= 0:
        raise ValueError('collector export metrics unavailable')
    return values


def assert_exporter_healthy():
    # Receipt evidence authorizes the change; this fresh check catches an outage
    # or saturated queue arising between evidence collection and host activation.
    invocation = collector_invocation()
    before = read_export_metrics()
    if before['queued'] >= before['capacity']:
        raise ValueError('collector export queue is full')
    subprocess.run(['systemctl', 'start', 'superserve-host-logging-heartbeat.service'], check=True, capture_output=True, timeout=2)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        time.sleep(1)
        current = read_export_metrics()
        if current['failed'] != before['failed'] or current['rejected'] != before['rejected'] or current['sent'] < before['sent']:
            raise ValueError('collector export failed during cutover check')
        if collector_invocation() != invocation or not active(LOGS):
            raise ValueError('collector restarted during cutover check')
        if current['sent'] > before['sent'] and current['queued'] == 0 and current['inflight'] == 0:
            return
    raise ValueError('collector did not acknowledge fresh logs before cutover')


def enforce(target):
    phase = target['phase']
    if phase == 'preserve':
        stop_logs()
        control('disable', '--now', EXPIRY, check=False)
        return
    if phase == 'rollback':
        # Restore legacy first so rollback never deliberately removes both writers.
        set_legacy_config(target['baseline'])
        if not active(OPS):
            control('restart', OPS)
        if not active(OPS):
            raise ValueError('legacy agent must be healthy before stopping OTel')
        stop_logs()
        (STATE / 'legacy-retired.json').unlink(missing_ok=True)
        (STATE / 'legacy-baseline.json').unlink(missing_ok=True)
    elif phase == 'retire':
        if not active(LOGS):
            raise ValueError('OTel must be healthy before retiring legacy logging')
        assert_exporter_healthy()
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
        if target['phase'] == 'preserve':
            return 1
        if target['phase'] == 'rollback':
            restored = CONFIG.exists() and CONFIG.read_text() == target['baseline'] and active(OPS)
            return 1 if restored else 0
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
