#!/usr/bin/env python3
"""One bounded staging-only, same-image rollup pause with mandatory restoration."""
import argparse
import copy
import datetime as dt
import json
import os
from pathlib import Path
import time
from urllib.request import urlopen

import staging_rollup_diagnostic as diagnostic
from collect_recovery_evidence import Reader

PROJECT, REGION, SERVICE = diagnostic.PROJECT, diagnostic.REGION, diagnostic.SERVICE
FLAG = 'BILLING_HOURLY_ROLLUP_DISABLED'
# This immutable executable was audited to suppress only the hourly service.
IMAGE = 'us-central1-docker.pkg.dev/rayai-dev/superserve/controlplane@sha256:3b5b4855bd5632fc2fa4494a4b7b34e95dcc283fedebe398f8414f0ef46d6702'
BASELINE = Path('staging-rollup-private-baseline.json')
RESULT = Path('staging-rollup-pause/result.json')


def require(value, reason):
    if not value:
        raise diagnostic.DiagnosticError(reason)


def gate(reader):
    env = os.environ
    require(env.get('ROLLUP_PAUSE') == 'true' and env.get('ROLLUP_PAUSE_ACK') == 'accepted'
            and env.get('ROLLUP_DIAGNOSTIC') == 'false', 'pause_acknowledgment_required')
    return diagnostic.check_dispatch(reader, dict(env, ROLLUP_DIAGNOSTIC='true'))


def service(reader):
    return diagnostic.cloud(reader, 'run', 'services', 'describe', SERVICE, '--region='+REGION)


def revisions(reader):
    rows = diagnostic.cloud(reader, 'run', 'revisions', 'list', '--service='+SERVICE,
                            '--region='+REGION, '--limit=1000')
    require(isinstance(rows, list) and len(rows) < 1000, 'revision_inventory_incomplete')
    return rows


def retired(row):
    return row['metadata'].get('generation') == row['status'].get('observedGeneration') and any(
        c.get('type') == 'Active' and c.get('status') == 'False' and c.get('reason') == 'Retired'
        for c in row['status'].get('conditions', []))


def canonical(value):
    template = copy.deepcopy(value['spec']['template'])
    template['metadata'].pop('name', None)
    annotations = template['metadata'].get('annotations', {})
    for key in ('run.googleapis.com/client-name', 'run.googleapis.com/client-version'):
        annotations.pop(key, None)
    template['metadata'].get('labels', {}).pop('client.knative.dev/nonce', None)
    containers = template['spec']['containers']
    require(len(containers) == 1, 'unexpected_sidecar')
    containers[0]['image'] = IMAGE
    containers[0]['env'] = sorted((e for e in containers[0].get('env', []) if e['name'] != FLAG), key=lambda e: e['name'])
    annotations = {k: v for k, v in value['metadata'].get('annotations', {}).items()
                   if k not in ('run.googleapis.com/client-name', 'run.googleapis.com/client-version',
                                'run.googleapis.com/operation-id', 'serving.knative.dev/lastModifier')}
    return {'template': template, 'service_annotations': annotations}


def same_configuration(value, original):
    image = value['spec']['template']['spec']['containers'][0]['image']
    original_image = original['spec']['template']['spec']['containers'][0]['image']
    return image in (IMAGE, original_image) and canonical(value) == canonical(original)


def flag(value):
    entries = [e for e in value['spec']['template']['spec']['containers'][0].get('env', []) if e['name'] == FLAG]
    require(len(entries) <= 1 and (not entries or set(entries[0]) == {'name', 'value'}), 'flag_not_literal')
    return entries[0]['value'] if entries else None


def ready(value, expected):
    return (value['metadata'].get('generation') == value['status'].get('observedGeneration')
            and value['status'].get('latestReadyRevisionName') == expected
            and value['status'].get('latestCreatedRevisionName') == expected
            and any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in value['status'].get('conditions', [])))


def route_is(value, revision):
    traffic = value['status'].get('traffic', [])
    return len(traffic) == 1 and traffic[0].get('percent') == 100 and traffic[0].get('revisionName') == revision and not traffic[0].get('tag')


def mutate(reader, *args):
    # The only mutable target is the fixed staging service. No SQL mutation.
    return json.loads(diagnostic.command(reader, ['gcloud', 'run', 'services', *args,
        '--project='+PROJECT, '--region='+REGION, '--format=json', '--quiet'], timeout=120))


def wait_ready(reader, expected, original, desired_flag):
    for _ in range(30):
        current = service(reader)
        require(same_configuration(current, original) and flag(current) == desired_flag, 'configuration_drift')
        if ready(current, expected):
            return current
        time.sleep(2)
    raise diagnostic.DiagnosticError('revision_readiness_timeout')


def change(reader, original, desired_flag, suffix):
    current = service(reader)
    require(same_configuration(current, original), 'configuration_drift_before_update')
    option = '--remove-env-vars='+FLAG if desired_flag is None else '--update-env-vars='+FLAG+'='+desired_flag
    mutate(reader, 'update', SERVICE, '--image='+IMAGE, '--no-traffic', '--revision-suffix='+suffix, option)
    expected = SERVICE+'-'+suffix
    wait_ready(reader, expected, original, desired_flag)
    mutate(reader, 'update-traffic', SERVICE, '--to-revisions='+expected+'=100')
    current = service(reader)
    require(route_is(current, expected) and same_configuration(current, original), 'traffic_transition_failed')
    with urlopen(current['status']['url']+'/health', timeout=15) as response:
        require(response.status == 200, 'serving_health_failed')
    return expected


def restore(reader, saved, result):
    original = saved['service']
    result['restore_started_at'] = diagnostic.utc()
    restored = change(reader, original, saved['flag'], saved['restore_suffix'])
    # Re-establish the original latest-tracking traffic semantics only after
    # checking that latest names this exact restoration revision.
    current = service(reader)
    require(ready(current, restored), 'restoration_revision_changed')
    mutate(reader, 'update-traffic', SERVICE, '--to-latest')
    current = service(reader)
    require(route_is(current, restored) and flag(current) == saved['flag']
            and same_configuration(current, original)
            and current['spec'].get('traffic') == original['spec'].get('traffic'), 'restoration_mismatch')
    result.update(restored=True, restored_revision=restored, restored_at=diagnostic.utc())


def write_result(result):
    RESULT.parent.mkdir(parents=True, exist_ok=True)
    RESULT.write_text(json.dumps(result, sort_keys=True)+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-dispatch', action='store_true')
    parser.add_argument('--restore', action='store_true')
    args = parser.parse_args()
    reader = Reader(time.monotonic()+360)
    result = {'kind': 'staging-rollup-pause', 'production_evidence': False, 'restored': False,
              'status': 'failed', 'started_at': diagnostic.utc(), 'image': IMAGE,
              'catchup_verified': False, 'catchup_limit': 'Affected-hour equality must be checked after the hour closes; no pause is extended for this check'}
    mutated = False
    saved = None
    try:
        result['revision'] = gate(reader)
        require(os.environ.get('GCP_PROJECT') == PROJECT, 'staging_project_required')
        if args.check_dispatch:
            return 0
        if args.restore:
            if not BASELINE.exists():
                return 0
            result = json.loads(RESULT.read_text()) if RESULT.exists() else result
            if result.get('restored'):
                return 0
            saved = json.loads(BASELINE.read_text())
            if not saved.get('mutation_started'):
                return 0
            restore(reader, saved, result)
            return 0
        original = service(reader)
        rows = revisions(reader)
        serving = original['status'].get('latestReadyRevisionName')
        require(ready(original, serving) and route_is(original, serving)
                and original['spec'].get('traffic') == [{'latestRevision': True, 'percent': 100}], 'ambiguous_baseline_traffic')
        require(all(r['status'].get('imageDigest') == IMAGE for r in rows if r['metadata']['name'] == serving), 'unaudited_serving_image')
        require(sum(r['metadata']['name'] == serving for r in rows) == 1, 'missing_serving_revision')
        require(all(r['metadata']['name'] == serving or retired(r) for r in rows), 'unknown_old_worker_revision')
        require(flag(original) not in ('true', '1'), 'rollups_already_disabled')
        scaling = diagnostic.safe_scaling(original)
        require(scaling['run.googleapis.com/scalingMode']['presence'] == 'absent'
                and scaling['run.googleapis.com/manualInstanceCount']['presence'] == 'absent', 'manual_allocation_unknown')
        run = os.environ['GITHUB_RUN_ID']
        saved = {'service': original, 'flag': flag(original), 'restore_suffix': 'rr'+run,
                 'baseline_revision': serving, 'pause_suffix': 'rp'+run}
        BASELINE.write_text(json.dumps(saved)); BASELINE.chmod(0o600)
        result['before'] = diagnostic.database(reader)
        require(result['before']['status'] == 'observed', 'database_baseline_incomplete')
        result['baseline_revision'] = serving
        result['restoration_deadline'] = (dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=10)).isoformat()
        write_result(result)
        saved['mutation_started'] = True
        BASELINE.write_text(json.dumps(saved))
        mutated = True
        paused = change(reader, original, 'true', saved['pause_suffix'])
        result.update(paused_revision=paused, pause_routed_at=diagnostic.utc())
        # Four minutes bounds retirement/telemetry lag; no recovery runs here.
        stop = min(reader.deadline-30, time.monotonic()+240)
        while time.monotonic() < stop:
            current = service(reader)
            require(route_is(current, paused) and flag(current) == 'true'
                    and same_configuration(current, original), 'pause_configuration_drift')
            live = revisions(reader)
            require({r['metadata']['name'] for r in live} == {r['metadata']['name'] for r in rows}|{paused}, 'revision_inventory_changed')
            old = [r for r in live if r['metadata']['name'] != paused]
            if all(retired(r) for r in old):
                observed = diagnostic.database(reader)
                activity = observed.get('activity', {})
                jobs = observed.get('observations', {}).get('billing_rollup_job', {}).get('aggregate', {})
                lease = observed.get('observations', {}).get('billing_rollup_scheduler_lease', {}).get('aggregate', {})
                require(activity.get('query_text_visibility') and activity.get('unclassified_hidden') == 0, 'database_activity_visibility_incomplete')
                if activity.get('rollup_related_active') == 0 and jobs.get('running') == 0 and lease.get('unexpired') == 0:
                    result.update(drain_proven=True, drain_at=diagnostic.utc(), during=observed)
                    break
            time.sleep(10)
        require(result.get('drain_proven'), 'drain_timeout')
        result['status'] = 'pause_and_drain_observed'
    except Exception as error:
        result['reason'] = diagnostic.diagnostic_category(error)
    finally:
        if mutated and saved:
            try:
                restore(Reader(time.monotonic()+240), saved, result)
                result['after'] = diagnostic.database(Reader(time.monotonic()+90))
            except Exception as error:
                result['restore_error'] = diagnostic.diagnostic_category(error)
        if not args.check_dispatch:
            write_result(result)
    print(json.dumps({k: result.get(k) for k in ('status', 'drain_proven', 'restored', 'reason', 'restore_error')}))
    return 0 if result.get('restored') and result.get('drain_proven') else 1


if __name__ == '__main__':
    raise SystemExit(main())
