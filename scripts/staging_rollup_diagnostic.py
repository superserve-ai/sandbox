#!/usr/bin/env python3
"""Bounded read-only staging readiness; never authorizes a pause or proves drain."""

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, parse_qsl, unquote
from urllib.request import Request, urlopen

from collect_recovery_evidence import Reader
from recovery_database_binding import matches_project
from migrate_database import PROJECTS
from staging_receiver_diagnostic import check_dispatch as receiver_check_dispatch

PROJECT = 'rayai-dev'
REGION = 'us-central1'
SERVICE = 'superserve-api'
SETTINGS = (
    'BILLING_HOURLY_ROLLUP_DISABLED', 'BILLING_HOURLY_ROLLUP_INTERVAL',
    'BILLING_HOURLY_ROLLUP_WORKER_POLL', 'BILLING_HOURLY_ROLLUP_LOCK_DURATION',
    'BILLING_HOURLY_ROLLUP_LEASE_DURATION', 'BILLING_HOURLY_ROLLUP_MAX_ATTEMPTS',
    'BILLING_HOURLY_ROLLUP_LOOKBACK_HOURS', 'BILLING_HOURLY_ROLLUP_WORKERS',
    'BILLING_HOURLY_ROLLUP_BACKFILL_LOOKBACK_HOURS',
    'BILLING_HOURLY_ROLLUP_BACKFILL_BATCH_HOURS', 'BILLING_HOURLY_ROLLUP_BATCH_SIZE',
)
TABLES = {
    'billing_rollup_scheduler_lease', 'billing_rollup_job',
    'sandbox_compute_billing_interval', 'sandbox_storage_interval',
    'team_billing_usage_hourly', 'billing_export_measurement_queue',
}


def check_dispatch(reader, env):
    if env.get('ROLLUP_DIAGNOSTIC') != 'true' or env.get('RECEIVER_DIAGNOSTIC') != 'false':
        raise ValueError('rollup diagnostic isolation required')
    return receiver_check_dispatch(reader, dict(env, RECEIVER_DIAGNOSTIC='true'))


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


class DiagnosticError(Exception):
    """Carries only a fixed, non-sensitive failure category."""


def diagnostic_category(error):
    if isinstance(error, DiagnosticError):
        return error.args[0]
    if isinstance(error, HTTPError):
        return 'http_'+str(int(error.code))
    if isinstance(error, (subprocess.TimeoutExpired, TimeoutError)):
        return 'timeout'
    if isinstance(error, FileNotFoundError):
        return 'command_unavailable'
    if isinstance(error, json.JSONDecodeError):
        return 'output_parse_failed'
    if isinstance(error, (URLError, ConnectionError)):
        return 'network_unavailable'
    return 'observation_unavailable'


def classify_stderr(stderr):
    # Match locally; never serialize provider diagnostics or their arguments.
    text = stderr.lower()
    patterns = (
        ('unsupported startup parameter', 'unsupported_startup_parameter'),
        ('invalid uri query parameter', 'invalid_uri_query_parameter'),
        ('tenant or user not found', 'database_tenant_or_user_not_found'),
        ('password authentication failed', 'database_authentication_failed'),
        ('permission denied', 'permission_denied'),
        ('permission_denied', 'permission_denied'),
        ('does not have permission', 'permission_denied'),
        ('insufficient privilege', 'permission_denied'),
        ('access denied', 'permission_denied'),
        ('unrecognized arguments', 'command_arguments_rejected'),
        ('invalid choice', 'command_arguments_rejected'),
        ('network is unreachable', 'network_unreachable'),
        ('could not translate host name', 'hostname_resolution_failed'),
        ('name or service not known', 'hostname_resolution_failed'),
        ('connection refused', 'connection_refused'),
        ('connection timed out', 'connection_timeout'),
        ('timeout', 'timeout'),
        ('timed out', 'timeout'),
        ('does not exist', 'database_object_missing'),
        ('invalid connection option', 'invalid_connection_option'),
        ('invalid uri', 'invalid_connection_uri'),
    )
    state = re.search(r'error:\s+([0-9A-Z]{5})(?:\s|$)', stderr)
    if state:
        return 'postgres_sqlstate_'+state.group(1)
    return next((category for needle, category in patterns if needle in text), 'command_failed')


def command(reader, args, *, env=None, timeout=60, reject_stderr=False):
    remaining = reader.deadline-time.monotonic()
    if remaining <= 0:
        raise DiagnosticError('collection_deadline_expired')
    try:
        result = subprocess.run(args, env=env, capture_output=True, text=True,
                                timeout=min(timeout, remaining))
    except FileNotFoundError:
        raise DiagnosticError('psql_unavailable' if args[0] == 'psql' else 'gcloud_unavailable') from None
    if result.returncode:
        raise DiagnosticError(classify_stderr(result.stderr))
    if reject_stderr and result.stderr:
        category = classify_stderr(result.stderr)
        raise DiagnosticError(category if category != 'command_failed' else 'provider_warning_completeness_unknown')
    if len(result.stdout) > 16_000_000:
        raise DiagnosticError('output_bound_exceeded')
    return result.stdout


def cloud(reader, *args):
    env = dict(os.environ, CLOUDSDK_CORE_LOG_HTTP='false', CLOUDSDK_CORE_DISABLE_FILE_LOGGING='true',
               CLOUDSDK_COMPUTE_ALLOW_PARTIAL_ERROR='false')
    return json.loads(command(reader, ['gcloud', *args, '--project='+PROJECT,
                                      '--format=json', '--quiet', '--verbosity=warning'],
                              env=env, reject_stderr=True))


def safe_scaling(resource):
    annotations = resource.get('metadata', {}).get('annotations', {})
    result = {}
    for key in ('run.googleapis.com/minScale', 'run.googleapis.com/maxScale',
                'autoscaling.knative.dev/minScale', 'autoscaling.knative.dev/maxScale',
                'run.googleapis.com/scalingMode', 'run.googleapis.com/manualInstanceCount'):
        if key not in annotations:
            result[key] = {'presence': 'absent'}
        elif re.fullmatch(r'(?:[0-9]{1,9}|automatic|manual)', str(annotations[key])):
            result[key] = {'presence': 'literal', 'value': str(annotations[key])}
        else:
            result[key] = {'presence': 'unrecognized', 'value': None}
    return result


def safe_settings(container):
    env = {item['name']: item for item in container.get('env', [])}
    result = {}
    for name in SETTINGS:
        item = env.get(name)
        if item is None:
            result[name] = {'presence': 'absent'}
        elif 'value' in item and re.fullmatch(r'[A-Za-z0-9.+-]{0,40}', str(item['value'])):
            result[name] = {'presence': 'literal', 'value': item['value']}
        else:
            result[name] = {'presence': 'reference_or_unrecognized', 'value': None}
    return result


def service_baseline(reader):
    service = cloud(reader, 'run', 'services', 'describe', SERVICE, '--region='+REGION)
    revisions = cloud(reader, 'run', 'revisions', 'list', '--service='+SERVICE,
                      '--region='+REGION, '--limit=1000')
    if not isinstance(revisions, list) or len(revisions) >= 1000:
        raise ValueError('incomplete revision inventory')
    summaries = []
    for revision in revisions:
        status = revision.get('status', {})
        spec = revision.get('spec', {})
        containers = spec.get('containers', [])
        image = status.get('imageDigest', '')
        # Only immutable container references leave this process.
        immutable = image if re.fullmatch(r'[A-Za-z0-9./_:-]+@sha256:[a-f0-9]{64}', image) else None
        summaries.append({'revision': revision['metadata']['name'], 'immutable_image': immutable,
                          'config_sha256': digest({'spec': spec, 'annotations': revision.get('metadata', {}).get('annotations', {})}),
                          'scaling_annotations': safe_scaling(revision), 'container_count': len(containers),
                          'generation': revision.get('metadata', {}).get('generation'),
                          'observed_generation': status.get('observedGeneration'),
                          'created_at': revision.get('metadata', {}).get('creationTimestamp'),
                          'conditions': [{k: c[k] for k in ('type', 'status', 'reason', 'lastTransitionTime') if k in c}
                                         for c in status.get('conditions', [])],
                          'rollup_settings': safe_settings(containers[0]) if len(containers) == 1 else None,
                          'ready': next((c.get('status') for c in status.get('conditions', [])
                                         if c.get('type') == 'Ready'), None)})
    return {'status': 'observed',
            'config_sha256': digest({'spec': service.get('spec', {}), 'annotations': service.get('metadata', {}).get('annotations', {})}),
            'service_scaling_annotations': safe_scaling(service),
            'generation': service.get('metadata', {}).get('generation'),
            'observed_generation': service.get('status', {}).get('observedGeneration'),
            'desired_traffic': [{k: t[k] for k in ('revisionName', 'percent', 'latestRevision', 'tag') if k in t}
                                for t in service.get('spec', {}).get('traffic', [])],
            'template_scaling_annotations': safe_scaling(service.get('spec', {}).get('template', {})),
            'latest_ready_revision': service.get('status', {}).get('latestReadyRevisionName'),
            'traffic': [{k: t[k] for k in ('revisionName', 'percent', 'latestRevision', 'tag') if k in t}
                        for t in service.get('status', {}).get('traffic', [])],
            'revisions': summaries, 'source_provenance': 'unknown',
            'switch_support': 'unknown_until_serving_image_source_verified'}


def monitoring(reader, started, ended):
    token = command(reader, ['gcloud', 'auth', 'print-access-token'], env=dict(
        os.environ, CLOUDSDK_CORE_LOG_HTTP='false', CLOUDSDK_CORE_DISABLE_FILE_LOGGING='true')).strip()
    query = {'filter': 'metric.type="run.googleapis.com/container/instance_count" '
                       'AND resource.type="cloud_run_revision" '
                       'AND resource.labels.service_name="'+SERVICE+'" '
                       'AND resource.labels.location="'+REGION+'"',
             'interval.startTime': started, 'interval.endTime': ended, 'pageSize': '1000', 'view': 'FULL'}
    observations = []
    for _ in range(10):
        request = Request('https://monitoring.googleapis.com/v3/projects/'+PROJECT+'/timeSeries?'+urlencode(query),
                          headers={'Authorization': 'Bearer '+token})
        remaining = reader.deadline-time.monotonic()
        if remaining <= 0:
            raise ValueError('deadline')
        with urlopen(request, timeout=min(20, remaining)) as response:
            body = response.read(2_000_001)
        if len(body) > 2_000_000:
            raise ValueError('monitoring output bound')
        payload = json.loads(body)
        for series in payload.get('timeSeries', []):
            points = series.get('points', [])
            if not points:
                continue
            latest = max(points, key=lambda p: p.get('interval', {}).get('endTime', ''))
            observations.append({'revision': series.get('resource', {}).get('labels', {}).get('revision_name'),
                                 'state': series.get('metric', {}).get('labels', {}).get('state', 'unknown'),
                                 'sample_end': latest.get('interval', {}).get('endTime'),
                                 'value': latest.get('value', {})})
        next_page = payload.get('nextPageToken')
        if not next_page:
            return {'status': 'observed' if observations else 'unknown_no_samples',
                    'window_start': started, 'window_end': ended, 'series': observations,
                    'drain_proven': False,
                    'limitation': 'Delayed sampled telemetry; absent series are unknown, not zero instances'}
        query['pageToken'] = next_page
    raise ValueError('monitoring pagination bound')


def logging(reader, started):
    messages = ('billing hourly rollup service starting',
                'billing hourly rollup worker disabled (BILLING_HOURLY_ROLLUP_DISABLED set)',
                'shutdown signal received', 'shutting down HTTP server')
    predicate = ('resource.type="cloud_run_revision" AND resource.labels.service_name="'+SERVICE+
                 '" AND resource.labels.location="'+REGION+'" AND timestamp>="'+started+'" AND ('+
                 ' OR '.join('jsonPayload.message="'+m+'"' for m in messages)+')')
    rows = cloud(reader, 'logging', 'read', predicate, '--limit=500', '--order=desc')
    if not isinstance(rows, list) or len(rows) >= 500:
        raise ValueError('logging completeness bound')
    counts = {}
    for row in rows:
        message = row.get('jsonPayload', {}).get('message')
        if message not in messages:
            continue
        revision = row.get('resource', {}).get('labels', {}).get('revision_name', 'unknown')
        key = (revision, message)
        counts[key] = counts.get(key, 0)+1
    return {'status': 'observed' if rows else 'unknown_no_matching_logs', 'window_start': started,
            'events': [{'revision': r, 'event': m, 'count': n} for (r, m), n in sorted(counts.items())],
            'limitation': 'Log absence does not prove process absence or full background drain'}


def sql(reader, statement):
    remaining = reader.deadline-time.monotonic()
    if remaining <= 0:
        raise ValueError('deadline')
    value = os.environ.get('DATABASE_URL', '')
    try:
        matches_project(value, PROJECTS['staging'])
    except Exception:
        raise DiagnosticError('staging_database_identity_unverified') from None
    url = urlsplit(value)
    env = {key: value for key, value in os.environ.items()
           if not key.startswith('PG') and key != 'DATABASE_URL'}
    env.update(PGHOST=url.hostname, PGPORT=str(url.port or 5432),
               PGUSER=unquote(url.username), PGPASSWORD=unquote(url.password),
               PGDATABASE='postgres', PGCONNECT_TIMEOUT='10', PGOPTIONS='')
    names = {'sslmode': 'PGSSLMODE', 'application_name': 'PGAPPNAME'}
    for key, value in parse_qsl(url.query):
        if key in names:
            env[names[key]] = value
    output = command(reader, ['psql', '-XqAt', '-v', 'ON_ERROR_STOP=1', '-v', 'VERBOSITY=sqlstate', '-c',
                             "BEGIN READ ONLY; SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='250ms'; "
                             +statement+'; COMMIT;'], env=env, timeout=25)
    return json.loads(output)


def database(reader):
    if not os.environ.get('DATABASE_URL'):
        return {'status': 'unknown', 'reason': 'staging_database_not_configured'}
    columns = sql(reader, "SELECT coalesce(json_object_agg(table_name, names),'{}'::json) FROM "
                  "(SELECT table_name, json_agg(column_name) names FROM information_schema.columns "
                  "WHERE table_schema='public' AND table_name IN ("+
                  ','.join("'"+t+"'" for t in sorted(TABLES))+") GROUP BY table_name) c")
    result = {'status': 'observed', 'tables': columns, 'observations': {}}
    queries = {
        'billing_rollup_scheduler_lease': ({'locked_until', 'updated_at', 'locked_by'},
            "json_build_object('leases',count(*),'unexpired',count(*) FILTER (WHERE locked_until>now()),"
            "'distinct_owners',count(DISTINCT locked_by),'latest_update',max(updated_at),'latest_expiry',max(locked_until))"),
        'billing_rollup_job': ({'status','attempt_count','locked_until','hour_start','updated_at'},
            "json_build_object('total',count(*),'pending',count(*) FILTER (WHERE status='pending'),"
            "'running',count(*) FILTER (WHERE status='running'),'failed',count(*) FILTER (WHERE status='failed'),"
            "'completed',count(*) FILTER (WHERE status='completed'),"
            "'attempts_ge_default_five',count(*) FILTER (WHERE attempt_count>=5 AND status<>'completed'),"
            "'expired_running',count(*) FILTER (WHERE status='running' AND locked_until<now()),"
            "'oldest_unfinished_hour',min(hour_start) FILTER (WHERE status<>'completed'),'latest_update',max(updated_at))"),
        'team_billing_usage_hourly': ({'hour_start','updated_at'},
            "json_build_object('rows',count(*),'latest_hour',max(hour_start),'latest_update',max(updated_at),"
            "'updates_last_5m',count(*) FILTER (WHERE updated_at>now()-interval '5 minutes'))"),
        'billing_export_measurement_queue': ({'pending'},
            "json_build_object('rows',count(*),'pending',count(*) FILTER (WHERE pending))"),
    }
    for table in ('sandbox_compute_billing_interval', 'sandbox_storage_interval'):
        queries[table] = ({'started_at', 'ended_at'},
            "json_build_object('rows',count(*),'open',count(*) FILTER (WHERE ended_at IS NULL),"
            "'latest_start',max(started_at),'latest_end',max(ended_at),"
            "'starts_last_5m',count(*) FILTER (WHERE started_at>now()-interval '5 minutes'),"
            "'ends_last_5m',count(*) FILTER (WHERE ended_at>now()-interval '5 minutes'))")
    for table, (required, expression) in queries.items():
        if not required.issubset(set(columns.get(table, []))):
            result['observations'][table] = {'status': 'unknown_missing_columns'}
            continue
        try:
            result['observations'][table] = {'status': 'observed', 'aggregate': sql(reader,
                'SELECT '+expression+' FROM public.'+table)}
        except Exception as error:
            result['observations'][table] = {'status': 'unknown_query_unavailable', 'reason': diagnostic_category(error)}
    try:
        result['activity'] = sql(reader, "SELECT json_build_object('query_text_visibility',"
            "(SELECT rolsuper OR pg_has_role(current_user,'pg_read_all_stats','MEMBER') FROM pg_roles WHERE rolname=current_user),"
            "'active_sessions',count(*) FILTER (WHERE state='active'),"
            "'rollup_related_active',count(*) FILTER (WHERE state='active' AND query ~* 'billing_rollup|team_billing_usage_hourly'),"
            "'unclassified_hidden',count(*) FILTER (WHERE query='<insufficient privilege>'),"
            "'oldest_rollup_query',min(query_start) FILTER (WHERE state='active' AND query ~* 'billing_rollup|team_billing_usage_hourly')) "
            "FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()")
    except Exception as error:
        result['activity'] = {'status': 'unknown_query_unavailable', 'reason': diagnostic_category(error)}
    if any(item.get('status') != 'observed' for item in result['observations'].values()) or result['activity'].get('status') == 'unknown_query_unavailable':
        result['status'] = 'partial'
    result['active_usage_proven'] = False
    result['limitation'] = 'Aggregate snapshots do not establish fixture ownership, continuous raw recording, or fixed-window catchup equality'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-dispatch', action='store_true')
    args = parser.parse_args()
    reader = Reader(time.monotonic()+300)
    result = {'schema': 1, 'kind': 'staging-rollup-readiness', 'project': PROJECT, 'region': REGION,
              'service': SERVICE, 'production_evidence': False, 'pause_authorized_by_diagnostic': False,
              'status': 'failed', 'observed_at': utc(), 'capabilities': {}}
    try:
        result['revision'] = check_dispatch(reader, os.environ)
        if os.environ.get('GCP_PROJECT') != PROJECT:
            raise ValueError('staging project required')
        if args.check_dispatch:
            return 0
        ended = dt.datetime.now(dt.timezone.utc)
        started = (ended-dt.timedelta(minutes=15)).isoformat()
        for name, operation in (
            ('service', lambda: service_baseline(reader)),
            ('monitoring', lambda: monitoring(reader, started, ended.isoformat())),
            ('logging', lambda: logging(reader, started)),
            ('database', lambda: database(reader)),
        ):
            try:
                result[name] = operation()
                result['capabilities'][name] = result[name].get('status', 'observed')
            except Exception as error:
                result[name] = {'status': 'unknown', 'reason': diagnostic_category(error)}
                result['capabilities'][name] = 'unknown'
        result['status'] = 'observed' if all(v == 'observed' for v in result['capabilities'].values()) else 'partial'
    except Exception:
        result['reason'] = 'Staging dispatch gate failed; diagnostics suppressed'
    if not args.check_dispatch:
        path = Path('staging-rollup-diagnostic/result.json')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, sort_keys=True)+'\n')
    print(json.dumps({'status': result['status'], 'capabilities': result['capabilities']}))
    return 0 if result['status'] in ('observed', 'partial') else 1


if __name__ == '__main__':
    raise SystemExit(main())
