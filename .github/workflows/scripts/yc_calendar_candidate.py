#!/usr/bin/env python3
"""Dedicated, manually approved staging path for the YC calendar migration."""

import argparse
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import zipfile

import staging_candidate_validation as common
import yc_calendar_drain as cloud

ROOT = common.ROOT
POLICY = ROOT / 'deploy/yc-calendar-candidate'
WORKFLOW = '.github/workflows/yc-calendar-candidate.yml'
CHECKS = '.github/workflows/yc-calendar-candidate-checks.yml'
# Deployment retries can currently bypass an earlier migration prerequisite.
# Remove this source gate only with the reviewed persistent deployment fence.
LIVE_APPLY_SUPPORTED = False
require = common.require
digest = common.digest

# Bind the whole regional financial cohort because all colocated workers resume.
# Hashes/counts, never these rows, are emitted into workflow artifacts.
TABLES = ('billing_yc_operation', 'team_billing_account', 'team_billing_period',
          'team_billing_usage', 'billing_usage_export', 'billing_usage_entitlement',
          'billing_commercial_contract', 'billing_contract_waiver', 'team_credit_ledger',
          'billing_entitlement_withheld', 'billing_entitlement_debt', 'billing_period_close_work',
          'billing_invoice_calendar', 'billing_invoice_close', 'billing_invoice_collection')


def load_policy():
    manifest = json.loads((POLICY / 'candidate.json').read_text())
    policy = json.loads((POLICY / 'history.json').read_text())
    require(manifest['schema'] == 1 and manifest['repository'] == common.REPOSITORY, 'Manifest identity mismatch')
    require(all(re.fullmatch(common.SHA, manifest[k]) for k in ('revision', 'baseline')), 'Exact revisions required')
    require(len(manifest['migrations']) == 1 and all(
        re.fullmatch(r'supabase/migrations/[0-9]{14}_yc_billing_calendar_transition.sql', p)
        and re.fullmatch(common.HASH, h) for p, h in manifest['migrations'].items()), 'Calendar migration binding required')
    require(policy['target'] == 'staging' and policy['candidate_revision'] == manifest['revision']
            and policy['candidate_migrations'] == manifest['migrations'], 'Historical policy binding mismatch')
    return manifest, policy


def provenance(manifest, env):
    common.provenance(manifest, env)
    runs = common.api(common.REPOSITORY,
                      f"actions/workflows/yc-calendar-candidate-checks.yml/runs?head_sha={env['GITHUB_SHA']}&event=push&per_page=100")['workflow_runs']
    require(runs and common.successful_run(runs[0], env['GITHUB_SHA'], 'push', CHECKS, 'main'),
            'Successful exact-main calendar source checks required')
    require(env.get('GITHUB_RUN_ATTEMPT') == '1', 'Use a fresh dispatch, never rerun an interrupted apply')


def fetch_receipt(env):
    run_id = env.get('PREFLIGHT_RUN_ID', '')
    require(re.fullmatch(r'[1-9][0-9]*', run_id), 'Explicit preflight run required')
    run = common.api(common.REPOSITORY, f'actions/runs/{run_id}')
    require(common.successful_run(run, env['GITHUB_SHA'], 'workflow_dispatch', WORKFLOW, 'main')
            and run.get('run_attempt') == 1, 'Receipt must come from a fresh successful same-main calendar preflight')
    jobs = common.api(common.REPOSITORY, f'actions/runs/{run_id}/jobs?per_page=100')['jobs']
    require(all(any(j['name'] == n and j['conclusion'] == 'success' for j in jobs)
                for n in ('Build candidate', 'Calendar staging')), 'Preflight jobs did not succeed')
    artifacts = common.api(common.REPOSITORY, f'actions/runs/{run_id}/artifacts?per_page=100')['artifacts']
    matches = [a for a in artifacts if a['name'] == 'yc-calendar-preflight' and not a['expired']]
    require(len(matches) == 1, 'Missing or ambiguous calendar receipt')
    archive = common.command(['gh', 'api', f"repos/{common.REPOSITORY}/actions/artifacts/{matches[0]['id']}/zip"], binary=True)
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        require(z.namelist() == ['receipt.json'] and z.getinfo('receipt.json').file_size < 65536, 'Invalid receipt archive')
        receipt = json.loads(z.read('receipt.json'))
    require(receipt.get('mode') == 'preflight' and receipt.get('run_id') == run_id
            and receipt.get('main_revision') == env['GITHUB_SHA']
            and digest(receipt) == env.get('APPROVED_RECEIPT_SHA256'), 'Approved receipt does not match')
    require(env.get('ACCEPT_STAGING_OUTAGE_AND_COHORT') == 'true', 'Explicit outage/cohort approval required')
    require(env.get('CONFIRM_EXECUTOR_INVENTORY') == 'true', 'Reviewed complete executor inventory required')
    return receipt


def topology():
    # Broad inventory is read-only. Scope remains the one reviewed service;
    # another possible executor requires a separate reviewed pause plan.
    result = {}
    for kind in ('services', 'jobs', 'worker-pools'):
        rows = json.loads(common.gcloud('run', kind, 'list', '--region', common.REGION))
        require(isinstance(rows, list), 'Runtime topology unavailable')
        for row in rows:
            name = row.get('metadata', {}).get('name', row.get('name', '')).split('/')[-1]
            if kind == 'services' and name == common.SERVICE:
                continue
            raw = json.dumps(row)
            require('controlplane' not in raw and not any(v in raw for v in common.SECRETS.values()),
                    'Another possible billing executor needs an explicitly reviewed drain scope')
        result[kind] = [r for r in rows if kind != 'services' or
                        r.get('metadata', {}).get('name', r.get('name', '')).split('/')[-1] != common.SERVICE]
    schedulers = json.loads(common.gcloud('scheduler', 'jobs', 'list', '--location', common.REGION))
    require(all(j.get('state') == 'PAUSED' or 'run.googleapis.com' not in json.dumps(j.get('httpTarget', {}))
                for j in schedulers), 'An enabled Cloud Run scaler requires separate coordination')
    result['schedulers'] = schedulers
    # Do not bind changing provider status; relevant input metadata/spec is bound.
    return digest({k: sorted([{'metadata': r.get('metadata'), 'spec': r.get('spec'),
                              'name': r.get('name'), 'state': r.get('state'),
                              'httpTarget': r.get('httpTarget'), 'pubsubTarget': r.get('pubsubTarget')}
                             for r in rows], key=lambda x: json.dumps(x, sort_keys=True))
                   for k, rows in result.items()})


def verify_calendar(conn, root, manifest):
    sql = (root / next(iter(manifest['migrations']))).read_text()
    functions = re.findall(r'CREATE FUNCTION (\w+)\([^;]*?\$\$(.*?)\$\$;', sql, re.S)
    require(len(functions) == 3, 'Unexpected calendar function source')
    for name, body in functions:
        rows = conn.execute("SELECT prosrc,prosecdef FROM pg_proc WHERE pronamespace='public'::regnamespace AND proname=%s", (name,)).fetchall()
        require(rows == [(body, False)], 'Applied calendar function differs')
    triggers = conn.execute("SELECT c.relname,t.tgname,t.tgenabled FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid "
                            "WHERE c.relnamespace='public'::regnamespace AND t.tgname IN ('a_yc_calendar_fence','billing_yc_calendar_transition_immutable') "
                            "ORDER BY c.relname,t.tgname").fetchall()
    tables = ['team_billing_usage', 'billing_usage_export', 'team_credit_ledger', 'billing_usage_entitlement',
              'billing_entitlement_withheld', 'billing_entitlement_debt', 'team_billing_period']
    require(triggers == sorted([(t, 'a_yc_calendar_fence', 'O') for t in tables]
                               + [('billing_yc_calendar_transition', 'billing_yc_calendar_transition_immutable', 'O')]),
            'Calendar writer fences unavailable')
    require(conn.execute("SELECT relrowsecurity FROM pg_class WHERE oid='public.billing_yc_calendar_transition'::regclass").fetchone() == (True,),
            'Calendar receipt RLS unavailable')
    require(conn.execute("SELECT contype,convalidated FROM pg_constraint WHERE conrelid='public.team_billing_period'::regclass "
                         "AND conname='team_billing_period_authoritative_no_overlap'").fetchone() == ('x', True),
            'Authoritative no-overlap constraint unavailable')


def database_state(url, root, policy, manifest, applied=False):
    import psycopg
    import snapshot_reference_index
    bounded = common.migration.bounded_url(common.migration.migration_connection_url(url, 'staging'))
    with psycopg.connect(bounded, connect_timeout=5, sslmode='require') as conn:
        conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        conn.execute("SET LOCAL statement_timeout='1900ms'")
        require(conn.execute('SELECT ' + ' AND '.join(common.migration.PREFLIGHT_CHECKS.values())).fetchone()[0], 'Bounded database settings unavailable')
        require(snapshot_reference_index.check(conn), 'Unrelated index preparation required')
        rows = [list(row) for row in conn.execute('SELECT version,name,statements FROM supabase_migrations.schema_migrations ORDER BY version')]
        catalog = common.historical.catalog_state(conn, policy)
        wakeup = (ROOT / 'supabase/migrations/20261017000100_entitlement_activation_wakeup.sql').read_text()
        for name, body in re.findall(r'CREATE (?:OR REPLACE )?FUNCTION (\w+)\(\) RETURNS trigger LANGUAGE plpgsql AS \$\$(.*?)\$\$;', wakeup, re.S):
            require(conn.execute("SELECT prosrc FROM pg_proc WHERE pronamespace='public'::regnamespace AND proname=%s AND pronargs=0", (name,)).fetchall() == [(body,)],
                    'Post-credit-dependency function differs from source')
        cohort = {}
        for table in TABLES:
            data = [row[0] for row in conn.execute(
                f"SELECT (to_jsonb(r)-'updated_at'-'next_check_at'-'last_error'-'payment_method_checked_at')::text FROM {table} r LIMIT 10001")]
            require(len(data) <= 10000, 'Cohort inventory exceeds reviewed bound')
            cohort[table] = {'hash': digest(sorted(data)), 'count': len(data)}
        leases = conn.execute('SELECT count(*) FROM stripe_webhook_processing_lease WHERE expires_at>now()').fetchone()[0]
        if applied:
            verify_calendar(conn, root, manifest)
    common.check_history(rows, root, policy)
    common.historical.check_catalog(catalog, policy, root)
    base_versions = {r[0] for r in common.expected_history(ROOT)}
    return {'history_hash': digest(rows), 'base_history_hash': digest([r for r in rows if r[0] in base_versions]),
            'cohort': cohort, 'catalog_hash': digest(catalog), 'active_leases': leases, 'policy_hash': digest(policy)}


def audit(phase, state):
    folder = ROOT / 'calendar-audit'
    folder.mkdir(exist_ok=True)
    with (folder / 'journal.jsonl').open('a') as f:
        f.write(json.dumps({'phase': phase, 'evidence_hash': digest(state),
                            'at': datetime.now(timezone.utc).isoformat(),
                            'run_id': os.environ.get('GITHUB_RUN_ID'), 'main_revision': os.environ.get('GITHUB_SHA'),
                            'image': state.get('image'),
                            'operation': state.get('operation'),
                            'revisions': [{'name': r['name'], 'uid': r['uid'],
                                           'generation': r.get('generation'), 'observed_generation': r.get('observedGeneration'),
                                           'conditions': [{k: c[k] for k in ('type', 'state', 'revisionReason') if k in c}
                                                          for c in r.get('conditions', [])]}
                                          for r in state.get('revisions', [])]}, sort_keys=True) + '\n')
    print('Calendar phase: ' + phase)


def transition(drain, state, inspect, migrate, recheck):
    drain.pause()
    drain.barrier()
    drained = inspect(False)
    require(drained['active_leases'] == 0, 'Processing leases remain; no migration permitted')
    require({k: v for k, v in drained.items() if k != 'active_leases'} ==
            {k: v for k, v in state.items() if k != 'active_leases'}, 'Financial cohort changed during drain; stop for review')
    recheck()
    drain.barrier()
    audit('migration_requested', drained)
    migrate()
    after = inspect(True)
    require(after['base_history_hash'] == state['history_hash'] and after['cohort'] == drained['cohort'],
            'Migration changed prior history or financial cohort')
    audit('migration_verified', after)
    recheck()
    drain.resume(migrated=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('gate', 'preflight', 'apply'))
    mode = parser.parse_args().mode
    try:
        env = os.environ
        if mode == 'apply' or (mode == 'gate' and env.get('VALIDATION_MODE') == 'apply'):
            require(LIVE_APPLY_SUPPORTED, 'Live apply blocked: persistent deployment-retry compatibility fence is not yet integrated')
        manifest, policy = load_policy()
        provenance(manifest, env)
        if mode == 'gate':
            with open(env['GITHUB_OUTPUT'], 'a') as output:
                output.write('candidate_revision=' + manifest['revision'] + '\n')
            return 0
        approved = fetch_receipt(env) if mode == 'apply' else None
        candidate = ROOT / 'candidate-source'
        common.verify_sources(manifest, candidate)
        before = cloud.inventory()
        # Runtime overrides could cause an approved image to execute another program.
        c = before['service']['template']['containers'][0]
        require(c.get('command', []) in ([], ['controlplane'], ['/usr/local/bin/controlplane'])
                and not c.get('args'), 'Unexpected application command override')
        url, versions = common.staging_credentials()
        require(before['service'].get('uri') == common.URL, 'Unexpected staging service URL')
        runtime_env = {e['name']: e for e in c.get('env', [])}
        for name, secret in common.SECRETS.items():
            ref = runtime_env.get(name, {}).get('valueSource', {}).get('secretKeyRef', {})
            require(ref.get('secret') == secret and ref.get('version') in ('latest', versions[name]),
                    'Unexpected regional staging secret binding')
        state = database_state(url, ROOT, policy, manifest)
        scope = topology()
        image_archive = ROOT / 'image/controlplane.tar'
        receipt = {'schema': 1, 'mode': 'preflight', 'run_id': env['GITHUB_RUN_ID'],
                   'main_revision': env['GITHUB_SHA'], 'manifest_hash': digest(manifest),
                   'candidate_revision': manifest['revision'], 'image_archive_hash': common.file_hash(image_archive),
                   'target': {'project': common.PROJECT, 'region': common.REGION, 'service': common.SERVICE,
                              'database': common.migration.PROJECTS['staging'], 'stripe': common.STRIPE_ACCOUNT},
                   'runtime_hash': digest(cloud.configuration(before)), 'instance_evidence_hash': digest(before),
                   'topology_hash': scope, 'secret_versions': versions, 'database': state}
        with tempfile.TemporaryDirectory(prefix='yc-calendar-') as directory:
            root = Path(directory)
            common.compose(manifest, candidate, root)
            for action in ('preflight', 'list', 'dry-run'):
                common.migration.migrate('staging', action, url, root=root)
            if mode == 'preflight':
                (ROOT / 'calendar-receipt').mkdir(exist_ok=True)
                (ROOT / 'calendar-receipt/receipt.json').write_text(json.dumps(receipt, sort_keys=True) + '\n')
                with open(env['GITHUB_STEP_SUMMARY'], 'a') as summary:
                    summary.write(f"Calendar receipt SHA256: `{digest(receipt)}`\n\n"
                                  'Apply pauses the staging API and all colocated workers; resume can process the entire inventoried financial cohort. '
                                  'Review topology and fixture scope before approval. No migration or deployment occurred.\n')
                return 0
            require(dict(receipt, run_id=approved['run_id']) == approved, 'Approved staging evidence changed; repeat preflight')
            audit('approved_receipt_verified', approved)
            image = common.IMAGE + '@' + common.publish_image(image_archive, manifest)
            provenance(manifest, env)
            require(topology() == scope, 'Executor topology changed')
            require(database_state(url, ROOT, policy, manifest) == state, 'Database changed before pause')
            drain = cloud.Drain(before, image, env['GITHUB_RUN_ID'], versions=versions, audit=audit)
            def recheck():
                provenance(manifest, env)
                require(topology() == scope, 'Executor topology changed during drain')
            transition(drain, state,
                       lambda applied: database_state(url, root if applied else ROOT, policy, manifest, applied=applied),
                       lambda: common.migration.migrate('staging', 'push', url, root=root), recheck)
            common.service_state(versions)
            with common.urllib.request.urlopen(common.URL + '/health', timeout=15) as response:
                require(response.status == 200, 'Candidate health check failed')
            audit('complete', {'image': image, 'candidate': manifest['revision']})
        return 0
    except Exception as error:
        audit('stopped', {'mode': mode})
        print(str(error) if isinstance(error, (common.GateError, common.migration.MigrationError))
              else 'Calendar validation failed; raw output withheld', file=sys.stderr)
        print('No automatic rollback. Inspect the last journal phase and recovery instructions before another action.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
