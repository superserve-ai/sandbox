#!/usr/bin/env python3
"""Validate a reviewed candidate on staging without changing production release gates."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

from deployment_migration_gate import MIGRATION_INPUTS
from migration_gate import GateError, api
import staging_history_baseline as historical

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts'))
import migrate_database as migration

REPOSITORY = 'superserve-ai/sandbox'
WORKFLOW = '.github/workflows/staging-candidate-validation.yml'
PROJECT = 'rayai-dev'
REGION = 'us-central1'
SERVICE = 'superserve-api'
URL = 'https://superserve-api-eszjsyysqa-uc.a.run.app'
IMAGE = f'{REGION}-docker.pkg.dev/{PROJECT}/superserve/controlplane'
STRIPE_ACCOUNT = 'acct_1U1UGVQ9Sm5V6nX8'
SECRETS = {'DATABASE_URL': 'database-url-staging',
           'STRIPE_SECRET_KEY': 'stripe-secret-key-staging-usc1',
           'OPERATOR_API_TOKEN': 'operator-api-token-staging'}
SHA = r'[a-f0-9]{40}'
HASH = r'[a-f0-9]{64}'


def require(condition, message):
    if not condition:
        raise GateError(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def file_hash(path):
    with open(path, 'rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def command(args, *, cwd=ROOT, binary=False, timeout=60):
    # Never surface subprocess arguments or provider output: they may contain secrets.
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=not binary, timeout=timeout)
    require(result.returncode == 0, 'External command failed; raw output withheld')
    return result.stdout if binary else result.stdout.strip()


def load_manifest(name):
    require(re.fullmatch(r'[a-z][a-z0-9-]{0,63}', name or ''), 'Invalid manifest name')
    manifest = json.loads((ROOT / 'deploy/staging-candidates' / (name + '.json')).read_text())
    require(manifest['schema'] == 1 and manifest['repository'] == REPOSITORY, 'Manifest identity mismatch')
    for field in ('revision', 'baseline'):
        require(re.fullmatch(SHA, manifest[field]), 'Manifest requires exact revisions')
    require(manifest['cohort'] == 'commercial-allowances-v1'
            and manifest['verification'] == 'entitlement-wakeup-v1', 'Unsupported candidate policy')
    require(manifest['migrations'], 'No reviewed migrations')
    for path, sha in manifest['migrations'].items():
        require(re.fullmatch(r'supabase/migrations/[0-9]{14}_[a-z0-9_]+\.sql', path)
                and re.fullmatch(HASH, sha), 'Invalid migration binding')
    return manifest


def successful_run(run, revision, event, path, branch):
    return (run.get('head_sha') == revision and run.get('event') == event
            and run.get('path') == path and run.get('head_branch') == branch
            and run.get('repository', {}).get('full_name') == REPOSITORY
            and run.get('head_repository', {}).get('full_name') == REPOSITORY
            and run.get('status') == 'completed' and run.get('conclusion') == 'success')


def provenance(manifest, env):
    require(env.get('GITHUB_REPOSITORY') == REPOSITORY
            and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
            and env.get('GITHUB_REF') == 'refs/heads/main'
            and re.fullmatch(SHA, env.get('GITHUB_SHA', '')), 'Use an exact main manual dispatch')
    revision = env['GITHUB_SHA']
    require(api(REPOSITORY, 'git/ref/heads/main')['object']['sha'] == revision,
            'Main advanced; review and repeat preflight')
    require(command(['git', 'rev-parse', 'HEAD']) == revision, 'Trusted checkout mismatch')
    runs = api(REPOSITORY, f'actions/workflows/ci.yml/runs?head_sha={revision}&event=push&per_page=100')['workflow_runs']
    require(runs and successful_run(runs[0], revision, 'push', '.github/workflows/ci.yml', 'main'),
            'Successful exact-main push CI required')
    runs = api(REPOSITORY, f'actions/workflows/staging-candidate-checks.yml/runs?head_sha={revision}&event=push&per_page=100')['workflow_runs']
    require(runs and successful_run(runs[0], revision, 'push', '.github/workflows/staging-candidate-checks.yml', 'main'),
            'Successful exact-main candidate source checks required')
    pr = api(REPOSITORY, f"pulls/{manifest['pull_request']}")
    require(pr['state'] == 'open' and not pr['draft'] and pr['base']['ref'] == 'main'
            and pr['base']['repo']['full_name'] == REPOSITORY
            and pr['head']['repo']['full_name'] == REPOSITORY
            and pr['head']['sha'] == manifest['revision'] and pr['head']['ref'] == manifest['branch'],
            'Candidate PR identity changed')
    review = api(REPOSITORY, f"pulls/{manifest['pull_request']}/reviews/{manifest['approval_review']}")
    require(review.get('state') == 'APPROVED' and review.get('commit_id') == manifest['revision'],
            'Pinned approval no longer approves this candidate')
    state = json.loads(command(['gh', 'pr', 'view', str(manifest['pull_request']), '--repo', REPOSITORY,
                                '--json', 'reviewDecision,statusCheckRollup']))
    require(state['reviewDecision'] == 'APPROVED', 'Current review approval required')
    checks = state['statusCheckRollup']
    require(checks and all((c.get('status') == 'COMPLETED' and c.get('conclusion') in ('SUCCESS', 'NEUTRAL', 'SKIPPED'))
                          or c.get('state') == 'SUCCESS' for c in checks), 'Candidate checks are incomplete or failed')
    run = api(REPOSITORY, f"actions/runs/{manifest['ci_run']}")
    require(successful_run(run, manifest['revision'], 'pull_request', '.github/workflows/ci.yml', manifest['branch']),
            'Successful exact-candidate PR CI required')
    # A new failed/pending rerun must not be hidden by the pinned successful run.
    runs = api(REPOSITORY, f"actions/workflows/ci.yml/runs?head_sha={manifest['revision']}&event=pull_request&per_page=100")['workflow_runs']
    require(runs and runs[0]['id'] == manifest['ci_run'] and runs[0].get('conclusion') == 'success',
            'Candidate CI changed; review the manifest')


def verify_sources(manifest, candidate):
    require(command(['git', 'rev-parse', 'HEAD'], cwd=candidate) == manifest['revision'], 'Candidate checkout mismatch')
    # Fetch the baseline as an object only; never run candidate migration tooling.
    command(['git', 'fetch', '--quiet', '--no-tags', 'origin', manifest['baseline']])
    require(not command(['git', 'diff', '--name-only', manifest['baseline'], 'HEAD', '--', *MIGRATION_INPUTS]),
            'Main migration inputs changed since candidate review')
    command(['git', 'fetch', '--quiet', '--no-tags', 'origin', manifest['revision']])
    changes = command(['git', 'diff', '--name-status', '--no-renames', manifest['baseline'], manifest['revision'],
                       '--', *MIGRATION_INPUTS]).splitlines()
    expected = sorted('A\t' + path for path in manifest['migrations'])
    require(sorted(changes) == expected, 'Candidate changes unapproved migration inputs')
    require(not command(['git', 'diff', '--name-only', manifest['baseline'], manifest['revision'],
                         '--', '.github/workflows/ci.yml']), 'Candidate changed its CI definition')
    for path, sha in manifest['migrations'].items():
        require(file_hash(candidate / path) == sha, 'Candidate migration bytes changed')


def expected_history(root):
    rows = []
    for path in sorted((root / 'supabase/migrations').glob('*.sql')):
        match = re.fullmatch(r'([0-9]+)_(.+)\.sql', path.name)
        require(match is not None, 'Unrecognized migration filename')
        rows.append([match[1], match[2]])
    require(len({r[0] for r in rows}) == len(rows), 'Duplicate migration versions')
    return rows


def load_historical_baseline(manifest):
    require(manifest.get('historical_baseline') == 'yc-credit-history',
            'Explicit reviewed historical baseline required')
    policy = json.loads((ROOT / 'deploy/staging-candidates/yc-credit-history.json').read_text())
    require(policy['schema'] == 1 and policy['target'] == 'staging'
            and policy['candidate_revision'] == manifest['revision']
            and policy['candidate_migrations'] == manifest['migrations'],
            'Historical baseline is not approved for this target or candidate')
    require(set(policy['variants']) == {'20260429000001', '20260710000001', '20260730000002',
                                       '20260818000001', '20260924000001'},
            'Historical baseline version scope changed')
    return policy


def sql_statements(sql):
    from pglast import parser
    def without_positions(value):
        if isinstance(value, list):
            return [without_positions(v) for v in value]
        if isinstance(value, dict):
            return {k: without_positions(v) for k, v in value.items()
                    if k not in ('location', 'stmt_len') and not k.endswith('_location')}
        return value
    return [without_positions(row['stmt']) for row in json.loads(parser.parse_sql_json(sql))['stmts']]


def check_history(rows, root, policy=None):
    expected_rows = expected_history(root)
    require([r[0] for r in rows] == [r[0] for r in expected_rows],
            'Remote migration inventory differs; unrelated pending or changed history')
    for (version, name, statements), (_, source_name) in zip(rows, expected_rows):
        require(isinstance(statements, list) and all(isinstance(s, str) for s in statements),
                'Stored migration statements are unavailable')
        path = 'supabase/migrations/' + version + '_' + source_name + '.sql'
        expected = sql_statements((root / path).read_text())
        actual = [stmt for sql in statements for stmt in sql_statements(sql)]
        variant = policy['variants'].get(version) if policy else None
        if variant:
            require(variant['source'] == path and file_hash(root / path) == variant['source_sha256']
                    and digest(expected) == variant['source_ast_sha256'], 'Historical baseline source changed')
            require(name == variant['observed_name'] and digest(statements) == variant['statements_sha256']
                    and digest(actual) == variant['ast_sha256'], 'Unapproved historical migration variant')
        else:
            require(name == source_name and actual == expected, 'Stored migration SQL differs from reviewed source')


COHORT_SQL = """
SELECT c.id::text,c.team_id::text,c.offer_key,c.starts_at::text,c.ends_at::text,
 c.entitlement_anchor::text,c.customer_id,c.subscription_id,
 EXISTS(SELECT 1 FROM billing_usage_entitlement e WHERE e.contract_id=c.id
  AND e.state='issued' AND e.period_start<=now() AND e.period_end>now()) AS current_issued,
 (SELECT count(*) FROM billing_usage_entitlement e WHERE e.contract_id=c.id AND e.state<>'issued') AS unresolved
FROM billing_commercial_contract c
WHERE c.status='active' AND c.offer_key IN ('pro_monthly','pro_annual','yc_2026')
 AND c.starts_at<=now() AND (c.ends_at IS NULL OR c.ends_at>now()) ORDER BY c.id
"""


def database_state(url, root, *, applied=False, policy=None):
    import psycopg
    import snapshot_reference_index
    bounded = migration.bounded_url(migration.migration_connection_url(url, 'staging'))
    with psycopg.connect(bounded, connect_timeout=5, sslmode='require') as conn:
        conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        conn.execute("SET LOCAL statement_timeout='1900ms'")
        require(conn.execute('SELECT ' + ' AND '.join(migration.PREFLIGHT_CHECKS.values())).fetchone()[0],
                'Database execution settings unavailable')
        require(snapshot_reference_index.check(conn), 'Unrelated index preparation required')
        rows = [list(row) for row in conn.execute('SELECT version,name,statements FROM supabase_migrations.schema_migrations ORDER BY version')]
        cohort = [list(row) for row in conn.execute(COHORT_SQL)]
        operations = [list(row) for row in conn.execute(
            "SELECT id::text,team_id::text,state,resource_terms,customer_id,subscription_id,"
            "starts_at::text,ends_at::text,revoked_at::text,cancel_pending FROM billing_yc_operation "
            "WHERE state<>'ended' ORDER BY id")]
        catalog = historical.catalog_state(conn, policy) if policy else None
        if applied:
            verify_wakeup_schema(conn, root)
    # Parse outside the short read-only transaction; large migration histories
    # must not consume its server-side transaction deadline doing local CPU work.
    check_history(rows, root, policy)
    catalog_hash = historical.check_catalog(catalog, policy, root, applied=applied) if policy else None
    # Only hashes and totals leave this process; no customer IDs in public artifacts.
    base_versions = {r[0] for r in expected_history(ROOT)}
    return {'history_hash': digest(rows), 'base_history_hash': digest([r for r in rows if r[0] in base_versions]),
            'cohort_hash': digest(cohort), 'yc_operations_hash': digest(operations), 'yc_operations': len(operations),
            'active_contracts': len(cohort), 'missing_current_grant': sum(not r[8] for r in cohort),
            'unresolved_entitlements': sum(r[9] for r in cohort),
            'historical_baseline_hash': digest(policy) if policy else None, 'catalog_hash': catalog_hash}


def verify_wakeup_schema(conn, root):
    columns = conn.execute("SELECT column_name,data_type,is_nullable,column_default FROM information_schema.columns "
                           "WHERE table_schema='public' AND table_name='billing_entitlement_work' "
                           "AND column_name IN ('wake_generation','lease_generation') ORDER BY column_name").fetchall()
    require(columns == [('lease_generation', 'bigint', 'NO', '0'), ('wake_generation', 'bigint', 'NO', '0')],
            'Applied wakeup columns mismatch')
    require(conn.execute("SELECT EXISTS(SELECT 1 FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid "
                         "WHERE t.tgrelid='public.billing_entitlement_work'::regclass "
                         "AND t.tgname='billing_entitlement_wakeup_guard' AND t.tgenabled='O' AND t.tgtype=19 "
                         "AND p.pronamespace='public'::regnamespace AND p.proname='guard_entitlement_wakeup')").fetchone()[0],
            'Applied wakeup trigger mismatch')
    paths = set((root / 'supabase/migrations').glob('*.sql'))
    baseline_names = {p.name for p in (ROOT / 'supabase/migrations').glob('*.sql')}
    functions = {}
    for path in paths:
        if path.name not in baseline_names:
            functions.update(re.findall(r'CREATE (?:OR REPLACE )?FUNCTION (\w+)\(\) RETURNS trigger LANGUAGE plpgsql AS \$\$(.*?)\$\$;', path.read_text(), re.S))
    require(set(functions) == {'guard_entitlement_wakeup', 'enqueue_billing_entitlement'}, 'Unexpected wakeup verification policy')
    for name, body in functions.items():
        rows = conn.execute("SELECT prosrc FROM pg_proc WHERE pronamespace='public'::regnamespace "
                            "AND proname=%s AND pronargs=0 AND prorettype='trigger'::regtype", (name,)).fetchall()
        require(rows == [(body,)], 'Installed wakeup function differs from reviewed SQL')


def gcloud(*args):
    return command(['gcloud', *args, '--project', PROJECT, '--format=json'])


def service_state(versions=None):
    desc = json.loads(gcloud('run', 'services', 'describe', SERVICE, '--region', REGION))
    require(desc['status']['url'] == URL, 'Unexpected staging service URL')
    containers = desc['spec']['template']['spec']['containers']
    require(len(containers) == 1, 'Unexpected staging container topology')
    env = {entry['name']: entry for entry in containers[0].get('env', [])}
    for key, secret in SECRETS.items():
        require(env.get(key, {}).get('valueFrom', {}).get('secretKeyRef') == {'name': secret, 'key': versions[key] if versions else 'latest'},
                'Unexpected staging runtime secret reference')
    # Cloud Run aliases may redirect short secret names to another project.
    aliases = desc['spec']['template'].get('metadata', {}).get('annotations', {}).get('run.googleapis.com/secrets', '')
    require(not aliases, 'Cross-project secret aliases are not supported')
    return desc


def staging_credentials():
    values, versions = {}, {}
    for key, name in SECRETS.items():
        metadata = json.loads(gcloud('secrets', 'versions', 'describe', 'latest', '--secret', name))
        require(metadata['state'] == 'ENABLED', 'Staging secret is disabled')
        version = metadata['name'].rsplit('/', 1)[1]
        require(re.fullmatch(r'[1-9][0-9]*', version), 'Secret version unresolved')
        versions[key] = version
        if key != 'OPERATOR_API_TOKEN':
            values[key] = command(['gcloud', 'secrets', 'versions', 'access', version, '--secret', name, '--project', PROJECT])
    migration.verify_connection_identity(values['DATABASE_URL'], 'staging')
    key = values['STRIPE_SECRET_KEY']
    require(key.startswith(('sk_test_', 'rk_test_')), 'Staging requires a Stripe test key')
    request = urllib.request.Request('https://api.stripe.com/v1/account', headers={'Authorization': 'Bearer ' + key})
    with urllib.request.urlopen(request, timeout=15) as response:
        account = json.load(response)
    require(account['id'] == STRIPE_ACCOUNT, 'Unexpected Stripe account')
    return values['DATABASE_URL'], versions


def validate_receipt_run(run_id, env):
    require(re.fullmatch(r'[1-9][0-9]*', run_id or ''), 'Explicit preflight run required')
    run = api(REPOSITORY, f'actions/runs/{run_id}')
    require(successful_run(run, env['GITHUB_SHA'], 'workflow_dispatch', WORKFLOW, 'main'),
            'Receipt run is not a successful same-main preflight')
    require(run.get('run_attempt') == 1, 'Use a fresh preflight run, not a rerun')
    jobs = api(REPOSITORY, f'actions/runs/{run_id}/jobs?per_page=100')['jobs']
    require(any(j['name'] == 'Build candidate' and j['conclusion'] == 'success' for j in jobs)
            and any(j['name'] == 'Staging validation' and j['conclusion'] == 'success' for j in jobs),
            'Run did not complete candidate preflight')


def fetch_receipt(run_id, env):
    validate_receipt_run(run_id, env)
    artifacts = api(REPOSITORY, f'actions/runs/{run_id}/artifacts?per_page=100')['artifacts']
    matches = [a for a in artifacts if a['name'] == 'staging-preflight' and not a['expired']]
    require(len(matches) == 1, 'Missing or ambiguous preflight artifact')
    archive = command(['gh', 'api', f"repos/{REPOSITORY}/actions/artifacts/{matches[0]['id']}/zip"], binary=True)
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        require(z.namelist() == ['receipt.json'] and z.getinfo('receipt.json').file_size < 65536, 'Invalid receipt archive')
        receipt = json.loads(z.read('receipt.json'))
    require(receipt['mode'] == 'preflight' and receipt['run_id'] == run_id
            and receipt['main_revision'] == env['GITHUB_SHA'], 'Receipt identity mismatch')
    require(digest(receipt) == env.get('APPROVED_RECEIPT_SHA256'), 'Receipt hash is not explicitly approved')
    require(env.get('ACCEPT_CONCURRENT_STAGING') == 'true', 'Accept normal concurrent staging worker effects explicitly')
    return receipt


def compose(manifest, candidate, root):
    for relative in ('supabase/migrations', 'supabase/shared-auth-history', 'supabase/shared-auth-migrations'):
        shutil.copytree(ROOT / relative, root / relative)
    for path in manifest['migrations']:
        shutil.copyfile(candidate / path, root / path)


def publish_image(image_archive, manifest):
    command(['gcloud', 'auth', 'configure-docker', f'{REGION}-docker.pkg.dev', '--quiet'])
    command(['docker', 'load', '--input', str(image_archive)], timeout=180)
    tag = f"{IMAGE}:staging-candidate-{manifest['revision']}-{os.environ['GITHUB_RUN_ID']}"
    command(['docker', 'tag', 'controlplane:' + manifest['revision'], tag])
    command(['docker', 'push', tag], timeout=300)
    metadata = json.loads(gcloud('artifacts', 'docker', 'images', 'describe', tag))
    image_digest = metadata['image_summary']['digest']
    require(re.fullmatch('sha256:' + HASH, image_digest), 'Registry digest unresolved')
    return image_digest


def deploy(image_digest, before, versions):
    require(service_state()['spec'] == before['spec'], 'Staging service changed before deployment')
    revision = SERVICE + '-candidate-' + os.environ['GITHUB_RUN_ID']
    command(['gcloud', 'run', 'services', 'update', SERVICE, '--image', IMAGE + '@' + image_digest,
             '--update-secrets', ','.join(key + '=' + name + ':' + versions[key] for key, name in SECRETS.items()),
             '--revision-suffix', 'candidate-' + os.environ['GITHUB_RUN_ID'], '--region', REGION, '--project', PROJECT,
             '--quiet'], timeout=600)
    desc = service_state(versions)
    require(desc['status']['latestReadyRevisionName'] == revision, 'Candidate revision is not ready')
    deployed = json.loads(gcloud('run', 'revisions', 'describe', revision, '--region', REGION))
    require(deployed['status']['imageDigest'] == IMAGE + '@' + image_digest, 'Deployed image digest mismatch')
    command(['gcloud', 'run', 'services', 'update-traffic', SERVICE, '--to-revisions', revision + '=100',
             '--region', REGION, '--project', PROJECT, '--quiet'], timeout=180)
    desc = service_state(versions)
    require(sum(t.get('percent', 0) for t in desc['status']['traffic'] if t.get('revisionName') == revision) == 100,
            'Candidate does not serve all staging traffic')
    with urllib.request.urlopen(URL + '/health', timeout=15) as response:
        require(response.status == 200, 'Staging health check failed')
    return {'revision': revision, 'image_digest': image_digest}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('gate', 'preflight', 'apply'))
    args = parser.parse_args()
    try:
        env = os.environ
        manifest = load_manifest(env.get('CANDIDATE', ''))
        policy = load_historical_baseline(manifest)
        provenance(manifest, env)
        require(env.get('GITHUB_RUN_ATTEMPT') == '1', 'Use a fresh dispatch, not a rerun')
        mode = env.get('VALIDATION_MODE')
        require(mode in ('preflight', 'apply'), 'Explicit validation mode required')
        approved = fetch_receipt(env.get('PREFLIGHT_RUN_ID', ''), env) if mode == 'apply' else None
        if args.action == 'gate':
            with open(env['GITHUB_OUTPUT'], 'a') as output:
                output.write('candidate_revision=' + manifest['revision'] + '\n')
            return 0
        require(args.action == mode, 'Action does not match the dispatch')
        candidate = ROOT / 'candidate-source'
        verify_sources(manifest, candidate)
        image_archive = ROOT / 'image/controlplane.tar'
        image_hash = file_hash(image_archive)
        before = service_state()
        url, versions = staging_credentials()
        state = database_state(url, ROOT, policy=policy)
        receipt = {'schema': 1, 'mode': 'preflight', 'run_id': env['GITHUB_RUN_ID'],
                   'main_revision': env['GITHUB_SHA'], 'manifest_hash': digest(manifest),
                   'candidate_revision': manifest['revision'], 'image_archive_hash': image_hash,
                   'target': {'project': PROJECT, 'region': REGION, 'service': SERVICE,
                              'database': migration.PROJECTS['staging'], 'stripe': STRIPE_ACCOUNT},
                   'runtime_hash': digest(before['spec']), 'secret_versions': versions, 'database': state}
        with tempfile.TemporaryDirectory(prefix='staging-candidate-') as directory:
            root = Path(directory)
            compose(manifest, candidate, root)
            migration.migrate('staging', 'preflight', url, root=root)
            migration.migrate('staging', 'list', url, root=root)
            migration.migrate('staging', 'dry-run', url, root=root)
            if mode == 'preflight':
                output = ROOT / 'receipt'
                output.mkdir(exist_ok=True)
                (output / 'receipt.json').write_text(json.dumps(receipt, sort_keys=True) + '\n')
                with open(env['GITHUB_STEP_SUMMARY'], 'a') as summary:
                    summary.write(f"Preflight receipt SHA256: `{digest(receipt)}`\n\n"
                                  f"Active contracts: {state['active_contracts']}; missing current grant: {state['missing_current_grant']}; "
                                  f"unresolved entitlements: {state['unresolved_entitlements']}.\n\n"
                                  'Execution includes normal concurrent staging workers. This is not Stripe acceptance evidence.\n')
            else:
                current = dict(receipt, run_id=approved['run_id'])
                require(current == approved, 'Staging state or approved input changed; repeat preflight')
                image_digest = publish_image(image_archive, manifest)
                provenance(manifest, env)
                require(database_state(url, ROOT, policy=policy) == state, 'Database changed during preflight')
                require(service_state()['spec'] == before['spec'], 'Staging service changed during preflight')
                # The existing runner owns SQL execution and its advisory lock. Workers
                # remain live: approval includes concurrent normal staging processing.
                migration.migrate('staging', 'push', url, root=root)
                after = database_state(url, root, applied=True, policy=policy)
                require(after['base_history_hash'] == state['history_hash'], 'Existing migration history changed during apply')
                result = deploy(image_digest, before, versions)
                with open(env['GITHUB_STEP_SUMMARY'], 'a') as summary:
                    summary.write('Staging candidate deployed: `' + result['revision'] + '`\n\n'
                                  'Image digest: `' + result['image_digest'] + '`\n\n'
                                  'Actual grant issuance, replay, invoice consumption and application access still require controlled acceptance.\n')
        return 0
    except Exception as error:
        print(str(error) if isinstance(error, (GateError, migration.MigrationError))
              else 'Staging validation failed; raw provider output withheld', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
