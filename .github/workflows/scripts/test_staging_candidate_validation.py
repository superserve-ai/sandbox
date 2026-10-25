"""Regressions at the candidate release trust boundaries; no provider credentials."""

import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from urllib.parse import urlsplit

import staging_candidate_validation as gate


MAIN = 'a' * 40
HEAD = 'b' * 40
ENV = {'GITHUB_REPOSITORY': gate.REPOSITORY, 'GITHUB_EVENT_NAME': 'workflow_dispatch',
       'GITHUB_REF': 'refs/heads/main', 'GITHUB_SHA': MAIN}
MANIFEST = {'revision': HEAD, 'pull_request': 12, 'branch': 'candidate', 'approval_review': 34, 'ci_run': 56}


def run(revision, event, path, branch, **extra):
    return dict(head_sha=revision, event=event, path=path, head_branch=branch,
                repository={'full_name': gate.REPOSITORY}, head_repository={'full_name': gate.REPOSITORY},
                status='completed', conclusion='success', **extra)


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.responses = {
            'git/ref/heads/main': {'object': {'sha': MAIN}},
            f'actions/workflows/ci.yml/runs?head_sha={MAIN}&event=push&per_page=100':
                {'workflow_runs': [run(MAIN, 'push', '.github/workflows/ci.yml', 'main')]},
            f'actions/workflows/staging-candidate-checks.yml/runs?head_sha={MAIN}&event=push&per_page=100':
                {'workflow_runs': [run(MAIN, 'push', '.github/workflows/staging-candidate-checks.yml', 'main')]},
            'pulls/12': {'state': 'open', 'draft': False,
                         'base': {'ref': 'main', 'repo': {'full_name': gate.REPOSITORY}},
                         'head': {'ref': 'candidate', 'sha': HEAD, 'repo': {'full_name': gate.REPOSITORY}}},
            'pulls/12/reviews/34': {'state': 'APPROVED', 'commit_id': HEAD},
            'actions/runs/56': run(HEAD, 'pull_request', '.github/workflows/ci.yml', 'candidate', id=56),
            f'actions/workflows/ci.yml/runs?head_sha={HEAD}&event=pull_request&per_page=100':
                {'workflow_runs': [run(HEAD, 'pull_request', '.github/workflows/ci.yml', 'candidate', id=56)]},
        }
        self.checks = {'reviewDecision': 'APPROVED', 'statusCheckRollup': [{'status': 'COMPLETED', 'conclusion': 'SUCCESS'}]}

    def verify(self, env=None):
        with patch.object(gate, 'api', side_effect=lambda repo, path: self.responses[path]), \
             patch.object(gate, 'command', side_effect=lambda args: MAIN if args[0] == 'git' else json.dumps(self.checks)):
            gate.provenance(MANIFEST, env or ENV)

    def test_approved_own_candidate_and_two_distinct_ci_events(self):
        self.verify()

    def test_rejects_branch_dispatch_and_changed_main(self):
        with self.assertRaises(gate.GateError):
            self.verify(dict(ENV, GITHUB_REF='refs/heads/candidate'))
        self.responses['git/ref/heads/main']['object']['sha'] = HEAD
        with self.assertRaises(gate.GateError):
            self.verify()

    def test_rejects_fork_or_replaced_candidate(self):
        for field, value in [('sha', MAIN), ('repo', {'full_name': 'other/fork'})]:
            with self.subTest(field=field):
                old = copy.deepcopy(self.responses['pulls/12']['head'])
                self.responses['pulls/12']['head'][field] = value
                with self.assertRaises(gate.GateError):
                    self.verify()
                self.responses['pulls/12']['head'] = old

    def test_rejects_dismissed_stale_or_current_changes_requested_review(self):
        self.responses['pulls/12/reviews/34']['commit_id'] = MAIN
        with self.assertRaises(gate.GateError):
            self.verify()
        self.responses['pulls/12/reviews/34'] = {'state': 'DISMISSED', 'commit_id': HEAD}
        with self.assertRaises(gate.GateError):
            self.verify()
        self.responses['pulls/12/reviews/34']['state'] = 'APPROVED'
        self.checks['reviewDecision'] = 'CHANGES_REQUESTED'
        with self.assertRaises(gate.GateError):
            self.verify()

    def test_rejects_wrong_ci_event_workflow_and_newer_failed_run(self):
        for field, value in [('event', 'workflow_dispatch'), ('head_sha', MAIN),
                             ('path', '.github/workflows/other.yml'), ('conclusion', 'failure')]:
            old = copy.deepcopy(self.responses['actions/runs/56'])
            self.responses['actions/runs/56'][field] = value
            with self.subTest(field=field), self.assertRaises(gate.GateError):
                self.verify()
            self.responses['actions/runs/56'] = old
        key = f'actions/workflows/ci.yml/runs?head_sha={HEAD}&event=pull_request&per_page=100'
        self.responses[key]['workflow_runs'][0]['id'] = 57
        with self.assertRaises(gate.GateError):
            self.verify()

    def test_pending_candidate_check_blocks(self):
        self.checks['statusCheckRollup'] = [{'status': 'IN_PROGRESS'}]
        with self.assertRaises(gate.GateError):
            self.verify()

    def test_missing_or_failed_main_parser_check_blocks(self):
        key = f'actions/workflows/staging-candidate-checks.yml/runs?head_sha={MAIN}&event=push&per_page=100'
        for runs in [[], [run(MAIN, 'push', '.github/workflows/staging-candidate-checks.yml', 'main')]]:
            if runs:
                runs[0]['conclusion'] = 'failure'
            self.responses[key]['workflow_runs'] = runs
            with self.assertRaises(gate.GateError):
                self.verify()


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.receipt = {'mode': 'preflight', 'run_id': '123', 'main_revision': MAIN, 'image_archive_hash': 'c' * 64}
        self.env = dict(ENV, APPROVED_RECEIPT_SHA256=gate.digest(self.receipt), ACCEPT_CONCURRENT_STAGING='true')
        self.run = run(MAIN, 'workflow_dispatch', gate.WORKFLOW, 'main', run_attempt=1)
        self.jobs = [{'name': name, 'conclusion': 'success'} for name in ['Build candidate', 'Staging validation']]
        self.artifacts = [{'id': 789, 'name': 'staging-preflight', 'expired': False}]

    def fetch(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as z:
            z.writestr('receipt.json', json.dumps(self.receipt))
        responses = {'actions/runs/123': self.run, 'actions/runs/123/jobs?per_page=100': {'jobs': self.jobs},
                     'actions/runs/123/artifacts?per_page=100': {'artifacts': self.artifacts}}
        with patch.object(gate, 'api', side_effect=lambda repo, path: responses[path]), \
             patch.object(gate, 'command', return_value=archive.getvalue()):
            return gate.fetch_receipt('123', self.env)

    def test_receipt_requires_successful_build_and_preflight_artifact(self):
        self.assertEqual(self.fetch(), self.receipt)
        self.jobs[0]['conclusion'] = 'skipped'
        with self.assertRaises(gate.GateError):
            self.fetch()

    def test_wrong_run_revision_workflow_or_attempt_cannot_supply_receipt(self):
        for field, value in [('head_sha', HEAD), ('path', '.github/workflows/other.yml'), ('run_attempt', 2)]:
            old = self.run[field]
            self.run[field] = value
            with self.subTest(field=field), self.assertRaises(gate.GateError):
                self.fetch()
            self.run[field] = old

    def test_receipt_tampering_or_unaccepted_worker_effects_blocks(self):
        self.receipt['image_archive_hash'] = 'd' * 64
        with self.assertRaises(gate.GateError):
            self.fetch()
        self.env['APPROVED_RECEIPT_SHA256'] = gate.digest(self.receipt)
        self.env['ACCEPT_CONCURRENT_STAGING'] = 'false'
        with self.assertRaises(gate.GateError):
            self.fetch()

    def test_duplicate_or_expired_artifact_blocks(self):
        self.artifacts.append(copy.deepcopy(self.artifacts[0]))
        with self.assertRaises(gate.GateError):
            self.fetch()
        self.artifacts.pop()
        self.artifacts[0]['expired'] = True
        with self.assertRaises(gate.GateError):
            self.fetch()


class SourcesTests(unittest.TestCase):
    def test_composed_bundle_satisfies_real_runner_aggregate_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate, root = Path(directory) / 'candidate', Path(directory) / 'composed'
            path = 'supabase/migrations/20990101000000_candidate.sql'
            (candidate / path).parent.mkdir(parents=True)
            (candidate / path).write_text('SELECT 1;')
            gate.compose({'migrations': {path: 'unused'}}, candidate, root)
            self.assertEqual(gate.migration.verified_aggregate(root), gate.migration.verified_aggregate(gate.ROOT))
            self.assertEqual((root / path).read_text(), 'SELECT 1;')

    def test_only_reviewed_addition_can_be_composed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'main'
            candidate = Path(directory) / 'candidate'
            root.mkdir()
            def git(*args):
                return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.DEVNULL, text=True).strip()
            git('init', '-q')
            git('config', 'user.email', 'test@example.com')
            git('config', 'user.name', 'test')
            (root / 'supabase/migrations').mkdir(parents=True)
            (root / 'supabase/migrations/20260101000000_initial.sql').write_text('SELECT 1;')
            git('add', '.')
            git('commit', '-qm', 'baseline')
            baseline = git('rev-parse', 'HEAD')
            path = 'supabase/migrations/20260102000000_candidate.sql'
            (root / path).write_text('SELECT 2;')
            git('add', '.')
            git('commit', '-qm', 'candidate')
            head = git('rev-parse', 'HEAD')
            subprocess.run(['git', 'clone', '-q', str(root), str(candidate)], check=True)
            git('remote', 'add', 'origin', str(candidate))
            git('checkout', '-q', baseline)
            manifest = {'baseline': baseline, 'revision': head, 'migrations': {path: gate.file_hash(candidate / path)}}
            original = gate.command
            def command(args, *, cwd=root, **kwargs):
                return original(args, cwd=cwd, **kwargs)
            with patch.object(gate, 'ROOT', root), patch.object(gate, 'command', side_effect=command):
                gate.verify_sources(manifest, candidate)
                (candidate / path).write_text('SELECT 3;')
                with self.assertRaisesRegex(gate.GateError, 'bytes changed'):
                    gate.verify_sources(manifest, candidate)
                (candidate / path).write_text('SELECT 2;')
                (root / 'supabase/migrations/20260103000000_unrelated.sql').write_text('SELECT 4;')
                git('add', '.')
                git('commit', '-qm', 'unrelated main migration')
                with self.assertRaisesRegex(gate.GateError, 'Main migration inputs changed'):
                    gate.verify_sources(manifest, candidate)


@unittest.skipUnless(importlib.util.find_spec('pglast'), 'SQL parser runs in the required candidate source check')
class SQLHistoryTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.migrations = self.root / 'supabase/migrations'
        self.migrations.mkdir(parents=True)
        (self.migrations / '1_first.sql').write_text('SELECT 1;')
        (self.migrations / '2_second.sql').write_text('SELECT 2;')
        self.rows = [['1', 'first', ['SELECT 1']], ['2', 'second', ['SELECT 2']]]

    def test_history_rejects_unrelated_missing_extra_and_renamed_entries(self):
        gate.check_history(self.rows, self.root)
        for rows in [self.rows[:1], self.rows + [['3', 'extra', []]],
                     [self.rows[0], ['2', 'renamed', ['SELECT 2']]]]:
            with self.subTest(rows=rows), self.assertRaises(gate.GateError):
                gate.check_history(rows, self.root)

    def test_correct_ledger_label_cannot_hide_changed_missing_or_reordered_sql(self):
        for statements in [['SELECT 9'], [], None, ['SELECT 2; SELECT 1']]:
            with self.subTest(statements=statements), self.assertRaises(gate.GateError):
                gate.check_history([self.rows[0], ['2', 'second', statements]], self.root)

    def test_parser_preserves_bodies_and_literals_but_ignores_comment_formatting(self):
        sql = "CREATE FUNCTION example() RETURNS text LANGUAGE sql AS $$SELECT 'semi;colon'$$; SELECT '/*literal*/';"
        (self.migrations / '2_second.sql').write_text(sql)
        formatted = ["-- comment\n CREATE FUNCTION example() RETURNS text LANGUAGE sql AS $$SELECT 'semi;colon'$$;",
                     "SELECT /* comment */ '/*literal*/';"]
        gate.check_history([self.rows[0], ['2', 'second', formatted]], self.root)
        with self.assertRaises(gate.GateError):
            gate.check_history([self.rows[0], ['2', 'second', [sql.replace('semi;colon', 'different')]]], self.root)

    def test_all_reviewed_migration_files_parse(self):
        for path in (gate.ROOT / 'supabase/migrations').glob('*.sql'):
            with self.subTest(path=path.name):
                gate.sql_statements(path.read_text())

    def historical_policy(self):
        path = 'supabase/migrations/2_second.sql'
        statements = ['SELECT 3', 'SELECT 4']
        return {'variants': {'2': {
            'source': path, 'source_sha256': gate.file_hash(self.root / path),
            'source_ast_sha256': gate.digest(gate.sql_statements('SELECT 2;')),
            'observed_name': 'historical', 'statements_sha256': gate.digest(statements),
            'ast_sha256': gate.digest(gate.sql_statements(';'.join(statements)))}}}

    def test_only_exact_reviewed_historical_variant_is_accepted(self):
        policy = self.historical_policy()
        rows = [self.rows[0], ['2', 'historical', ['SELECT 3', 'SELECT 4']]]
        gate.check_history(rows, self.root, policy)
        for replacement in [['SELECT 4', 'SELECT 3'], ['SELECT 3', 'SELECT 5'], ['SELECT 3; SELECT 4']]:
            with self.subTest(replacement=replacement), self.assertRaises(gate.GateError):
                gate.check_history([rows[0], ['2', 'historical', replacement]], self.root, policy)
        for changed in [self.rows, [['1', 'first', ['SELECT 9']], rows[1]], rows[:1],
                        rows + [['3', 'extra', ['SELECT 5']]]]:
            with self.subTest(changed=changed), self.assertRaises(gate.GateError):
                gate.check_history(changed, self.root, policy)
        (self.migrations / '2_second.sql').write_text('SELECT 5;')
        with self.assertRaisesRegex(gate.GateError, 'baseline source changed'):
            gate.check_history(rows, self.root, policy)


class HistoricalCatalogTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / 'before.sql').write_text('reviewed before')
        (self.root / 'after.sql').write_text('reviewed after')
        spec = {'source': 'before.sql', 'source_sha256': gate.file_hash(self.root / 'before.sql'),
                'arguments': '', 'body_sha256': gate.digest('original'), 'language': 'sql', 'security_definer': False, 'volatility': 'v', 'result': 'text', 'configuration': None}
        updated = dict(spec, source='after.sql', source_sha256=gate.file_hash(self.root / 'after.sql'),
                       body_sha256=gate.digest('updated'))
        self.policy = {'catalog': {'checks': [['required', True]]},
                       'functions': {'example': spec}, 'applied_functions': {'example': updated}}
        self.catalog = {'checks': [['required', True]], 'functions': [['example', '', 'original', 'sql', False, 'v', 'text', None]]}

    def test_catalog_drift_and_function_substitution_fail_closed(self):
        gate.historical.check_catalog(self.catalog, self.policy, self.root)
        for key, value in [('checks', []), ('checks', [['required', False]]), ('functions', []),
                           ('functions', [['example', '', 'changed', 'sql', False, 'v', 'text', None]]),
                           ('functions', [['example', '', 'original', 'sql', True, 'v', 'text', None]])]:
            with self.subTest(value=value), self.assertRaises(gate.GateError):
                gate.historical.check_catalog(dict(self.catalog, **{key: value}), self.policy, self.root)
        (self.root / 'before.sql').write_text('changed source')
        with self.assertRaises(gate.GateError):
            gate.historical.check_catalog(self.catalog, self.policy, self.root)

    def test_applied_phase_requires_only_reviewed_function_transition(self):
        after = dict(self.catalog, functions=[['example', '', 'updated', 'sql', False, 'v', 'text', None]])
        gate.historical.check_catalog(after, self.policy, self.root, applied=True)
        with self.assertRaises(gate.GateError):
            gate.historical.check_catalog(after, self.policy, self.root)
        with self.assertRaises(gate.GateError):
            gate.historical.check_catalog(self.catalog, self.policy, self.root, applied=True)

    def test_policy_cannot_follow_another_candidate_or_target(self):
        manifest = json.loads((gate.ROOT / 'deploy/staging-candidates/yc-credit-recovery.json').read_text())
        policy = gate.load_historical_baseline(manifest)
        for changed in [dict(manifest, revision='c' * 40), dict(manifest, migrations={}),
                        dict(manifest, historical_baseline='unreviewed')]:
            with self.subTest(changed=changed), self.assertRaises(gate.GateError):
                gate.load_historical_baseline(changed)
        with patch.object(Path, 'read_text', return_value=json.dumps(dict(policy, target='production'))), \
             self.assertRaises(gate.GateError):
            gate.load_historical_baseline(manifest)


class ApplyHistoryTests(unittest.TestCase):
    def invoke(self, *, approved_change=None, preapply_change=None, after_change=None):
        state = {'history_hash': 'original-history', 'catalog_hash': 'original-catalog',
                 'historical_baseline_hash': 'reviewed-policy'}
        manifest = {'revision': HEAD}
        runtime = {'spec': {'synthetic': True}}
        approved = {'schema': 1, 'mode': 'preflight', 'run_id': '123', 'main_revision': MAIN,
                    'manifest_hash': gate.digest(manifest), 'candidate_revision': HEAD, 'image_archive_hash': 'image',
                    'target': {'project': gate.PROJECT, 'region': gate.REGION, 'service': gate.SERVICE,
                               'database': gate.migration.PROJECTS['staging'], 'stripe': gate.STRIPE_ACCOUNT},
                    'runtime_hash': gate.digest(runtime['spec']), 'secret_versions': {},
                    'database': dict(state, **(approved_change or {}))}
        after = dict(state, base_history_hash=state['history_hash'])
        after.update(after_change or {})
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(os.environ, dict(ENV, GITHUB_RUN_ID='124', GITHUB_RUN_ATTEMPT='1', VALIDATION_MODE='apply',
                                         GITHUB_STEP_SUMMARY=str(Path(directory) / 'summary'))), \
             patch.object(sys, 'argv', ['validator', 'apply']), \
             patch.object(gate, 'load_manifest', return_value=manifest), \
             patch.object(gate, 'load_historical_baseline', return_value={'synthetic': True}), \
             patch.object(gate, 'provenance'), patch.object(gate, 'verify_sources'), patch.object(gate, 'compose'), \
             patch.object(gate, 'fetch_receipt', return_value=approved), \
             patch.object(gate, 'file_hash', return_value='image'), \
             patch.object(gate, 'service_state', return_value=runtime), \
             patch.object(gate, 'staging_credentials', return_value=('synthetic', {})), \
             patch.object(gate, 'database_state', side_effect=[state, dict(state, **(preapply_change or {})), after]), \
             patch.object(gate.migration, 'migrate') as migrate, \
             patch.object(gate, 'publish_image', return_value='image'), \
             patch.object(gate, 'deploy', return_value={'revision': 'synthetic', 'image_digest': 'image'}) as deploy:
            result = gate.main()
        return result, [call.args[1] for call in migrate.call_args_list], deploy.called

    def test_receipt_and_preapply_bind_catalog_and_policy(self):
        for change in [{'catalog_hash': 'drift'}, {'historical_baseline_hash': 'different-policy'}]:
            for point in ['approved_change', 'preapply_change']:
                with self.subTest(point=point, change=change):
                    status, actions, deployed = self.invoke(**{point: change})
                    self.assertEqual(status, 1)
                    self.assertNotIn('push', actions)
                    self.assertFalse(deployed)

    def test_postapply_history_change_prevents_deployment(self):
        status, actions, deployed = self.invoke(after_change={'base_history_hash': 'rewritten-history'})
        self.assertEqual(status, 1)
        self.assertIn('push', actions)
        self.assertFalse(deployed)
        self.assertEqual(self.invoke(), (0, ['preflight', 'list', 'dry-run', 'push'], True))


@unittest.skipUnless(os.environ.get('STAGING_CATALOG_DATABASE_URL'), 'Disposable catalog database runs in candidate source check')
class CatalogQueryTests(unittest.TestCase):
    def test_catalog_query_collects_real_postgres_rows_without_writes(self):
        import psycopg
        url = os.environ['STAGING_CATALOG_DATABASE_URL']
        parsed = urlsplit(url)
        self.assertEqual(parsed.hostname, '127.0.0.1')
        self.assertEqual(parsed.path, '/staging_catalog_test')
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute("""
CREATE TABLE template(team_id uuid,name text NOT NULL,deleted_at timestamptz,vcpu int,
 CONSTRAINT template_vcpu_range CHECK(vcpu BETWEEN 1 AND 32));
CREATE UNIQUE INDEX template_name_unique_per_team_active ON template(team_id,name) WHERE deleted_at IS NULL;
CREATE TABLE sandbox_snapshot(id uuid,team_id uuid,PRIMARY KEY(id,team_id));
CREATE TABLE sandbox(id uuid,team_id uuid,source_snapshot_id uuid,
 preview_access text NOT NULL DEFAULT 'public',preview_token_version integer NOT NULL DEFAULT 1,
 CONSTRAINT sandbox_preview_access_valid CHECK(preview_access IN ('public','private')),
 CONSTRAINT sandbox_source_snapshot_fk FOREIGN KEY(source_snapshot_id,team_id) REFERENCES sandbox_snapshot(id,team_id));
CREATE INDEX sandbox_by_source_snapshot ON sandbox(source_snapshot_id) WHERE source_snapshot_id IS NOT NULL;
CREATE TABLE sandbox_preview_policy(id uuid);
CREATE TABLE sandbox_published_port(id uuid);
ALTER TABLE sandbox_preview_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE sandbox_published_port ENABLE ROW LEVEL SECURITY;
CREATE SCHEMA analytics;
CREATE VIEW analytics.synthetic AS SELECT 1 AS value;
CREATE ROLE grafana_readonly LOGIN;
GRANT USAGE ON SCHEMA analytics TO grafana_readonly;
GRANT SELECT ON analytics.synthetic TO grafana_readonly;
CREATE FUNCTION example() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$;
CREATE TRIGGER example BEFORE INSERT ON sandbox FOR EACH ROW EXECUTE FUNCTION example();
""")
        with psycopg.connect(url) as conn:
            conn.execute('SET TRANSACTION READ ONLY')
            catalog = gate.historical.catalog_state(conn, {'functions': {'example': {}}})
            self.assertEqual(conn.execute('SHOW transaction_read_only').fetchone()[0], 'on')
        self.assertEqual(catalog['functions'], [['example', '', ' BEGIN RETURN NEW; END ', 'plpgsql', False, 'v', 'trigger', None]])
        self.assertEqual(catalog['triggers'], [['sandbox', 'example', 'O', 'example', 'CREATE TRIGGER example BEFORE INSERT ON public.sandbox FOR EACH ROW EXECUTE FUNCTION example()']])
        self.assertEqual(catalog['analytics_grants'], [True, True])
        self.assertEqual(catalog['grafana_role'], [['grafana_readonly', True, False, False, False, False, False]])
        self.assertEqual(catalog['columns'], [['name', 'text', True], ['source_snapshot_id', 'uuid', False]])
        self.assertEqual(catalog['legacy_columns'], [['preview_access', 'text', True, "'public'::text"],
                                                     ['preview_token_version', 'integer', True, '1']])
        self.assertEqual(catalog['preview_tables'], [['sandbox_preview_policy', True, False],
                                                     ['sandbox_published_port', True, False]])
        self.assertEqual([r[:3] for r in catalog['constraints']],
                         [['sandbox', 'sandbox_preview_access_valid', True], ['template', 'template_vcpu_range', True]])
        self.assertEqual(catalog['source_snapshot_fk'], [['sandbox_source_snapshot_fk', True,
                         'FOREIGN KEY (source_snapshot_id, team_id) REFERENCES sandbox_snapshot(id, team_id)']])
        self.assertEqual([r[:4] for r in catalog['indexes']],
                         [['sandbox_by_source_snapshot', True, True, False], ['template_name_unique_per_team_active', True, True, True]])

class TargetTests(unittest.TestCase):
    def setUp(self):
        projects = patch.dict(gate.migration.PROJECTS, staging='stagingprojectexample', use4='productionexampleone')
        projects.start()
        self.addCleanup(projects.stop)
        account = patch.object(gate, 'STRIPE_ACCOUNT', 'acct_example')
        account.start()
        self.addCleanup(account.stop)

    def test_live_stripe_key_and_wrong_test_account_fail_before_any_mutation(self):
        url = 'postgresql://postgres:example@db.stagingprojectexample.supabase.co/postgres'
        metadata = json.dumps({'name': 'projects/example/secrets/example/versions/1', 'state': 'ENABLED'})
        for key, account in [('sk_live_example', gate.STRIPE_ACCOUNT), ('sk_test_example', 'acct_other')]:
            with self.subTest(key=key), patch.object(gate, 'gcloud', return_value=metadata), \
                 patch.object(gate, 'command', side_effect=[url, key]), \
                 patch.object(gate.urllib.request, 'urlopen') as request:
                request.return_value.__enter__.return_value = io.BytesIO(json.dumps({'id': account}).encode())
                with self.assertRaises(gate.GateError):
                    gate.staging_credentials()
                if key.startswith('sk_live_'):
                    request.assert_not_called()

    def test_deploy_pins_validated_versions_despite_latest_rotation(self):
        versions = {key: str(i + 1) for i, key in enumerate(gate.SECRETS)}
        before = self.service()
        after = self.service()
        for entry in after['spec']['template']['spec']['containers'][0]['env']:
            entry['valueFrom']['secretKeyRef']['key'] = versions[entry['name']]
        revision = gate.SERVICE + '-candidate-123'
        after['status'].update(latestReadyRevisionName=revision, traffic=[{'revisionName': revision, 'percent': 100}])
        with patch.dict(os.environ, GITHUB_RUN_ID='123'), \
             patch.object(gate, 'service_state', side_effect=[before, after, after]) as service, \
             patch.object(gate, 'command', return_value='') as command, \
             patch.object(gate, 'gcloud', return_value=json.dumps({'status': {'imageDigest': gate.IMAGE + '@sha256:' + 'd' * 64}})), \
             patch.object(gate.urllib.request, 'urlopen') as request:
            request.return_value.__enter__.return_value.status = 200
            gate.deploy('sha256:' + 'd' * 64, before, versions)
        args = command.call_args_list[0].args[0]
        self.assertEqual(args[args.index('--update-secrets') + 1],
                         ','.join(key + '=' + name + ':' + versions[key] for key, name in gate.SECRETS.items()))
        self.assertEqual(service.call_args_list[1].args, (versions,))
        self.assertEqual(service.call_args_list[2].args, (versions,))

    def test_verified_numeric_runtime_ref_must_not_drift_to_latest(self):
        versions = {key: '1' for key in gate.SECRETS}
        with patch.object(gate, 'gcloud', return_value=json.dumps(self.service())), self.assertRaises(gate.GateError):
            gate.service_state(versions)

    def service(self):
        return {'status': {'url': gate.URL}, 'spec': {'template': {'spec': {'containers': [
            {'env': [{'name': key, 'valueFrom': {'secretKeyRef': {'name': name, 'key': 'latest'}}}
                     for key, name in gate.SECRETS.items()]}]}}}}

    def test_wrong_service_secret_project_alias_or_plaintext_blocks(self):
        good = self.service()
        with patch.object(gate, 'gcloud', return_value=json.dumps(good)):
            self.assertEqual(gate.service_state(), good)
        wrong_url = self.service()
        wrong_url['status']['url'] = 'https://production.example.com'
        alias = self.service()
        alias['spec']['template']['metadata'] = {'annotations': {'run.googleapis.com/secrets': 'other-project-secret'}}
        plaintext = self.service()
        plaintext['spec']['template']['spec']['containers'][0]['env'][0] = {'name': 'DATABASE_URL', 'value': 'hidden'}
        for value in [wrong_url, alias, plaintext]:
            with patch.object(gate, 'gcloud', return_value=json.dumps(value)), self.assertRaises(gate.GateError):
                gate.service_state()

    def test_production_database_url_and_transaction_pooler_are_rejected(self):
        for url in ['postgresql://postgres:example@db.productionexampleone.supabase.co/postgres',
                    'postgresql://postgres.stagingprojectexample:example@aws-0-us-east-1.pooler.supabase.com:6543/postgres']:
            with self.assertRaises(gate.migration.MigrationError):
                gate.migration.verify_connection_identity(url, 'staging')

    def test_command_error_never_contains_secret_output_or_arguments(self):
        result = subprocess.CompletedProcess(['private'], 1, 'secret-output', 'secret-error')
        with patch.object(gate.subprocess, 'run', return_value=result), self.assertRaises(gate.GateError) as raised:
            gate.command(['private', 'secret-value'])
        self.assertNotIn('secret', str(raised.exception))


class CohortTests(unittest.TestCase):
    def test_cohort_covers_every_catalog_plan_once_the_catalog_exists(self):
        catalog = gate.cohort_sql(True)
        self.assertIn("SELECT offer_key FROM billing_plan", catalog)
        self.assertIn("c.offer_key='yc_2026'", catalog)
        before = gate.cohort_sql(False)
        self.assertNotIn('billing_plan', before.replace('billing_plan_', ''))
        self.assertIn("('pro_monthly'),('pro_annual')", before)


if __name__ == '__main__':
    unittest.main()
