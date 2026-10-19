"""Reject extra IAM effects and saved-plan substitution before any apply."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('yc_claim_access', ROOT / 'scripts/yc_claim_access.py')
access = importlib.util.module_from_spec(spec)
spec.loader.exec_module(access)
SHA = 'a' * 40
HASH = 'b' * 64


def plan():
    return {'errored': False, 'applyable': True, 'complete': False,
            'terraform_version': access.TERRAFORM_VERSION, 'resource_changes': [
        {'address': address, 'mode': 'managed', 'type': 'google_secret_manager_secret_iam_member',
         'provider_name': 'registry.terraform.io/hashicorp/google', 'change': {
             'actions': ['create'], 'before': None,
             'after': {'project': 'rayai-dev', 'secret_id': secret, 'role': 'roles/secretmanager.secretAccessor',
                       'member': access.MEMBER, 'condition': []}, 'after_unknown': {'id': True, 'etag': True}}}
        for address, secret in access.TARGETS.items()]}


def environment(mode='plan'):
    return dict(YC_CLAIM_ACCESS=mode, CONFIRM=mode, PRIVATECA_BOOTSTRAP='false', SMOKE_ONLY='false',
                PROXY_PREPARE='false', PROXY_RUNTIME_IAM='false', PROXY_MIGRATION='none',
                GITHUB_REPOSITORY=access.REPOSITORY, GITHUB_EVENT_NAME='workflow_dispatch',
                GITHUB_SHA=SHA, YC_CLAIM_SOURCE_SHA=SHA, GITHUB_RUN_ATTEMPT='1',
                DEPLOYMENT_SERVICE_ACCOUNT=access.DEPLOYER, GITHUB_RUN_ID='456',
                YC_CLAIM_PLAN_RUN_ID='123' if mode == 'apply' else '',
                YC_CLAIM_PLAN_SHA256=HASH if mode == 'apply' else '')


def receipt():
    return dict(repository=access.REPOSITORY, workflow=access.WORKFLOW, source_sha=SHA,
                run_id='123', run_attempt=1, phase='plan', terraform_version=access.TERRAFORM_VERSION,
                plan_uri=access.prefix(SHA, '123') + '/approved.tfplan', plan_generation='789',
                plan_sha256=HASH, changes=access.validate_plan(plan()))


class ClaimAccessTest(unittest.TestCase):
    def test_command_errors_expose_only_structured_source_metadata(self):
        secret = 'private-credential-value'
        diagnostic = {'type': 'diagnostic', '@message': secret, 'diagnostic': {
            'severity': 'error', 'summary': secret, 'detail': secret, 'code': secret,
            'snippet': {'values': [{'value': secret}]}, 'address': secret,
            'range': {'filename': 'control-plane-identity.tf', 'start': {'line': 96}}}}
        result = access.subprocess.CompletedProcess([], 1, stdout=json.dumps(diagnostic), stderr=secret)
        with patch.object(access.subprocess, 'run', return_value=result):
            with self.assertRaises(ValueError) as error:
                access.run('terraform', 'plan', '-json', cwd=access.DIRECTORY)
        safe = json.loads(str(error.exception))
        self.assertEqual(safe, {'command': 'terraform plan', 'exit_status': 1, 'diagnostics': [
            {'severity': 'error', 'file': 'infra/envs/staging/us-central1/control-plane-identity.tf', 'line': 96}]})
        self.assertNotIn(secret, str(error.exception))

    def test_diagnostic_metadata_rejects_unknown_paths_fields_and_types(self):
        secret = 'private-credential-value'
        cases = [None, secret, {'type': 'diagnostic', 'diagnostic': secret}]
        for filename in ('/outside/' + secret, '../../../../../' + secret, secret + '\x00', [], None):
            cases.append({'type': 'diagnostic', 'diagnostic': {'severity': secret,
                'range': {'filename': filename, 'start': {'line': secret}}, 'address': secret}})
        cases.append({'type': 'diagnostic', 'diagnostic': {'severity': 'warning',
            'range': {'filename': 'main.tf', 'start': {'line': -1}}}})
        output = '\n'.join(json.dumps(c) for c in cases)
        safe = access.diagnostic_metadata(output, access.DIRECTORY)
        self.assertNotIn(secret, json.dumps(safe))
        self.assertEqual(safe[-1], {'severity': 'warning', 'file': 'infra/envs/staging/us-central1/main.tf'})
        self.assertEqual(len(access.diagnostic_metadata(output * 100, access.DIRECTORY)), 100)

    def test_exact_two_grants_and_targeted_incomplete_flag(self):
        p = plan()
        p['resource_changes'].append({'address': 'unchanged', 'mode': 'managed', 'change': {'actions': ['no-op']}})
        self.assertEqual(len(access.validate_plan(p)), 2)

    def test_extra_missing_duplicate_and_destructive_changes_rejected(self):
        extra = deepcopy(plan()['resource_changes'][0])
        extra['address'] = 'module.api.google_cloud_run_v2_service.this'
        extra['change']['actions'] = ['update']
        cases = []
        for action in (['update'], ['delete'], ['delete', 'create'], ['create', 'delete'], ['forget']):
            p = plan(); p['resource_changes'][0]['change']['actions'] = action; cases.append(p)
        p = plan(); p['resource_changes'].append(extra); cases.append(p)
        p = plan(); p['resource_changes'].pop(); cases.append(p)
        p = plan(); p['resource_changes'][1] = deepcopy(p['resource_changes'][0]); cases.append(p)
        for p in cases:
            with self.subTest(plan=p), self.assertRaises(ValueError):
                access.validate_plan(p)

    def test_wrong_grant_authority_and_unknown_values_rejected(self):
        for key, value in (('project', 'production'), ('secret_id', 'yc-claim-email-api-key-staging-usc1'),
                           ('role', 'roles/owner'), ('member', 'allUsers'),
                           ('condition', [{'expression': 'true'}])):
            p = plan(); p['resource_changes'][0]['change']['after'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): access.validate_plan(p)
        for key in ('project', 'secret_id', 'role', 'member', 'condition'):
            p = plan(); p['resource_changes'][0]['change']['after_unknown'][key] = True
            with self.subTest(unknown=key), self.assertRaises(ValueError): access.validate_plan(p)

    def test_import_move_defer_and_error_rejected(self):
        for mutation in ('import', 'move', 'defer', 'error', 'unapplyable', 'provider'):
            p = plan()
            if mutation == 'import': p['resource_changes'][0]['change']['importing'] = {'id': 'existing'}
            if mutation == 'move': p['resource_changes'][0]['previous_address'] = 'old'
            if mutation == 'defer': p['deferred_changes'] = [{'reason': 'unknown'}]
            if mutation == 'error': p['errored'] = True
            if mutation == 'unapplyable': p['applyable'] = False
            if mutation == 'provider': p['resource_changes'][0]['provider_name'] = 'unreviewed/provider'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): access.validate_plan(p)

    def test_no_op_imports_and_moves_cannot_hide_extra_state_changes(self):
        for kind in ('import', 'move', 'replace'):
            p = plan()
            extra = {'address': 'unrelated', 'mode': 'managed', 'change': {'actions': ['no-op']}}
            if kind == 'import': extra['change']['importing'] = {'id': 'existing'}
            if kind == 'move': extra['previous_address'] = 'old'
            if kind == 'replace': extra['change']['replace_paths'] = [['name']]
            p['resource_changes'].append(extra)
            with self.subTest(kind=kind), self.assertRaises(ValueError): access.validate_plan(p)

    def test_input_mixing_substitution_and_reruns_rejected(self):
        for mode in ('plan', 'apply'): access.validate_inputs(environment(mode))
        for key, value in (('PRIVATECA_BOOTSTRAP', 'true'), ('SMOKE_ONLY', 'true'),
                           ('PROXY_PREPARE', 'true'), ('PROXY_RUNTIME_IAM', 'true'),
                           ('PROXY_MIGRATION', 'hold'), ('GITHUB_RUN_ATTEMPT', '2'),
                           ('GITHUB_SHA', 'c' * 40), ('GITHUB_REPOSITORY', 'other/repo'),
                           ('CONFIRM', 'apply'), ('TF_CLI_ARGS_plan', '-refresh=false'),
                           ('DEPLOYMENT_SERVICE_ACCOUNT', 'alternate@example.com')):
            env = environment(); env[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): access.validate_inputs(env)
        env = environment(); env['YC_CLAIM_PLAN_RUN_ID'] = '123'
        with self.assertRaises(ValueError): access.validate_inputs(env)
        env = environment('apply'); env['YC_CLAIM_PLAN_SHA256'] = ''
        with self.assertRaises(ValueError): access.validate_inputs(env)

    def test_receipt_cannot_select_other_plan_or_source(self):
        access.validate_receipt(receipt(), SHA, '123', HASH)
        for key, value in (('source_sha', 'c' * 40), ('repository', 'other/repo'),
                           ('run_id', '999'), ('run_attempt', 2), ('phase', 'apply'),
                           ('workflow', 'another.yml'), ('plan_sha256', 'd' * 64),
                           ('plan_generation', ''), ('plan_uri', 'gs://other/approved.tfplan')):
            r = receipt(); r[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                access.validate_receipt(r, SHA, '123', HASH)

    def test_run_requires_successful_plan_step_at_same_source(self):
        metadata = dict(id=123, head_sha=SHA, path=access.WORKFLOW, event='workflow_dispatch',
                        repository={'full_name': access.REPOSITORY}, conclusion='success', run_attempt=1)
        jobs = {'jobs': [{'name': 'Staging YC claim credential access', 'conclusion': 'success',
                         'steps': [{'name': 'Save reviewed claim access plan', 'conclusion': 'success'}]}]}
        access.validate_run(metadata, jobs, '123', SHA)
        for key, value in (('head_sha', 'c' * 40), ('conclusion', 'failure'), ('path', 'other.yml'),
                           ('event', 'pull_request'), ('run_attempt', 2)):
            changed = deepcopy(metadata); changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                access.validate_run(changed, jobs, '123', SHA)
        jobs['jobs'][0]['steps'][0]['conclusion'] = 'skipped'
        with self.assertRaises(ValueError): access.validate_run(metadata, jobs, '123', SHA)

    def test_apply_never_replans_and_passes_guarded_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = environment('apply'); env.update(RUNNER_TEMP=tmp, GITHUB_STEP_SUMMARY=tmp + '/summary')
            r = receipt(); r['plan_sha256'] = access.hashlib.sha256(b'private plan').hexdigest()
            env['YC_CLAIM_PLAN_SHA256'] = r['plan_sha256']
            calls = []
            def fake_run(*args, **kwargs):
                calls.append(args)
                if args[:2] == ('git', 'rev-parse'): return SHA
                if args[:4] == ('gcloud', 'storage', 'buckets', 'describe'):
                    return json.dumps(dict(public_access_prevention='enforced', uniform_bucket_level_access=True,
                                           retention_policy={'retentionPeriod': '7776000'}))
                if args[:2] == ('terraform', 'version'): return json.dumps({'terraform_version': access.TERRAFORM_VERSION})
                if args[:2] == ('gh', 'api'): return '{}'
                if args[:3] == ('gcloud', 'storage', 'cp'):
                    Path(args[-1]).write_bytes(json.dumps(r).encode() if args[-1].endswith('receipt.json') else b'private plan')
                if args[:2] == ('terraform', 'show'): return json.dumps(plan())
                return ''
            with patch.dict(access.os.environ, env, clear=True), patch.object(access, 'run', side_effect=fake_run), patch.object(access, 'validate_run'):
                access.main('apply')
            self.assertFalse(any(c[:2] == ('terraform', 'plan') for c in calls))
            applies = [c for c in calls if c[:2] == ('terraform', 'apply')]
            self.assertEqual(len(applies), 1)
            self.assertEqual(applies[0][-1], tmp + '/yc-claim-access/approved.tfplan')
            self.assertFalse(Path(applies[0][-1]).exists())
            downloads = [c for c in calls if c[:3] == ('gcloud', 'storage', 'cp')]
            self.assertTrue(downloads[1][3].endswith('#789'))


if __name__ == '__main__':
    unittest.main()
