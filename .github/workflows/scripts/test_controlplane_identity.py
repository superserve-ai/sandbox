"""Operator credentials must never be deployed under a host runtime identity."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location(
    'identity_check', Path(__file__).with_name('check_controlplane_identity.py'))
identity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identity)


class ControlplaneIdentityTest(unittest.TestCase):
    def test_promotion_evidence_secrets_reach_every_controlplane(self):
        for environment, region, secret_file in (
            ('production', 'us-east4', 'controlplane-identity.tf'),
            ('production', 'us-west2', 'controlplane-identity.tf'),
            ('staging', 'us-central1', 'control-plane-identity.tf'),
        ):
            root = ROOT / 'infra/envs' / environment / region
            secrets = (root / secret_file).read_text()
            main = (root / 'main.tf').read_text()
            with self.subTest(environment=environment, region=region):
                for name, resource in (
                    ('PROMOTION_AUTH_DATABASE_URL', 'promotion_auth_database_url'),
                    ('PROMOTION_CAPTURE_TOKEN', 'promotion_capture_token'),
                    ('PROMOTION_ACCOUNT_TOKEN', 'promotion_account_token'),
                ):
                    self.assertIn(f'google_secret_manager_secret.{resource}.secret_id', secrets + main)
                    self.assertRegex(secrets + main, rf'{name}\s*=\s*\{{\s*secret\s*=\s*google_secret_manager_secret\.{resource}\.secret_id')
                    self.assertNotRegex(main, rf'(?m)^\s*{name}\s*=\s*"')
                self.assertIn('roles/secretmanager.secretAccessor', secrets)
                self.assertIn('controlplane_runtime.email', secrets)

    def test_shared_auth_proxy_role_has_only_rpc_privileges(self):
        migration = (ROOT / 'supabase/shared-auth-migrations/20260925190000_promotion_evidence_proxy_role.sql').read_text()
        self.assertIn('LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION', migration)
        self.assertIn('REVOKE ALL ON public.signup_device_attempt, public.signup_device_account_evidence', migration)
        for function in ('create_signup_device_attempt()',
                         'verify_signup_device_attempt(uuid,uuid,text,text,timestamptz)',
                         'bind_signup_device_account(uuid,uuid)',
                         'get_signup_device_account_evidence(uuid)'):
            self.assertIn(function, migration)
        self.assertNotRegex(migration, r'GRANT\s+(?:SELECT|INSERT|UPDATE|DELETE|ALL)\s+ON\s+(?:TABLE\s+)?public\.signup_device_')

    def service(self, cell):
        secrets = [('OPERATOR_API_TOKEN', 'operator-api-token'),
                   ('PROMOTION_AUTH_DATABASE_URL', 'promotion-auth-database-url'),
                   ('PROMOTION_CAPTURE_TOKEN', 'promotion-capture-token'),
                   ('PROMOTION_ACCOUNT_TOKEN', 'promotion-account-token')]
        return {'spec': {'template': {'spec': {
            'serviceAccountName': f'superserve-controlplane-{cell}@example-project.iam.gserviceaccount.com',
            'containers': [{'env': [{'name': name, 'valueFrom': {
                'secretKeyRef': {'name': f'{secret}-{cell}', 'key': 'latest'}}}
                for name, secret in secrets]}],
        }}}}

    def test_accepts_both_cell_identities(self):
        for cell in ('use4', 'usw2'):
            identity.check(self.service(cell), 'example-project', cell)

    def test_rejects_shared_host_identity_and_missing_or_wrong_credentials(self):
        service = self.service('use4')
        mutations = [
            lambda s: s.update(serviceAccountName='superserve-api-runner@example-project.iam.gserviceaccount.com'),
            lambda s: s.update(containers=[]),
            lambda s: s['containers'][0].update(env=[]),
            lambda s: s['containers'][0]['env'][0].update(value='example-token', valueFrom={}),
            lambda s: s['containers'][0]['env'][0]['valueFrom']['secretKeyRef'].update(name='internal-api-token'),
            lambda s: s['containers'][0]['env'][0]['valueFrom']['secretKeyRef'].update(name='operator-api-token-usw2'),
            lambda s: s['containers'][0]['env'][0]['valueFrom']['secretKeyRef'].update(key=''),
            lambda s: s['containers'][0]['env'].pop(1),
            lambda s: s['containers'][0]['env'][1].update(value='example-url', valueFrom={}),
            lambda s: s['containers'][0]['env'][2]['valueFrom']['secretKeyRef'].update(name='promotion-capture-token-usw2'),
            lambda s: s['containers'][0]['env'][3]['valueFrom']['secretKeyRef'].update(key=''),
        ]
        for mutate in mutations:
            candidate = deepcopy(service)
            mutate(candidate['spec']['template']['spec'])
            with self.assertRaises(ValueError):
                identity.check(candidate, 'example-project', 'use4')

    def test_production_deploys_check_identity_before_image_update(self):
        for workflow in ('deploy-api.yml', 'terraform-cd.yml'):
            source = (ROOT / '.github/workflows' / workflow).read_text()
            for cell, suffix in (('USE4', 'use4'), ('USW', 'usw2')):
                command = 'gcloud run services update ${{ vars.CLOUD_RUN_SERVICE_' + cell + ' }}'
                prefix = source.split(command, 1)[0].rsplit('run: |', 1)[1]
                self.assertIn('check_controlplane_identity.py', prefix)
                self.assertIn('--cell ' + suffix, prefix)

    def test_terraform_limits_operator_access_to_controlplane(self):
        for region in ('us-east4', 'us-west2'):
            root = ROOT / 'infra/envs/production' / region
            source = (root / 'main.tf').read_text()
            api = source.split('module "api" {', 1)[1].split('\n}', 1)[0]
            self.assertIn('service_account_email = google_service_account.controlplane_runtime.email', api)
            self.assertRegex(api, r'(?m)^\s*secrets\s*=\s*local\.controlplane_secrets\s*$')
            self.assertRegex(api, r'(?m)^\s*secret_volumes\s*=\s*local\.controlplane_secret_volumes\s*$')
            self.assertIn('COMPUTE_RESTRICTIONS_FILE = "${local.controlplane_secret_volumes.compute-restrictions.mount_path}/${local.controlplane_secret_volumes.compute-restrictions.path}"', api)
            self.assertIn('google_secret_manager_secret_iam_member.controlplane_runtime_secret_volumes', api)
            self.assertIn('google_secret_manager_secret_iam_member.controlplane_runtime_secrets', api)
            self.assertIn('google_kms_crypto_key_iam_member.controlplane_credentials', api)
            self.assertIn('google_service_account_iam_member.controlplane_deploy_act_as', api)
            grants = (root / 'controlplane-identity.tf').read_text()
            self.assertIn('for config in values(local.controlplane_secrets) : config.secret', grants)
            self.assertRegex(grants, r'secret\s*=\s*var\.compute_restrictions_secret_name')
            self.assertRegex(grants, r'mount_path\s*=\s*"/etc/superserve"')
            self.assertRegex(grants, r'path\s*=\s*"abuse-restrictions.json"')
            self.assertIn('OPERATOR_API_TOKEN = {', grants)
            self.assertIn('roles/secretmanager.secretAccessor', grants)
            self.assertIn('roles/cloudkms.cryptoKeyEncrypterDecrypter', grants)
            self.assertIn('roles/iam.serviceAccountUser', grants)
            self.assertIn('data.google_service_account.github_actions.email', grants)
            self.assertNotIn('api_runner.email', grants)
            self.assertNotIn('vmd_runtime.email', grants)
            for module in ('sandbox_host', 'sandbox_host_b', 'sandbox_host_2'):
                marker = f'module "{module}" {{'
                if marker in source:
                    host = source.split(marker, 1)[1].split('\n}', 1)[0]
                    self.assertNotIn('controlplane_runtime', host)
                    self.assertNotIn('OPERATOR_API_TOKEN', host)

    def test_production_permission_probes_include_cell_operator_secret(self):
        for workflow in ('deploy-api.yml', 'terraform-cd.yml'):
            source = (ROOT / '.github/workflows' / workflow).read_text()
            probes = source.split('bash scripts/verify-control-plane-kms.sh')[1:]
            self.assertEqual(len(probes), 2, workflow)
            for probe in probes:
                command = probe.split('\n\n', 1)[0]
                cell = re.search(r'control-plane-kms/(use4|usw2)"', command).group(1)
                with self.subTest(workflow=workflow, cell=cell):
                    self.assertIn('--secret "${TF_VAR_compute_restrictions_secret_name:?Set COMPUTE_RESTRICTIONS_SECRET_NAME}"', command)
                    self.assertIn(f'--secret operator-api-token-{cell} ', command)
                    other = 'usw2' if cell == 'use4' else 'use4'
                    self.assertNotIn(f'--secret operator-api-token-{other} ', command)

    def test_cd_policy_management_is_scoped_to_credentials_key(self):
        source = (ROOT / 'infra/envs/production/us-central1/cd-credentials-key-iam.tf').read_text()
        binding = re.search(r'resource "google_project_iam_member" "cd_credentials_key_iam" \{(.*?)\n\}', source, re.S)
        self.assertIsNotNone(binding)
        source = binding.group(1)
        condition = re.search(r'condition \{(.*?)\n  \}', source, re.S)
        self.assertIsNotNone(condition)
        self.assertIn('role    = "roles/iam.securityAdmin"', source)
        self.assertIn('serviceAccount:superserve-github-actions@${local.project_id}.iam.gserviceaccount.com', source)
        self.assertIn("resource.type == 'cloudkms.googleapis.com/CryptoKey' && resource.name == 'projects/${local.project_id}/locations/us-central1/keyRings/superserve/cryptoKeys/credentials-kek'", condition.group(1))
        self.assertNotIn('roles/cloudkms.admin', source)
        self.assertNotIn('resource.name.startsWith', source)

    def test_key_policy_permission_bootstraps_before_both_regions(self):
        workflow = (ROOT / '.github/workflows/terraform-cd.yml').read_text()
        self.assertIn("'.github/workflows/scripts/wait_credentials_key_iam.py'", workflow.split('jobs:', 1)[0])
        bootstrap = workflow.split('  production-us-central1-bootstrap:', 1)[1].split('\n  production-us-west2-infra:', 1)[0]
        self.assertIn('-target=google_project_iam_member.cd_credentials_key_iam', bootstrap)
        self.assertIn('wait_credentials_key_iam.py', bootstrap)
        self.assertLess(bootstrap.index('terraform apply'), bootstrap.index('wait_credentials_key_iam.py'))
        manual = (ROOT / '.github/workflows/terraform-rollout-production.yml').read_text().split('  central1:', 1)[0]
        self.assertIn('-target=google_project_iam_member.cd_credentials_key_iam', manual)
        self.assertLess(manual.index('apply -input=false -auto-approve cd-key.tfplan'), manual.index('wait_credentials_key_iam.py'))
        self.assertLess(manual.index('wait_credentials_key_iam.py'), manual.index('- name: Terraform apply production/us-west2'))
        for region in ('us-east4', 'us-west2'):
            job = workflow.split(f'  production-{region}-infra:', 1)[1].split('\n    steps:', 1)[0]
            self.assertIn('production-us-central1-bootstrap', job)

    def test_controlplane_key_grants_exclude_deployment_identity(self):
        for region in ('us-east4', 'us-west2'):
            source = (ROOT / 'infra/envs/production' / region / 'controlplane-identity.tf').read_text()
            grants = re.findall(r'resource "google_kms_crypto_key_iam_member" "[^"]+" \{(.*?)\n\}', source, re.S)
            self.assertTrue(grants, region)
            for grant in grants:
                self.assertRegex(grant, r'role\s*=\s*"roles/cloudkms.cryptoKeyEncrypterDecrypter"')
                self.assertRegex(grant, r'member\s*=\s*"serviceAccount:\$\{google_service_account.controlplane_runtime.email\}"')
                self.assertNotIn('github_actions', grant)
            self.assertNotIn('controlplane_deploy_kms_admin', source)


if __name__ == '__main__':
    unittest.main()
