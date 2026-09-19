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
    def service(self, cell):
        return {'spec': {'template': {'spec': {
            'serviceAccountName': f'superserve-controlplane-{cell}@example-project.iam.gserviceaccount.com',
            'containers': [{'env': [{'name': 'OPERATOR_API_TOKEN', 'valueFrom': {
                'secretKeyRef': {'name': f'operator-api-token-{cell}', 'key': 'latest'}}}]}],
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
            self.assertIn('secrets = local.controlplane_secrets', api)
            self.assertIn('google_secret_manager_secret_iam_member.controlplane_runtime_secrets', api)
            self.assertIn('google_kms_crypto_key_iam_member.controlplane_credentials', api)
            self.assertIn('google_service_account_iam_member.controlplane_deploy_act_as', api)
            grants = (root / 'controlplane-identity.tf').read_text()
            self.assertIn('for config in values(local.controlplane_secrets) : config.secret', grants)
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
