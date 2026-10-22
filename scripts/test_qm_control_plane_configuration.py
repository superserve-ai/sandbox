"""Evaluate staging wiring without providers, credentials or remote state.

The failure modes are partial enablement, an unpinned/shared credential, and
replacement of existing settings/grants when the optional service is added.
"""
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGING = ROOT / 'infra/envs/staging/us-central1'
CONFIG = {
    'namespace': 'example-teams',
    'authority_id': '9136eb23-9dcb-4786-90ab-2fd24b8b9b3e',
    'home_region': 'use',
    'credential_secret_id': 'qm-team-service-token-example',
    'credential_secret_version': '7',
}


def match(pattern, source):
    found = re.search(pattern, source, re.S | re.M)
    if found is None:
        raise AssertionError(f'missing Terraform expression: {pattern}')
    return found[1]


class OrganizationTeamConfigurationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.directory = Path(cls.tmp.name)
        variables = (STAGING / 'variables.tf').read_text()
        identity = (STAGING / 'control-plane-identity.tf').read_text()
        main = (STAGING / 'main.tf').read_text()
        variable = match(r'(^variable "qm_team_service" \{.*?^\})', variables)
        team_locals = match(r'(^locals \{\n  qm_team_service_env =.*?^\})', identity)
        api = match(r'module "api" \{(.*?)^\}', main)
        env = match(r'^  env = (.*?)\n  secrets =', api)
        secrets = match(r'^  secrets = (.*?)\n  vpc_connector =', api)
        grants = match(r'  controlplane_secret_ids = (toset\(concat\(.*?\n  \)\))', identity)
        # Keep the real merge/set expressions; replace unrelated external
        # resources with distinct fixtures so removed grants/settings are visible.
        fixtures = {
            'local.promotion_evidence_secrets': {'PROMOTION_CAPTURE_TOKEN': {'secret': 'promotion-fixture'}},
            'local.yc_claim_secrets': {'YC_CLAIM_TOKEN': {'secret': 'claim-fixture'}},
            'var.yc_claim_api_access_enabled': True,
        }
        def replace(found):
            ref = found[0]
            if ref.startswith('local.qm_team_service_'):
                return ref
            return json.dumps(fixtures.get(ref, ref.replace('.', '-')))
        def isolate(expression):
            return re.sub(r'\b(?:var|local|module|google_[a-z_]+)\.[\w.]+(?:\["[\w-]+"\]\.\w+)?', replace, expression)
        source = variable + '\n' + team_locals + '\n' + '\n'.join(
            f'output "{name}" {{ value = {isolate(expression)} }}'
            for name, expression in [('env', env), ('secrets', secrets), ('grants', grants)]
        )
        (cls.directory / 'main.tf').write_text(source)
        cls.identity = identity

    def plan(self, config=None, valid=True, omit=False):
        values = {} if omit else {'qm_team_service': config}
        (self.directory / 'test.auto.tfvars.json').write_text(json.dumps(values))
        command = ['terraform', '-chdir=' + str(self.directory)]
        result = subprocess.run(command + ['plan', '-input=false', '-refresh=false', '-lock=false', '-out=test.plan'],
                                text=True, capture_output=True, timeout=30)
        if not valid:
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertRegex(result.stderr, 'Invalid value|Invalid function argument')
            return
        self.assertEqual(result.returncode, 0, result.stderr)
        shown = subprocess.run(command + ['show', '-json', 'test.plan'], text=True,
                               capture_output=True, check=True, timeout=30)
        return {key: value['value'] for key, value in json.loads(shown.stdout)['planned_values']['outputs'].items()}

    def test_default_and_null_leave_service_disabled(self):
        absent = self.plan(omit=True)
        self.assertEqual(absent, self.plan())
        self.assertFalse(any(key.startswith('QM_TEAM_') for key in absent['env'] | absent['secrets']))
        self.assertFalse(any('qm-team-service-token' in value for value in absent['grants']))

    def test_enabled_config_preserves_other_settings_and_grants(self):
        before, after = self.plan(), self.plan(CONFIG)
        expected_env = {'QM_TEAM_NAMESPACE': CONFIG['namespace'], 'QM_TEAM_AUTHORITY_ID': CONFIG['authority_id'],
                        'QM_TEAM_REGION': CONFIG['home_region']}
        self.assertEqual(after['env'], before['env'] | expected_env)
        self.assertEqual(after['secrets'], before['secrets'] | {'QM_TEAM_SERVICE_TOKEN': {
            'secret': CONFIG['credential_secret_id'], 'version': '7'}})
        self.assertEqual(set(after['grants']), set(before['grants']) | {CONFIG['credential_secret_id']})
        grant = match(r'resource "google_secret_manager_secret_iam_member" "controlplane_runtime" \{(.*?)^\}', self.identity)
        self.assertRegex(grant, r'for_each\s*=\s*local.controlplane_secret_ids')
        self.assertRegex(grant, r'secret_id\s*=\s*each.value')
        self.assertRegex(grant, r'role\s*=\s*"roles/secretmanager.secretAccessor"')
        self.assertIn('serviceAccount:${google_service_account.controlplane_runtime.email}', grant)

    def test_partial_and_null_fields_are_rejected(self):
        for key in CONFIG:
            for missing in (True, False):
                with self.subTest(key=key, missing=missing):
                    config = dict(CONFIG)
                    if missing:
                        del config[key]
                    else:
                        config[key] = None
                    self.plan(config, valid=False)

    def test_invalid_identity_or_unpinned_shared_credential_is_rejected(self):
        for key, values in {
            'namespace': ['', 'Example', 'a', 'a' * 41],
            'authority_id': ['00000000-0000-0000-0000-000000000000', 'not-a-uuid', CONFIG['authority_id'].upper()],
            'home_region': ['us-west-2', ''],
            'credential_secret_id': ['internal-api-token-staging', 'operator-api-token-staging',
                                     'projects/example/secrets/qm-team-service-token-example'],
            'credential_secret_version': ['latest', '0', '-1', '1.0', ' 7', ''],
        }.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    self.plan(CONFIG | {key: value}, valid=False)


if __name__ == '__main__':
    unittest.main()
