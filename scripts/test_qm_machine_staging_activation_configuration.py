"""Evaluate activation wiring without providers, credentials or remote state.

Catch accidental activation, loss of explicit false predicates, environment
confusion, and replacement of existing API settings at the deployment seam.
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
    'contract_revision': 'machine-identity-v1',
    'environment': 'staging',
    'ownership_ready': True,
    'verifier_ready': True,
    'operator_ready': True,
}


def match(pattern, source):
    found = re.search(pattern, source, re.S | re.M)
    if found is None:
        raise AssertionError(f'missing Terraform expression: {pattern}')
    return found[1]


class StagingMachineActivationConfigurationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.directory = Path(cls.tmp.name)
        variables = (STAGING / 'variables.tf').read_text()
        main = (STAGING / 'main.tf').read_text()
        declarations = '\n'.join(match(r'(^variable "' + name + r'" \{.*?^\})', variables)
                                 for name in ['qm_machine_identity_activation', 'project_id', 'environment', 'region'])
        activation = match(r'(^locals \{\n  qm_machine_identity_env =.*?^\})', main)
        environment = match(r'^  (environment\s*=\s*var.environment)', main)
        api = match(r'module "api" \{(.*?)^\}', main)
        env = match(r'^  env = (.*?)\n  secrets\s*=', api)
        # Evaluate the real merge; isolate unrelated resources with distinct
        # fixtures so deleting/replacing another API setting remains observable.
        def replace(found):
            ref = found[0]
            if ref in ('local.qm_machine_identity_env', 'local.environment'):
                return ref
            if ref == 'local.qm_team_service_env':
                return json.dumps({'QM_TEAM_NAMESPACE': 'example-teams', 'QM_TEAM_REGION': 'use'})
            return json.dumps(ref.replace('.', '-'))
        env = re.sub(r'\b(?:var|local|module)\.[\w.-]+', replace, env)
        (cls.directory / 'main.tf').write_text(
            declarations + '\nlocals { ' + environment + ' }\n' + activation +
            '\noutput "env" { value = ' + env + ' }\n')

    def plan(self, config=None, valid=True, omit=False, **root_values):
        values = root_values if omit else root_values | {'qm_machine_identity_activation': config}
        (self.directory / 'test.auto.tfvars.json').write_text(json.dumps(values))
        command = ['terraform', '-chdir=' + str(self.directory)]
        result = subprocess.run(command + ['plan', '-input=false', '-refresh=false', '-lock=false', '-out=test.plan'],
                                text=True, capture_output=True, timeout=30)
        if not valid:
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn('Invalid value', result.stderr)
            return
        self.assertEqual(result.returncode, 0, result.stderr)
        shown = subprocess.run(command + ['show', '-json', 'test.plan'], text=True,
                               capture_output=True, check=True, timeout=30)
        return json.loads(shown.stdout)['planned_values']['outputs']['env']['value']

    def test_default_and_null_leave_issuance_disabled(self):
        absent = self.plan(omit=True)
        self.assertEqual(absent, self.plan())
        self.assertFalse(any(key.startswith('QM_MACHINE_AUTH_') for key in absent))

    def test_activation_preserves_other_settings(self):
        before, after = self.plan(), self.plan(CONFIG)
        expected = {
            'QM_MACHINE_AUTH_CONTRACT_REVISION': 'machine-identity-v1',
            'QM_MACHINE_AUTH_ENVIRONMENT': 'staging',
            'QM_MACHINE_AUTH_CONFIGURED_ENVIRONMENT': 'staging',
            'QM_MACHINE_AUTH_OWNERSHIP_READY': 'true',
            'QM_MACHINE_AUTH_VERIFIER_READY': 'true',
            'QM_MACHINE_AUTH_OPERATOR_READY': 'true',
        }
        self.assertEqual(after, before | expected)

    def test_each_false_predicate_is_preserved(self):
        for name in ('ownership_ready', 'verifier_ready', 'operator_ready'):
            with self.subTest(name=name):
                env = self.plan(CONFIG | {name: False})
                self.assertEqual(env['QM_MACHINE_AUTH_' + name.upper()], 'false')

    def test_partial_and_null_fields_are_rejected(self):
        for name in CONFIG:
            for missing in (True, False):
                with self.subTest(name=name, missing=missing):
                    config = dict(CONFIG)
                    if missing:
                        del config[name]
                    else:
                        config[name] = None
                    self.plan(config, valid=False)

    def test_incompatible_activation_is_rejected(self):
        for config in (CONFIG | {'contract_revision': 'unknown'}, CONFIG | {'environment': 'production'}):
            self.plan(config, valid=False)
        for key, value in {'project_id': 'example-project', 'environment': 'production', 'region': 'us-east4'}.items():
            with self.subTest(key=key):
                self.plan(CONFIG, valid=False, **{key: value})


if __name__ == '__main__':
    unittest.main()
