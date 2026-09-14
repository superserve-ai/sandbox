"""Staging runtime values must reach the deployment and fail closed when absent."""
import os
from pathlib import Path
import re
import subprocess
import textwrap
import unittest

WORKFLOW = (Path(__file__).parents[1] / 'deploy-vmd.yml').read_text()
STAGING = WORKFLOW.split('  deploy-staging:', 1)[1].split('  deploy-production:', 1)[0]
STEP = STAGING.split('      - name: Discover and deploy to VMD instances', 1)[1]
INPUTS = {
    'CONTROL_PLANE_URL': 'vars.CONTROL_PLANE_URL_STAGING',
    'DATABASE_URL': 'secrets.DATABASE_URL_STAGING',
    'INTERNAL_API_TOKEN': 'secrets.STAGING_INTERNAL_API_TOKEN',
}


class StagingRuntimeInputsTest(unittest.TestCase):
    def test_staging_environment_exposes_runtime_inputs(self):
        self.assertIn('    environment: staging', STAGING)
        env = STEP.split('        run: |', 1)[0]
        for name, source in INPUTS.items():
            self.assertRegex(env, re.escape(name + ': ${{ ' + source + ' }}'))

    def test_missing_values_never_invoke_deploy(self):
        body = textwrap.dedent(STEP.split('        run: |', 1)[1])
        prelude = 'set -eu\nsource() { :; }\npython3() { echo deploy-invoked; }\n'
        for missing in (*INPUTS, None):
            with self.subTest(missing=missing):
                env = dict(os.environ)
                for name in INPUTS:
                    env[name] = '' if name == missing else 'configured-test-value'
                result = subprocess.run(['bash', '-c', prelude + body], env=env,
                                        text=True, capture_output=True)
                if missing:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(INPUTS[missing].split('.', 1)[1] + ' is unset', result.stderr)
                    self.assertNotIn('deploy-invoked', result.stdout)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn('deploy-invoked', result.stdout)
