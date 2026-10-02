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

    def run_staging(self, zones='', discovery_status=0, deploy_status=0, **overrides):
        body = textwrap.dedent(STEP.split('        run: |', 1)[1])
        env = dict(os.environ, DEPLOY_EVENT='workflow_dispatch',
                   DEPLOY_ENVIRONMENT='production', DEPLOY_TARGET='standby',
                   DEPLOY_PRODUCTION_CELL='usw2', DEPLOY_CELL='staging',
                   GCP_PROJECT='example-project', GCP_REGION='us-central1',
                   TEST_ZONES=zones, TEST_DISCOVERY_STATUS=str(discovery_status),
                   TEST_DEPLOY_STATUS=str(deploy_status))
        env.update({name: 'configured-test-value' for name in INPUTS})
        env.update(overrides)
        prelude = '''set -euo pipefail
        gcloud() {
          printf '%s\\n' "$*" >&2
          printf '%s\\n' "$TEST_ZONES"
          return "$TEST_DISCOVERY_STATUS"
        }
        python3() { echo deploy-invoked; return "$TEST_DEPLOY_STATUS"; }
        '''
        return subprocess.run(['bash', '-c', prelude + body], env=env,
                              cwd=Path(__file__).parents[3],
                              text=True, capture_output=True)

    def test_absent_staging_standby_skips_only_manual_production_standby(self):
        for zones in ('', 'projects/example-project/zones/us-west2-a'):
            result = self.run_staging(zones=zones, CONTROL_PLANE_URL='',
                                      DATABASE_URL='', INTERNAL_API_TOKEN='')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('No staging standby found', result.stdout)
            self.assertNotIn('deploy-invoked', result.stdout)
            self.assertIn('--project=example-project', result.stderr)
            self.assertIn('--filter=labels.component=vmd-staging-standby', result.stderr)
            self.assertNotIn('status=RUNNING', result.stderr)
        for overrides in ({'DEPLOY_ENVIRONMENT': 'staging'},
                          {'DEPLOY_ENVIRONMENT': ''},
                          {'DEPLOY_TARGET': 'serving'},
                          {'DEPLOY_EVENT': 'push'}):
            with self.subTest(overrides=overrides):
                result = self.run_staging(deploy_status=1, **overrides)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn('deploy-invoked', result.stdout)
                self.assertNotIn('compute instances list', result.stderr)

    def test_existing_staging_standby_deploys_and_propagates_failure(self):
        for zones in ('us-central1-a',
                      'projects/example-project/zones/us-central1-b',
                      'us-west2-a\nus-central1-a'):
            for status in (0, 1):
                with self.subTest(zones=zones, status=status):
                    result = self.run_staging(zones=zones, deploy_status=status)
                    self.assertEqual(result.returncode, status, result.stderr)
                    self.assertIn('deploy-invoked', result.stdout)
                    self.assertNotIn('No staging standby found', result.stdout)

    def test_optional_standby_discovery_fails_closed(self):
        for overrides in ({'discovery_status': 1}, {'GCP_PROJECT': ''},
                          {'GCP_REGION': ''}):
            with self.subTest(overrides=overrides):
                result = self.run_staging(**overrides)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('deploy-invoked', result.stdout)
                self.assertNotIn('No staging standby found', result.stdout)

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
