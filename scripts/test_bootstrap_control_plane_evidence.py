import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/bootstrap-control-plane-evidence.sh'


class EvidenceBootstrapTests(unittest.TestCase):
    def run_bootstrap(self, failure=''):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for tool in ('terraform', 'gcloud', 'sleep'):
                executable = root / tool
                executable.write_text('''#!/bin/sh
printf '%s %s\\n' "${0##*/}" "$*" >> "$CALLS"
if [ "${0##*/}:$1" = "$FAILURE" ]; then exit 1; fi
if [ "$FAILURE" = "terraform:apply-once" ] && [ "${0##*/}:$1" = "terraform:apply" ] && [ ! -f "$CALLS.once" ]; then
  touch "$CALLS.once"
  exit 1
fi
if [ "${0##*/}:$1" = "terraform:output" ]; then echo example-control-plane-evidence; fi
''')
                executable.chmod(0o755)
            result = subprocess.run(['bash', str(SCRIPT)], capture_output=True, text=True, env={
                **os.environ, 'PATH': f'{root}:{os.environ["PATH"]}', 'PROJECT': 'example-project',
                'STATE_BUCKET': 'example-state', 'DEPLOYMENT_SERVICE_ACCOUNT': 'deployer@example.com',
                'GITHUB_ENV': str(root / 'env'), 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '2',
                'GITHUB_JOB': 'production-use4', 'RUNNER_TEMP': str(root),
                'CALLS': str(root / 'calls'), 'FAILURE': failure,
            })
            return result, (root / 'calls').read_text(), (root / 'env').read_text() if (root / 'env').exists() else ''

    def test_bootstrap_publishes_bucket_only_after_successful_upload(self):
        result, calls, env = self.run_bootstrap()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('-backend-config=bucket=example-state', calls)
        self.assertIn('-backend-config=prefix=bootstrap/control-plane-evidence', calls)
        self.assertLess(calls.index('terraform apply'), calls.index('gcloud storage cp'))
        self.assertIn('/preflight/123/2/production-use4-1/ --if-generation-match=0', calls)
        self.assertEqual(env, 'CONTROL_PLANE_EVIDENCE_BUCKET=example-control-plane-evidence\n')

    def test_apply_or_upload_failure_does_not_publish_bucket(self):
        for failure in ('terraform:apply', 'gcloud:storage'):
            with self.subTest(failure=failure):
                result, calls, env = self.run_bootstrap(failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(env, '')
                self.assertNotIn('gcloud run ', calls)
                if failure == 'terraform:apply':
                    self.assertEqual(calls.count('terraform plan'), 6)
                    self.assertEqual(calls.count('terraform apply'), 6)
                if failure == 'gcloud:storage':
                    self.assertEqual(calls.count('gcloud storage cp'), 6)

    def test_partial_apply_replans_before_retry_and_still_requires_upload(self):
        result, calls, env = self.run_bootstrap('terraform:apply-once')
        self.assertEqual(result.returncode, 0, result.stderr)
        terraform_calls = [line.split()[1] for line in calls.splitlines() if line.startswith('terraform ')]
        self.assertEqual(terraform_calls, ['init', 'plan', 'apply', 'plan', 'apply', 'output'])
        self.assertIn('gcloud storage cp', calls)
        self.assertIn('CONTROL_PLANE_EVIDENCE_BUCKET=', env)

    def test_every_cell_bootstraps_before_identity_changes_and_pins_candidate(self):
        workflow = (ROOT / '.github/workflows/control-plane-identity-rollout.yml').read_text()
        for job, state in (
            ('staging', 'superserve-terraform-state'),
            ('production-use4', 'superserve-terraform-state-prod'),
            ('production-usw2', 'superserve-terraform-state-prod'),
        ):
            with self.subTest(job=job):
                block = workflow.split(f'  {job}:\n', 1)[1].split('\n  production-', 1)[0]
                self.assertLess(block.index('scripts/bootstrap-control-plane-evidence.sh'),
                                block.index('gcloud run services'))
                self.assertIn(f'STATE_BUCKET: {state}\n', block)
                self.assertIn('DEPLOYMENT_SERVICE_ACCOUNT: ${{ secrets.GCP_SERVICE_ACCOUNT }}', block)
                self.assertIn('EVIDENCE_BUCKET: ${{ env.CONTROL_PLANE_EVIDENCE_BUCKET }}', block)
                self.assertLess(block.index('terraform apply'), block.index('candidate=$(gcloud'))
                self.assertIn('value(status.latestCreatedRevisionName)', block)
                self.assertIn('--candidate-revision "$candidate"', block)


if __name__ == '__main__':
    unittest.main()
