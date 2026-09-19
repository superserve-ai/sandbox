"""Production billing timers need CPU and resident instances without requests."""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[3]


class BillingWorkerCPUTest(unittest.TestCase):
    def test_production_terraform_keeps_background_workers_running(self):
        for region in ('us-east4', 'us-west2'):
            with self.subTest(region=region):
                source = (ROOT / 'infra/envs/production' / region / 'main.tf').read_text()
                api = source.split('module "api" {', 1)[1].split('\n}', 1)[0]
                self.assertRegex(api, r'(?m)^\s*cpu_idle\s*=\s*false\s*$')
                minimum = re.search(r'(?m)^\s*min_instances\s*=\s*(\d+)\s*$', api)
                self.assertIsNotNone(minimum)
                self.assertGreater(int(minimum.group(1)), 0)

    def test_each_production_deploy_preserves_cpu_and_minimum_instances(self):
        for workflow in ('deploy-api.yml', 'terraform-cd.yml'):
            source = (ROOT / '.github/workflows' / workflow).read_text()
            for cell in ('USE4', 'USW'):
                with self.subTest(workflow=workflow, cell=cell):
                    command = 'gcloud run services update ${{ vars.CLOUD_RUN_SERVICE_' + cell + ' }}'
                    self.assertEqual(source.count(command), 1)
                    update = source.split(command, 1)[1].split('\n\n', 1)[0]
                    self.assertIn('--no-cpu-throttling', update)
                    self.assertRegex(update, r'--min-instances\s+10\s')


if __name__ == '__main__':
    unittest.main()
