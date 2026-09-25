"""Run the west verifier against a plan fixture."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class WestPlanWorkflowTests(unittest.TestCase):
    def test_pr_fallback_reaches_both_plan_steps(self):
        workflow = (ROOT / '.github/workflows/terraform-plans.yml').read_text()
        setup = workflow.split('      - name: Set PR runbook URLs\n', 1)[1].split(
            '      - name: Validate and plan\n', 1)[0]
        plan = workflow.split('      - name: Validate and plan\n', 1)[1].split(
            '      - name: Verify west VMD and OTLP ingress\n', 1)[0]
        west = workflow.split('      - name: Verify west VMD and OTLP ingress\n', 1)[1]
        self.assertIn('if [[ -z "${TF_VAR_alert_runbook_urls:-}" ]]', setup)
        self.assertIn('TF_VAR_alert_runbook_urls=', setup)
        self.assertIn('>> "$GITHUB_ENV"', setup)
        self.assertIn('terraform plan', plan)
        self.assertIn('scripts/terraform-plan-west.sh', west)


@unittest.skipUnless(shutil.which('jq'), 'jq is required by the plan verifier')
class WestPlanTests(unittest.TestCase):
    def verify(self, broken_identity=False, broken_endpoint=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'scripts').mkdir()
            env_dir = root / 'infra/envs/production/us-west2'
            env_dir.mkdir(parents=True)
            shutil.copy(ROOT / 'scripts/terraform-plan-west.sh', root / 'scripts')
            ip = '192.0.2.2'
            identity = 'usw2-2' if broken_identity else 'example-generated-id'
            env = dict(VMD_GRPC_ADDRESS=('192.0.2.1' if broken_endpoint else ip) + ':50051',
                       DEFAULT_HOST_ID=identity,
                       DB_MAX_CONNS='15', OTEL_ENVIRONMENT='production',
                       OTEL_EXPORTER_OTLP_ENDPOINT='http://' + ip + ':4318',
                       OTEL_EXPORT_INTERVAL='15s', OTEL_METRICS_ENABLED='true',
                       OTEL_SERVICE_NAME='sandbox-controlplane')
            resources = {
                'module.api.google_cloud_run_v2_service.this': {'template': [{'containers': [{'env': [dict(name=k, value=v) for k, v in env.items()]}]}]},
                'module.sandbox_host_b.google_compute_instance.this': {'network_interface': [{'network_ip': ip}], 'tags': ['vmd-usw2']},
                'module.network.google_compute_subnetwork.connector[0]': {'ip_cidr_range': '192.0.2.0/28'},
                'module.network.google_compute_firewall.rules["allow_vmd_grpc"]': {'allow': [{'protocol': 'tcp', 'ports': ['50051']}]},
                'module.network.google_compute_firewall.rules["allow_otel_ingress"]': {'direction': 'INGRESS', 'source_ranges': ['192.0.2.0/28'], 'target_tags': ['vmd-usw2'], 'allow': [{'protocol': 'tcp', 'ports': ['4317', '4318']}]},
            }
            plan = {'variables': {'standby_host_id': {'value': 'example-generated-id'}},
                    'planned_values': {'root_module': {'resources': [dict(address=k, values=v) for k, v in resources.items()]}}}
            (env_dir / 'plan.json').write_text(json.dumps(plan))
            terraform = root / 'terraform'
            terraform.write_text('''#!/usr/bin/env python3
import pathlib, sys
args = sys.argv[1:]
if args[0] == 'plan':
    output = next(a.split('=', 1)[1] for a in args if a.startswith('-out='))
    pathlib.Path(output).write_text(pathlib.Path('plan.json').read_text())
elif args[0] == 'show':
    print(pathlib.Path(args[-1]).read_text())
''')
            terraform.chmod(0o755)
            result = subprocess.run(['bash', str(root / 'scripts/terraform-plan-west.sh')],
                                    env=dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH']),
                                    capture_output=True, text=True)
            declared = (env_dir / 'plan.json').read_text()
            self.assertEqual((env_dir / 'tfplan').read_text(), declared)
            self.assertEqual((env_dir / 'plan.txt').read_text().strip(), declared)
            return result.returncode

    def test_matching_plan_passes(self):
        self.assertEqual(self.verify(), 0)

    def test_wrong_generated_identity_is_rejected(self):
        self.assertNotEqual(self.verify(broken_identity=True), 0)

    def test_wrong_endpoint_is_rejected(self):
        self.assertNotEqual(self.verify(broken_endpoint=True), 0)
