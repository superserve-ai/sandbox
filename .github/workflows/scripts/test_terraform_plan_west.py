"""Run the west verifier against plan fixtures with either committed default."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


@unittest.skipUnless(shutil.which('jq'), 'jq is required by the plan verifier')
class WestPlanTests(unittest.TestCase):
    def verify(self, default, broken_identity=False, broken_endpoint=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'scripts').mkdir()
            env_dir = root / 'infra/envs/production/us-west2'
            env_dir.mkdir(parents=True)
            shutil.copy(ROOT / 'scripts/terraform-plan-west.sh', root / 'scripts')
            for role in ('primary', 'standby'):
                ip = '192.0.2.1' if role == 'primary' else '192.0.2.2'
                host = 'module.sandbox_host' if role == 'primary' else 'module.sandbox_host_b'
                identity = 'usw2' if role == 'primary' else 'example-generated-id'
                if broken_identity and role == 'standby':
                    identity = 'usw2-2'
                env = dict(VMD_GRPC_ADDRESS=ip + ':50051', DEFAULT_HOST_ID=identity,
                           DB_MAX_CONNS='15', OTEL_ENVIRONMENT='production',
                           OTEL_EXPORTER_OTLP_ENDPOINT='http://' + ip + ':4318',
                           OTEL_EXPORT_INTERVAL='15s', OTEL_METRICS_ENABLED='true',
                           OTEL_SERVICE_NAME='sandbox-controlplane')
                if broken_endpoint and role == 'primary':
                    env['VMD_GRPC_ADDRESS'] = '192.0.2.2:50051'
                resources = {
                    'module.api.google_cloud_run_v2_service.this': {'template': [{'containers': [{'env': [dict(name=k, value=v) for k, v in env.items()]}]}]},
                    host + '.google_compute_instance.this': {'network_interface': [{'network_ip': ip}], 'tags': ['vmd-usw2']},
                    'module.network.google_compute_subnetwork.connector[0]': {'ip_cidr_range': '192.0.2.0/28'},
                    'module.network.google_compute_firewall.rules["allow_vmd_grpc"]': {'allow': [{'protocol': 'tcp', 'ports': ['50051']}]},
                    'module.network.google_compute_firewall.rules["allow_otel_ingress"]': {'direction': 'INGRESS', 'source_ranges': ['192.0.2.0/28'], 'target_tags': ['vmd-usw2'], 'allow': [{'protocol': 'tcp', 'ports': ['4317', '4318']}]},
                }
                plan = {'variables': {'standby_host_id': {'value': 'example-generated-id'}},
                        'planned_values': {'root_module': {'resources': [dict(address=k, values=v) for k, v in resources.items()]}}}
                (env_dir / (role + '.json')).write_text(json.dumps(plan))
            terraform = root / 'terraform'
            terraform.write_text('''#!/usr/bin/env python3
import os, pathlib, sys
args = sys.argv[1:]
if args[0] == 'plan':
    role = os.environ['DEFAULT_ROLE']
    for arg in args:
        if arg.startswith('-var=active_sandbox_host='):
            role = arg.split('=')[-1]
    output = next(a.split('=', 1)[1] for a in args if a.startswith('-out='))
    pathlib.Path(output).write_text(pathlib.Path(role + '.json').read_text())
    with open('planned-roles', 'a') as log:
        log.write(role + '\\n')
elif args[0] == 'show':
    print(pathlib.Path(args[-1]).read_text())
''')
            terraform.chmod(0o755)
            result = subprocess.run(['bash', str(root / 'scripts/terraform-plan-west.sh')],
                                    env=dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'], DEFAULT_ROLE=default),
                                    capture_output=True, text=True)
            roles = (env_dir / 'planned-roles').read_text().splitlines()
            declared = (env_dir / (default + '.json')).read_text()
            self.assertEqual((env_dir / 'tfplan').read_text(), declared)
            self.assertEqual((env_dir / 'plan.txt').read_text().strip(), declared)
            return result.returncode, roles

    def test_both_roles_are_checked_independently_of_default(self):
        for default in ('primary', 'standby'):
            self.assertEqual(self.verify(default), (0, [default, 'primary', 'standby']))

    def test_wrong_generated_identity_is_rejected(self):
        self.assertNotEqual(self.verify('standby', broken_identity=True)[0], 0)

    def test_wrong_rollback_endpoint_is_rejected(self):
        self.assertNotEqual(self.verify('standby', broken_endpoint=True)[0], 0)
