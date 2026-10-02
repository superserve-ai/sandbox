import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch
from configure import configure


class CreationIdentityTest(unittest.TestCase):
    def config(self):
        return {'project_id': 'example-project', 'project_number': '123456789012',
                'region': 'us-central1', 'pool_id': 'example-pool', 'namespace': 'vmd', 'identity': 'peer',
                'ca_pool': 'projects/example-project/locations/us-central1/caPools/example',
                'spiffe_uri': 'spiffe://example.test/ns/vmd/sa/peer', 'instance_id': '987654321',
                'instance_name': 'example-host', 'zone': 'us-central1-a',
                'runtime_email': 'runtime@example-project.iam.gserviceaccount.com', 'identity_at_creation': True}

    def test_trust_phase_does_not_need_or_touch_a_vm(self):
        config = self.config()
        for key in ('instance_id', 'instance_name', 'zone', 'runtime_email'):
            del config[key]
        config['phase'] = 'trust'
        def run(args, **kwargs):
            self.assertNotIn('compute', args)
            self.assertNotIn('set-attestation-rules', args)
            return subprocess.CompletedProcess(args, 0, '[]' if 'list' in args else '')
        with patch('configure.subprocess.run', side_effect=run):
            configure(config)

    def test_attestation_uses_new_id_and_never_retrofits_identity(self):
        for configured in (True, False):
            config = self.config()
            config['phase'] = 'attestation'
            policies = []
            calls = []
            def run(args, **kwargs):
                calls.append(args)
                self.assertNotIn('update', args)
                if 'set-attestation-rules' in args:
                    path = next(a.split('=', 1)[1] for a in args if a.startswith('--policy-file='))
                    policies.append(json.loads(Path(path).read_text()))
                    return subprocess.CompletedProcess(args, 0, '')
                self.assertEqual(args[1:4], ['compute', 'instances', 'describe'])
                instance = {'id': config['instance_id'], 'serviceAccounts': [{'email': config['runtime_email']}],
                            'workloadIdentityConfig': {'identity': config['spiffe_uri'][9:], 'identityCertificateEnabled': configured}}
                return subprocess.CompletedProcess(args, 0, json.dumps(instance))
            with patch('configure.subprocess.run', side_effect=run):
                if configured:
                    configure(config)
                else:
                    with self.assertRaisesRegex(RuntimeError, 'refusing to retrofit'):
                        configure(config)
            self.assertEqual(policies[0]['attestationRules'][0]['googleCloudResource'],
                             '//compute.googleapis.com/projects/123456789012/uid/zones/us-central1-a/instances/987654321')
            self.assertFalse(any('privateca' in c for c in calls))


if __name__ == '__main__':
    unittest.main()
