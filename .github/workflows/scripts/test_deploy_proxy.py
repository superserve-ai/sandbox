import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('deploy_proxy', Path(__file__).with_name('deploy-proxy.py'))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DeployProxyTests(unittest.TestCase):
    def deploy(self, manifests=None, **overrides):
        env = dict(GCP_PROJECT='example-project',GCP_REGION='us-central1',SHA='12345678',
                   PROXY_DOMAIN='sandbox.example.test',PROXY_ROLLOUT_ID='run-1')
        env.update(overrides)
        self.commands,self.requests,self.manifests = [],[],[]
        def run(args, **kwargs):
            self.commands.append(args)
            if args[:4] == ['gcloud','compute','instances','list']:
                return subprocess.CompletedProcess(
                    args, 0, env.get('DISCOVERED_INSTANCES', 'example-host,us-central1-a\n'), '')
            if args[:3] == ['gcloud','compute','scp'] and args[3].endswith('request.json'):
                self.requests.append(json.loads(Path(args[3]).read_text()))
            if args[:3] == ['gcloud','compute','scp'] and args[3].endswith('manifest.json'):
                self.manifests.append(json.loads(Path(args[3]).read_text()))
            return subprocess.CompletedProcess(args,0,'','')
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ,env,clear=True), \
             patch.object(MODULE.subprocess,'run',side_effect=run), \
             patch.object(MODULE.os.path,'expanduser',return_value=directory+'/ssh-key'):
            manifest_file = Path(directory) / 'manifests.json'
            manifest_file.write_text(json.dumps(manifests if manifests is not None else {
                'example-cell': dict(project='example-project',instance='example-host',
                                     zone='us-central1-a',ip='192.0.2.10',
                                     migration_complete=True,
                                     routes=[dict(name='public-http', backend='public-backend'),
                                             dict(name='redirect', backend='redirect-backend')],
                                     frontend_backend_references={
                                         'public-http': ['public-backend'],
                                         'redirect': ['redirect-backend'],
                                     })}))
            os.environ['PROXY_ROLLOUT_MANIFESTS'] = str(manifest_file)
            return MODULE.main()

    def test_standby_reuses_cell_routes_with_discovered_host_identity(self):
        serving = dict(project='example-project', instance='example-serving', zone='us-central1-a',
                       ip='192.0.2.10', serving_host=dict(project='example-project',
                       instance='example-serving', zone='us-central1-a', ip='192.0.2.10'),
                       migration_complete=True,
                       routes=[dict(name='public-http', backend='public-backend')],
                       frontend_backend_references={'public-http': ['public-backend']})
        self.assertEqual(self.deploy(
            manifests={'cell': serving}, DEPLOY_TARGET='standby',
            EXPECTED_STANDBY_HOST='example-standby',
            DISCOVERED_INSTANCES='example-standby,us-central1-a,RUNNING,192.0.2.11\n'), 0)
        self.assertEqual(self.manifests[0]['instance'], 'example-standby')
        self.assertEqual(self.manifests[0]['ip'], '192.0.2.11')
        self.assertEqual(self.manifests[0]['routes'], serving['routes'])
        self.assertEqual(self.requests[0]['target'], 'standby')

    def test_standby_does_not_require_serving_frontend_adoption(self):
        manifest = dict(project='example-project', instance='example-serving', zone='us-central1-a',
                        ip='192.0.2.10', routes=[dict(name='public-http', backend='public-backend')])
        self.assertEqual(self.deploy(
            manifests={'cell': manifest}, DEPLOY_TARGET='standby',
            EXPECTED_STANDBY_HOST='example-standby',
            DISCOVERED_INSTANCES='example-standby,us-central1-a,RUNNING,192.0.2.11\n'), 0)

    def test_immutable_upload_invokes_host_controller_without_vmd_mutation(self):
        self.assertEqual(self.deploy(),0)
        commands = [c[-1] for c in self.commands if c[:3] == ['gcloud','compute','ssh']]
        self.assertEqual(len(commands),2)
        self.assertIn('--request',commands[-1])
        self.assertIn('sudo python3',commands[-1])
        self.assertNotIn('vmd.env',commands[-1])
        self.assertNotIn('restart',commands[-1])
        self.assertEqual(self.requests[0]['rollout'],'run-1')
        self.assertEqual(self.requests[0]['target'], 'serving')
        self.assertEqual(self.requests[0]['env']['HOST_REGION'],'us-central1')

    def test_bootstrap_uploads_manifest_and_immutable_generation_request(self):
        manifest = dict(project='example-project',instance='example-host',zone='us-central1-a',
                        ip='192.0.2.10',migration_complete=False,routes=[])
        self.assertEqual(self.deploy(manifests={'cell':manifest}, PROXY_OPERATION='bootstrap'),0)
        self.assertEqual(self.manifests,[manifest])
        remote = self.commands[-1][-1]
        self.assertIn('--manifest',remote)
        self.assertIn('--bootstrap',remote)
        self.assertIn('--request',remote)

    def test_standby_rejects_serving_bootstrap_operation(self):
        self.assertEqual(self.deploy(
            DEPLOY_TARGET='standby', PROXY_OPERATION='bootstrap',
            EXPECTED_STANDBY_HOST='example-host',
            DISCOVERED_INSTANCES='example-host,us-central1-a,RUNNING,192.0.2.10\n'), 1)
        self.assertEqual(len(self.commands), 1)

    def test_replacement_ci_run_preserves_explicit_retry_identity(self):
        self.assertEqual(self.deploy(GITHUB_RUN_ID='replacement-run'), 0)
        self.assertEqual(self.requests[0]['rollout'], 'run-1')

    def test_new_ci_run_defaults_to_its_run_identity(self):
        self.assertEqual(self.deploy(GITHUB_RUN_ID='new-run', PROXY_ROLLOUT_ID=''), 0)
        self.assertEqual(self.requests[0]['rollout'], 'new-run')

    def test_missing_ambiguous_or_unmigrated_manifest_fails_before_upload(self):
        manifest = dict(project='example-project',instance='example-host',zone='us-central1-a',
                        ip='192.0.2.10',migration_complete=False,routes=[])
        for manifests in ({}, {'cell':manifest}, {'one':manifest,'two':manifest},
                          {'cell':dict(manifest,project='other-project')}):
            with self.subTest(manifests=manifests):
                self.assertEqual(self.deploy(manifests=manifests),1)
                self.assertEqual(len(self.commands),1)

    def test_applied_frontend_references_authorize_without_migration_flag(self):
        manifest = dict(project='example-project', instance='example-host', zone='us-central1-a',
                        ip='192.0.2.10', migration_complete=False,
                        routes=[dict(name='public-http', backend='public-backend')],
                        frontend_backend_references={'public-http': ['public-backend']})
        self.assertEqual(self.deploy(manifests={'cell': manifest}), 0)

    def test_migration_flag_cannot_authorize_unswitched_frontend(self):
        manifest = dict(project='example-project', instance='example-host', zone='us-central1-a',
                        ip='192.0.2.10', migration_complete=True,
                        routes=[dict(name='public-http', backend='replacement-backend')],
                        frontend_backend_references={'public-http': ['legacy-backend']})
        self.assertEqual(self.deploy(manifests={'cell': manifest}), 1)
        self.assertEqual(len(self.commands), 1)

    def test_frontend_resource_inventory_covers_declared_routes(self):
        manifest = dict(project='example-project', instance='example-host', zone='us-central1-a',
                        ip='192.0.2.10', migration_complete=True,
                        routes=[dict(name='public-http', backend='replacement-backend')],
                        frontend_backend_references={'public-http': ['replacement-backend']},
                        frontend_resources={})
        self.assertEqual(self.deploy(manifests={'cell': manifest}), 1)
        self.assertEqual(len(self.commands), 1)

    def test_secrets_are_json_data_not_shell_text(self):
        secret = 'postgres://router:$(touch /tmp/unsafe)`echo unsafe`@db.example.test/db'
        self.assertEqual(self.deploy(PROXY_DATABASE_URL=secret,PEER_ROUTING_ENABLED='1'),0)
        self.assertEqual(self.requests[0]['env']['PROXY_DATABASE_URL'],secret)
        for key, path in (
                ('PEER_PROXY_CERT_FILE', '/etc/superserve/peer/tls.crt'),
                ('PEER_PROXY_KEY_FILE', '/etc/superserve/peer/tls.key'),
                ('PEER_PROXY_CA_FILE', '/etc/superserve/peer/ca.crt')):
            self.assertEqual(self.requests[0]['env'][key], path)
        self.assertTrue(all(secret not in ' '.join(c) for c in self.commands))

    def test_disabled_routing_omits_database_credential(self):
        self.assertEqual(self.deploy(PROXY_DATABASE_URL='postgres://example'),0)
        self.assertEqual(self.requests[0]['env']['PROXY_DATABASE_URL'],'')

    def test_disabled_peer_ingress_omits_default_credentials(self):
        self.assertEqual(self.deploy(
            PEER_PROXY_LISTEN_ADDR='',
            PEER_PROXY_CERT_FILE='/etc/superserve/peer/tls.crt',
            PEER_PROXY_KEY_FILE='/etc/superserve/peer/tls.key',
            PEER_PROXY_CA_FILE='/etc/superserve/peer/ca.crt'), 0)
        self.assertEqual(self.requests[0]['env']['PEER_PROXY_LISTEN_ADDR'], '')
        for key in ('PEER_PROXY_CERT_FILE', 'PEER_PROXY_KEY_FILE', 'PEER_PROXY_CA_FILE'):
            self.assertEqual(self.requests[0]['env'][key], '')

    def test_required_bootstrap_policy_is_preserved(self):
        self.assertEqual(self.deploy(PEER_IDENTITY_HOSTS='example-host'),0)
        self.assertTrue(self.requests[0]['require_identity'])

    def test_inputs_fail_before_upload(self):
        for overrides in [dict(GCP_REGION=''),dict(PEER_ROUTING_ENABLED='1'),
                          dict(PEER_ROUTING_ENABLED='invalid'),dict(PEER_PROXY_LISTEN_ADDR='10.0.0.1:5008'),
                          dict(PROXY_DOMAINS='one.example.test two.example.test')]:
            with self.subTest(overrides=overrides):
                self.assertEqual(self.deploy(**overrides),1)
                self.assertFalse(self.commands)

    def test_discovery_failure_does_not_contact_hosts(self):
        env = dict(GCP_PROJECT='example-project',GCP_REGION='us-central1',SHA='12345678',PROXY_DOMAIN='sandbox.example.test')
        with patch.dict(os.environ,env,clear=True), patch.object(MODULE.subprocess,'run',
                return_value=subprocess.CompletedProcess([],1,'','permission denied')) as run:
            self.assertEqual(MODULE.main(),1)
            self.assertEqual(run.call_count,1)


if __name__ == '__main__':
    unittest.main()
