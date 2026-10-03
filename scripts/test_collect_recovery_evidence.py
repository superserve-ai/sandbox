"""Exercise the collector/verifier boundary with synthetic cloud and guest data."""

import copy
from contextlib import ExitStack
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import time
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import zipfile

import collect_recovery_evidence as collector
import recovery_evidence as evidence
from migrate_database import MigrationError, PROJECTS


def fixture():
    now = time.time()
    stamp = lambda delta: datetime.datetime.fromtimestamp(now+delta, datetime.timezone.utc).isoformat()
    digest = 'sha256:' + 'c'*64
    state = {'services': [], 'jobs': [], 'instances': [{'id': '1', 'name': 'host', 'zone': 'zones/us-west2-a'}],
             'routes': [], 'backends': [], 'negs': [], 'forwarders': [], 'https_proxies': [], 'dns': {},
             'service_dns': {}, 'canary_image': collector.CANARY['image'], 'deleted_receivers': [],
             'active_job_executions': [], 'workers': []}
    bindings = {}
    for index, (region, name) in enumerate(collector.CELLS.items()):
        short = str(index)
        secret = 'database-url-usw2' if index == 0 else 'database-url'
        host = 'api-usw.superserve.ai' if index == 0 else 'api.superserve.ai'
        address = '192.0.2.' + str(index+1)
        direct = 'https://' + name + '.example.run.app'
        state['dns'][host] = [address]
        state['service_dns'][direct] = [address]
        state['services'].append({'metadata': {'name': name}, 'status': {'url': direct}})
        env = [{'name': 'DATABASE_URL', 'valueFrom': {'secretKeyRef': {'name': secret, 'key': 'latest'}}}]
        state['revisions_'+region] = [{'metadata': {'name': name+'-v1', 'creationTimestamp': stamp(-3600)},
              'spec': {'containers': [{'image': collector.IMAGE+'@'+digest, 'env': env}]},
              'status': {'imageDigest': collector.IMAGE+'@'+digest, 'conditions': [{'type': 'Active', 'status': 'True'}]}}]
        state['routes'].append({'selfLink': 'map'+short, 'defaultService': 'backend'+short})
        state['backends'].append({'selfLink': 'backend'+short, 'backends': [{'group': 'neg'+short}]})
        state['negs'].append({'selfLink': 'neg'+short, 'networkEndpointType': 'SERVERLESS', 'cloudRun': {'service': name}})
        state['forwarders'].append({'IPAddress': address, 'target': 'proxy'+short,
                                    'IPProtocol': 'TCP', 'portRange': '443-443'})
        state['https_proxies'].append({'selfLink': 'proxy'+short, 'urlMap': 'map'+short})
        version = {'name': f'projects/rayai-prod/secrets/{secret}/versions/1', 'state': 'ENABLED', 'createTime': stamp(-7200)}
        state['versions_'+secret] = [version]
        bindings[secret] = {'secret': secret, 'earliest_revision_start': stamp(-3600), 'observed_at': stamp(-3),
            'versions': [{'name': version['name'], 'created_at': version['createTime'], 'expected_project_match': True}]}
        for prefix, mode in [('api-canary', 'lifecycle'), ('api-canary-janitor', 'janitor')]:
            state['jobs'].append({'metadata': {'name': f'{prefix}-production-{region}',
                                   'labels': {'cloud.googleapis.com/location': region}}, 'spec': {'template': {'spec': {'template': {'spec': {
                'containers': [{'image': collector.CANARY_IMAGE+':'+collector.CANARY['source'], 'args': ['-mode', mode],
                                'env': [{'name': 'API_BASE_URL', 'value': 'https://'+host}]}]}}}}}})
    builds, entries = {}, []
    for binary in ('vmd', 'secretsproxy'):
        builds[binary] = {'source': collector.HOST_SOURCE, 'binary': 'd'*64, 'unit': 'e'*64, 'dropins': {}, 'guards': {}}
        route = {'origin': 'https://api-usw.superserve.ai', 'resolved_addresses': ['192.0.2.1']}
        entries.append({'binary': binary, 'installed_sha256': 'd'*64, 'unit_sha256': 'e'*64,
                        'dropins': {}, 'guards': {}, 'restart_routing': route,
                        'process': {'pid': 1 if binary == 'vmd' else 2, 'start_ticks': '100', 'executable_sha256': 'd'*64,
                                    'routing': route, 'established_peers': [{'address': '192.0.2.1', 'port': 443}]}})
    doc = {'schema': 2, 'policy': 'incapable-receivers-v1', 'target': 'usw2', 'recovery_revision': 'a'*40,
           'collector_revision': 'a'*40, 'plan_hash': 'b'*64, 'database_project': PROJECTS['usw2'],
           'started_at': stamp(-10), 'completed_at': stamp(-1),
           'inventory_before': evidence.sha(state), 'inventory_after': evidence.sha(state),
           'receiver_provenance': {digest: {'source': evidence.AUDITED_SOURCE, 'lineage_boundary': evidence.AUDITED_SOURCE,
                                          'artifact': 1, 'build_run': 2, 'config_digest': 'sha256:'+'f'*64}},
           'canary_provenance': dict(collector.CANARY), 'host_provenance': builds, 'database_bindings': bindings,
           'hosts': [{'instance_id': '1', 'instance_name': 'host', 'zone': 'zones/us-west2-a',
                      'route': 'existing-ssh-identity-over-iap', 'observation': {'boot_id': 'boot',
                       'services': entries, 'additional_managed_reporters': []}}],
           'coordinated_assumption': {'actor': 'operator', 'run_id': '12', 'revision': 'a'*40, 'target': 'usw2',
             'plan_hash': 'b'*64, 'acknowledgment': 'accepted', 'started_at': stamp(-10), 'scope': evidence.COORDINATION_SCOPE}}
    return now, state, doc


class CollectorTest(unittest.TestCase):
    def setUp(self):
        self.now, self.state, self.doc = fixture()

    def validate(self, doc=None, state=None):
        evidence.validate_receivers(doc or self.doc, revision='a'*40, plan_hash='b'*64,
            database_project=PROJECTS['usw2'], current=state or self.state, now=self.now)

    def test_reproduced_host_build_rejects_either_binary_mismatch(self):
        from recovery_guest_probe import DROPINS
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root/'audited-host-source'
            (source/'bin').mkdir(parents=True)
            (source/'deploy').mkdir()
            expected = {}
            for binary in ('vmd', 'secretsproxy'):
                data = binary.encode()
                (source/'bin'/binary).write_bytes(data)
                expected[binary] = hashlib.sha256(data).hexdigest()
                (source/'deploy'/f'superserve-{binary}.service').write_text('unit')
            for name, guard in DROPINS.items():
                (source/'deploy'/('superserve-vmd-'+name.split('-', 1)[1])).write_text('dropin')
                if guard:
                    (source/'deploy'/guard).write_text('guard')
            reader = Mock()
            reader.command.return_value = collector.HOST_SOURCE
            with patch.object(collector, 'ROOT', root), patch.object(collector, 'HOST_BINARIES', expected):
                self.assertEqual(set(collector.host_provenance(reader)), set(expected))
                for binary in expected:
                    path = source/'bin'/binary
                    path.write_bytes(b'changed')
                    with self.subTest(binary=binary), self.assertRaisesRegex(MigrationError, 'not reproducible'):
                        collector.host_provenance(reader)
                    path.write_bytes(binary.encode())
                reader.command.return_value = '0'*40
                with self.assertRaisesRegex(MigrationError, 'source checkout'):
                    collector.host_provenance(reader)

    def test_complete_receiver_proof_accepts_capable_publisher_without_spool_assertions(self):
        self.validate()
        self.assertNotIn('spools', self.doc['hosts'][0])
        self.assertEqual(self.doc['host_provenance']['vmd']['source'], collector.HOST_SOURCE)

    def test_unknown_consumers_routing_or_secret_alias_fail_closed(self):
        cases = [('worker in another region', lambda s: s['workers'].append({'name': 'projects/example/locations/europe-west1/workerPools/other'})),
                 ('retired deletion', lambda s: s['deleted_receivers'].append({'name': 'deleted'})),
                 ('canary tag', lambda s: s.update(canary_image='sha256:'+'0'*64)),
                 ('route action', lambda s: s['routes'][0].update(defaultRouteAction={'rewrite': 'elsewhere'})),
                 ('sidecar', lambda s: s['revisions_us-west2'][0]['spec']['containers'].append({})),
                 ('secret alias', lambda s: s['revisions_us-west2'][0]['metadata'].update(
                     annotations={'run.googleapis.com/secrets': 'database-url-usw2:projects/other/secrets/elsewhere'})),
                 ('different image', lambda s: s['revisions_us-west2'][0]['status'].update(imageDigest='sha256:'+'0'*64))]
        for name, mutate in cases:
            state = copy.deepcopy(self.state)
            mutate(state)
            doc = copy.deepcopy(self.doc)
            doc['inventory_before'] = doc['inventory_after'] = evidence.sha(state)
            with self.subTest(name=name), self.assertRaises(MigrationError):
                self.validate(doc, state)

    def test_guest_split_dns_destination_restart_and_unit_changes_reject(self):
        cases = [lambda e: e['process']['routing'].update(resolved_addresses=['203.0.113.8']),
                 lambda e: e['process']['routing'].update(origin='https://elsewhere.example'),
                 lambda e: e['restart_routing'].update(origin='https://elsewhere.example'),
                 lambda e: e.update(dropins={'extra.conf': '0'*64}),
                 lambda e: e.update(installed_sha256='0'*64)]
        for mutate in cases:
            doc = copy.deepcopy(self.doc)
            mutate(doc['hosts'][0]['observation']['services'][0])
            with self.assertRaises(MigrationError):
                self.validate(doc)

    def test_active_execution_keeps_its_own_configuration_after_job_update(self):
        spec = copy.deepcopy(self.state['jobs'][0]['spec']['template']['spec']['template']['spec'])
        spec['containers'][0]['image'] = collector.CANARY_IMAGE+'@'+collector.CANARY['image']
        for mode in ('lifecycle', 'janitor'):
            spec['containers'][0]['args'] = ['-mode', mode]
            state = copy.deepcopy(self.state)
            state['active_job_executions'] = [{'spec': {'template': {'spec': copy.deepcopy(spec)}}}]
            doc = copy.deepcopy(self.doc)
            doc['inventory_before'] = doc['inventory_after'] = evidence.sha(state)
            self.validate(doc, state)
        cases = [lambda s: s['containers'][0]['env'][0].update(value='https://elsewhere.example'),
                 lambda s: s['containers'][0]['env'].append({'name': 'DATABASE_URL', 'value': 'private-value'}),
                 lambda s: s['containers'][0]['env'].append({'name': 'PGHOST', 'value': 'elsewhere.example'}),
                 lambda s: s.update(volumes=[{'name': 'credentials', 'secret': {'secretName': 'other'}}]),
                 lambda s: s['containers'][0].update(volumeMounts=[{'name': 'credentials', 'mountPath': '/credentials'}])]
        for mutate in cases:
            state = copy.deepcopy(self.state)
            old_spec = copy.deepcopy(spec)
            mutate(old_spec)
            state['active_job_executions'] = [{'spec': {'template': {'spec': old_spec}}}]
            doc = copy.deepcopy(self.doc)
            doc['inventory_before'] = doc['inventory_after'] = evidence.sha(state)
            with self.assertRaises(MigrationError):
                self.validate(doc, state)
            # Refresh must reject the old execution even when the current job
            # template and authenticated evidence agree on the new safe config.
            observation = evidence.Observation(repository='example/project', revision='a'*40, run_id='12',
                plan_hash='b'*64, database_project=PROJECTS['usw2'], deadline=time.monotonic()+60)
            observation.load_artifact = Mock(return_value=(doc, 'synthetic-authenticated-digest'))
            with patch.object(collector, 'receiver_inventory', return_value=state), \
                 patch.object(collector, 'active_mutations'), \
                 patch.object(collector, 'guest_observation', return_value=doc['hosts'][0]), \
                 self.assertRaises(MigrationError):
                observation.verify()

    def test_report_forwarder_must_uniquely_cover_tcp_443(self):
        for ports in ({'portRange': '443-443'}, {'portRange': '400-500'}, {'ports': ['80', '443']}, {'allPorts': True}):
            state = copy.deepcopy(self.state)
            state['forwarders'][0].pop('portRange')
            state['forwarders'][0].update(ports)
            self.assertEqual(evidence.public_api_routes(state)['https://api-usw.superserve.ai'], 'superserve-api-usw2')
        for rule in ({'IPProtocol': 'TCP', 'portRange': '8443-8443'},
                     {'IPProtocol': 'UDP', 'portRange': '443-443'},
                     {'IPProtocol': 'TCP'}, {'portRange': '443'},
                     {'IPProtocol': 'TCP', 'portRange': 'bad'},
                     {'IPProtocol': 'TCP', 'portRange': '443', 'allPorts': True}):
            state = copy.deepcopy(self.state)
            state['forwarders'][0] = dict(rule, IPAddress='192.0.2.1', target='proxy0')
            with self.subTest(rule=rule), self.assertRaises(MigrationError):
                evidence.public_api_routes(state)
        for audited_port in ('443', '8443'):
            state = copy.deepcopy(self.state)
            state['forwarders'][0]['portRange'] = audited_port
            state['forwarders'].append({'IPAddress': '192.0.2.1', 'IPProtocol': 'TCP',
                                        'portRange': '443', 'target': 'unaudited-tcp-or-ssl-proxy'})
            doc = copy.deepcopy(self.doc)
            doc['inventory_before'] = doc['inventory_after'] = evidence.sha(state)
            with self.subTest(audited_port=audited_port), self.assertRaises(MigrationError):
                self.validate(doc, state)

    def test_fresh_cross_run_evidence_preserves_receipt_writer_identity(self):
        def observation(doc, run):
            obj = evidence.Observation(repository='example/project', revision='a'*40, run_id=run,
                plan_hash='b'*64, database_project=PROJECTS['usw2'], deadline=time.monotonic()+60)
            obj.load_artifact = Mock(return_value=(doc, 'digest-'+run))
            return obj
        with patch.object(collector, 'receiver_inventory', return_value=self.state), patch.object(collector, 'active_mutations'), \
             patch.object(collector, 'guest_observation', side_effect=lambda *args: self.doc['hosts'][0]):
            old = observation(self.doc, '12')
            old.verify()
            receipt = {'writer_state': old.state_digest}
            refreshed = copy.deepcopy(self.doc)
            refreshed['started_at'] = refreshed['coordinated_assumption']['started_at'] = datetime.datetime.fromtimestamp(self.now-5, datetime.timezone.utc).isoformat()
            refreshed['coordinated_assumption']['run_id'] = '13'
            new = observation(refreshed, '13')
            new.verify()
            self.assertEqual(receipt['writer_state'], new.state_digest)
            self.assertNotEqual(old.valid_until, new.valid_until)
            changed = copy.deepcopy(self.doc['hosts'][0])
            changed['observation']['services'][0]['process']['established_peers'] = [{'address': '203.0.113.4', 'port': 443}]
            # Normal backup TLS connections do not change the source-fixed
            # report authority or invalidate the existing preflight receipt.
            with patch.object(collector, 'guest_observation', return_value=changed):
                new.verify()
                self.assertEqual(receipt['writer_state'], new.state_digest)
            changed['observation']['services'][0]['process']['routing']['origin'] = 'https://elsewhere.example'
            with patch.object(collector, 'guest_observation', return_value=changed), self.assertRaises(MigrationError):
                new.verify()

    def test_branch_mutation_blocks_collection_and_self_run_is_excluded(self):
        reader = Mock()
        reader.pages.return_value = [{'id': 42, 'head_branch': 'other-branch', 'path': '.github/workflows/deploy-api.yml'}]
        with self.assertRaises(MigrationError):
            collector.active_mutations(reader, '12')
        self.assertTrue(all('branch=' not in call.args[0] for call in reader.pages.call_args_list))
        collector.active_mutations(reader, '42')

    def test_inventory_lists_alternate_consumers_across_all_regions(self):
        reader = Mock()
        def cloud(*args):
            if args[:3] == ('artifacts', 'docker', 'images'):
                return {'image_summary': {'digest': collector.CANARY['image']}}
            if args[:3] == ('run', 'revisions', 'list'):
                return [{'metadata': {'name': 'revision', 'creationTimestamp': '2026-01-01T00:00:00Z'}}]
            if args[:3] == ('run', 'worker-pools', 'list'):
                return [{'name': 'projects/example/locations/europe-west1/workerPools/other'}]
            if args[:3] == ('run', 'jobs', 'list'):
                return [{'metadata': {'name': region, 'labels': {'cloud.googleapis.com/location': region}}}
                        for region in ('us-west2', 'us-east4', 'europe-west1')]
            return []
        reader.cloud.side_effect = cloud
        with patch.object(collector.socket, 'getaddrinfo', return_value=[(None, None, None, None, ('192.0.2.1', 443))]):
            state = collector.receiver_inventory(reader)
        self.assertEqual(len(state['workers']), 1)
        calls = [call.args for call in reader.cloud.call_args_list if call.args[:3] == ('run', 'worker-pools', 'list')]
        self.assertEqual(len(calls), 1)
        self.assertFalse(any(arg.startswith('--region=') for arg in calls[0]))
        calls = [call.args for call in reader.cloud.call_args_list if call.args[:4] == ('run', 'jobs', 'executions', 'list')]
        self.assertEqual(len(calls), 3)
        self.assertEqual({arg for call in calls for arg in call if arg.startswith('--region=')},
                         {'--region=us-west2', '--region=us-east4', '--region=europe-west1'})
        audit = [call.args for call in reader.cloud.call_args_list if call.args[:2] == ('logging', 'read')]
        self.assertIn('DeleteJob', audit[0][2])

    def test_cloud_inventory_rejects_successful_partial_results_without_disclosing_warning(self):
        reader = collector.Reader(time.monotonic()+60)
        commands = [('run', resource, 'list') for resource in ('services', 'jobs', 'worker-pools')]
        commands += [('compute', resource, 'list') for resource in ('instances', 'url-maps', 'backend-services',
                     'network-endpoint-groups', 'forwarding-rules', 'target-https-proxies')]
        for args in commands:
            with self.subTest(command=args), patch.object(collector.subprocess, 'run') as run:
                run.return_value = SimpleNamespace(returncode=0, stdout='[]',
                                                   stderr='WARNING: unreachable region, private-provider-detail')
                with self.assertRaises(MigrationError) as caught:
                    reader.cloud(*args, '--limit=1000')
                self.assertNotIn('private-provider-detail', str(caught.exception))
                self.assertIn('--verbosity=warning', run.call_args.args[0])
                self.assertEqual(run.call_args.kwargs['env']['CLOUDSDK_COMPUTE_ALLOW_PARTIAL_ERROR'], 'false')
                run.return_value.stderr = ''
                self.assertEqual(reader.cloud(*args, '--limit=1000'), [])

    def test_identical_partial_compute_snapshots_cannot_collect_or_refresh_evidence(self):
        partial = copy.deepcopy(self.state)
        partial['instances'] = []
        document = copy.deepcopy(self.doc)
        document['hosts'] = []
        document['inventory_before'] = document['inventory_after'] = evidence.sha(partial)
        def transport(args, **kwargs):
            warning = 'WARNING: omitted-zone private-provider-detail' if args[1:4] == ['compute', 'instances', 'list'] else ''
            return SimpleNamespace(returncode=0, stdout='[]', stderr=warning)
        with patch.object(collector.subprocess, 'run', side_effect=transport), \
             patch.object(collector, 'private_binding') as private, patch.object(collector, 'guest_observation') as guest:
            for _ in range(2):
                with self.assertRaisesRegex(MigrationError, 'completeness is unproved'):
                    collector.collect(collector.Reader(time.monotonic()+60), 'a'*40, {})
                observation = evidence.Observation(repository='example/project', revision='a'*40, run_id='12',
                    plan_hash='b'*64, database_project=PROJECTS['usw2'], deadline=time.monotonic()+60)
                observation.load_artifact = Mock(return_value=(document, 'synthetic-authenticated-digest'))
                with self.assertRaisesRegex(MigrationError, 'completeness is unproved'):
                    observation.verify()
            private.assert_not_called()
            guest.assert_not_called()

    def test_dispatch_requires_actual_operator_ack_and_current_main(self):
        reader = Mock()
        reader.github.return_value = json.dumps({'object': {'sha': 'a'*40}})
        env = {'GITHUB_SHA': 'a'*40, 'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
               'GITHUB_REPOSITORY': 'superserve-ai/sandbox', 'GITHUB_RUN_ID': '12', 'GITHUB_ACTOR': 'operator',
               'APPROVED_REVISION': 'a'*40, 'COORDINATION_ACK': 'accepted'}
        self.assertEqual(collector.verify_dispatch(reader, env), 'a'*40)
        for key, value in [('COORDINATION_ACK', 'not-approved'), ('GITHUB_EVENT_NAME', 'push'),
                           ('APPROVED_REVISION', 'b'*40), ('GITHUB_ACTOR', '')]:
            with self.subTest(key=key), self.assertRaises(MigrationError):
                collector.verify_dispatch(reader, dict(env, **{key: value}))

    def test_build_config_is_read_without_extracting_or_executing(self):
        config = json.dumps({'config': {'Entrypoint': ['controlplane']}}).encode()
        inner = io.BytesIO()
        with tarfile.open(fileobj=inner, mode='w:gz') as tar:
            for name, data in [('manifest.json', json.dumps([{'Config': 'config.json'}]).encode()), ('config.json', config)]:
                item = tarfile.TarInfo(name)
                item.size = len(data)
                tar.addfile(item, io.BytesIO(data))
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, 'w') as archive:
            archive.writestr('image.tar.gz', inner.getvalue())
        self.assertEqual(collector.artifact_config(outer.getvalue()), config)

    def test_collection_orders_private_reads_and_rejects_changed_inventory(self):
        env = {'GITHUB_SHA': 'a'*40, 'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
               'GITHUB_REPOSITORY': 'superserve-ai/sandbox', 'GITHUB_RUN_ID': '12', 'GITHUB_ACTOR': 'operator',
               'APPROVED_REVISION': 'a'*40, 'COORDINATION_ACK': 'accepted', 'RECOVERY_SSH_USER': 'observer'}
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary)
            (root/'supabase/recovery').mkdir(parents=True)
            (root/'supabase/recovery/retained-storage-v1.json').write_text('{}')
            (root/'.ssh').mkdir()
            for name in ('google_compute_engine', 'known_hosts'):
                (root/'.ssh'/name).touch()
            stack.enter_context(patch.object(collector, 'ROOT', root))
            stack.enter_context(patch.object(Path, 'home', return_value=root))
            stack.enter_context(patch.dict(os.environ, env))
            reader = Mock(deadline=time.monotonic()+1800)
            reader.github.return_value = json.dumps({'object': {'sha': 'a'*40}})
            stack.enter_context(patch.object(collector, 'receiver_provenance', return_value=self.doc['receiver_provenance']))
            stack.enter_context(patch.object(collector, 'verify_canary', return_value=self.doc['canary_provenance']))
            stack.enter_context(patch.object(collector, 'host_provenance', return_value=self.doc['host_provenance']))
            stack.enter_context(patch.object(collector, 'active_mutations'))
            calls = []
            def inventory(_):
                calls.append('inventory')
                return copy.deepcopy(self.state)
            def guest(*_):
                calls.append('guest')
                return self.doc['hosts'][0]
            def binding(_, secret, start, end):
                calls.append(secret)
                result = copy.deepcopy(self.doc['database_bindings'][secret])
                result['observed_at'] = end
                self.assertEqual(result['earliest_revision_start'], start)
                return result
            inventory_mock = stack.enter_context(patch.object(collector, 'receiver_inventory', side_effect=inventory))
            guest_mock = stack.enter_context(patch.object(collector, 'guest_observation', side_effect=guest))
            private = stack.enter_context(patch.object(collector, 'private_binding', side_effect=binding))
            document = collector.collect(reader, 'a'*40, env)
            self.assertEqual(calls, ['inventory', 'inventory', 'guest', 'database-url-usw2', 'database-url', 'inventory'])
            self.assertEqual(document['coordinated_assumption']['actor'], 'operator')
            self.assertLessEqual(reader.deadline, time.monotonic()+evidence.MAX_AGE_SECONDS)
            changed = copy.deepcopy(self.state)
            changed['instances'][0]['id'] = '2'
            inventory_mock.side_effect = [self.state, self.state, changed]
            with self.assertRaisesRegex(MigrationError, 'Inventory changed during observation'):
                collector.collect(reader, 'a'*40, env)
            private.reset_mock()
            inventory_mock.side_effect = [self.state, changed]
            with self.assertRaisesRegex(MigrationError, 'provenance preparation'):
                collector.collect(reader, 'a'*40, env)
            private.assert_not_called()
            inventory_mock.side_effect = inventory
            guest_mock.side_effect = MigrationError('guest unavailable')
            with self.assertRaisesRegex(MigrationError, 'guest unavailable'):
                collector.collect(reader, 'a'*40, env)
            private.assert_not_called()
            (root/'.ssh/known_hosts').unlink()
            with self.assertRaisesRegex(MigrationError, 'guest read route'):
                collector.collect(reader, 'a'*40, env)
            private.assert_not_called()

    def test_receiver_provenance_requires_authenticated_main_build_and_matching_config(self):
        digest = 'sha256:'+'c'*64
        source = evidence.AUDITED_SOURCE
        config = json.dumps({'config': {'Entrypoint': ['controlplane']}}).encode()
        archive = b'synthetic authenticated archive'
        run = {'id': 12, 'head_sha': source, 'head_branch': 'main',
               'path': '.github/workflows/deploy-api.yml', 'conclusion': 'success'}
        artifact = {'id': 23, 'name': 'controlplane-image-'+source, 'expired': False,
                    'size_in_bytes': len(archive), 'digest': 'sha256:'+hashlib.sha256(archive).hexdigest()}
        def reader_for(run_value=run, artifact_value=artifact, tag=source, config_value=config):
            reader = Mock()
            reader.command.return_value = source+'\n'
            reader.cloud.return_value = [{'version': digest, 'tags': [tag]}]
            reader.pages.side_effect = lambda path, key: [run_value] if key == 'workflow_runs' else [artifact_value]
            reader.github.return_value = archive
            reader.registry.return_value = json.dumps({'config': {'digest': 'sha256:'+hashlib.sha256(config_value).hexdigest()}})
            return reader
        revisions = self.state['revisions_us-west2']
        with patch.object(collector, 'artifact_config', return_value=config):
            result = collector.receiver_provenance(reader_for(), revisions)
            self.assertEqual(result[digest]['artifact'], 23)
            cases = [reader_for(run_value=dict(run, head_branch='side-branch')),
                     reader_for(run_value=dict(run, conclusion='failure')),
                     reader_for(artifact_value=dict(artifact, expired=True)),
                     reader_for(artifact_value=dict(artifact, digest='sha256:'+'0'*64)),
                     reader_for(tag='0'*40), reader_for(config_value=b'unrelated config')]
            for reader in cases:
                with self.assertRaises(MigrationError):
                    collector.receiver_provenance(reader, revisions)
        overridden = json.dumps({'config': {'Entrypoint': ['shell']}}).encode()
        with patch.object(collector, 'artifact_config', return_value=overridden), self.assertRaises(MigrationError):
            collector.receiver_provenance(reader_for(config_value=overridden), revisions)


class ConsumerFreshnessTest(unittest.TestCase):
    def setUp(self):
        self.now, self.state, self.doc = fixture()
        self.doc['schema'] = 3
        for key in ('started_at', 'completed_at'):
            self.doc[key] = self.stamp(evidence.timestamp(self.doc[key])-600)
        self.doc['coordinated_assumption']['started_at'] = self.doc['started_at']
        for proof in self.doc['database_bindings'].values():
            proof['observed_at'] = self.stamp(evidence.timestamp(proof['observed_at'])-600)
        self.env = {'RECOVERY_COORDINATION_ACK': 'accepted', 'GITHUB_ACTIONS': 'true',
                    'GITHUB_REPOSITORY': 'example/project', 'GITHUB_SHA': 'a'*40,
                    'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                    'GITHUB_RUN_ID': '99', 'GITHUB_ACTOR': 'current-operator'}
        self.observation = evidence.Observation(repository='example/project', revision='a'*40, run_id='12',
            plan_hash='b'*64, database_project=PROJECTS['usw2'], deadline=time.monotonic()+1800)
        self.observation.load_artifact = Mock(return_value=(self.doc, 'authenticated-archive-digest'))
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(os.environ, self.env))
        self.clock = self.stack.enter_context(patch.object(evidence.time, 'time', return_value=self.now))
        self.inventory = self.stack.enter_context(patch.object(collector, 'receiver_inventory', return_value=self.state))
        self.mutations = self.stack.enter_context(patch.object(collector, 'active_mutations'))
        self.guest = self.stack.enter_context(patch.object(collector, 'guest_observation', return_value=self.doc['hosts'][0]))

    @staticmethod
    def stamp(value):
        return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).isoformat()

    def test_old_provenance_requires_live_checks_and_each_refresh_renews_only_live_lease(self):
        # A historical artifact alone is still not a fresh authorization.
        with self.assertRaisesRegex(MigrationError, 'stale'):
            evidence.validate(self.doc, revision='a'*40, plan_hash='b'*64,
                              database_project=PROJECTS['usw2'], current=self.state, now=self.now)
        self.observation.verify()
        self.assertEqual(self.observation.valid_until, self.now+120)
        state, digest = self.observation.state_digest, self.observation.artifact_digest
        for delta in (60, 180, 360):
            self.clock.return_value = self.now+delta
            self.observation.verify()
            self.assertEqual(self.observation.valid_until, self.now+delta+120)
            self.assertEqual((self.observation.state_digest, self.observation.artifact_digest), (state, digest))
        self.assertEqual(self.observation.load_artifact.call_count, 1)
        self.assertEqual(self.inventory.call_count, 8)
        self.assertEqual(self.guest.call_count, 4)
        self.assertEqual(self.mutations.call_count, 8)
        self.assertTrue(all(call.args[1] == '99' for call in self.mutations.call_args_list))
        self.assertEqual(self.doc['started_at'], self.stamp(self.now-610))

    def test_schema_one_and_two_cannot_renew_an_old_artifact(self):
        for schema in (1, 2):
            self.doc['schema'] = schema
            with self.subTest(schema=schema), self.assertRaisesRegex(MigrationError, 'stale'):
                self.observation.verify()
            self.assertIsNone(self.observation.valid_until)
        self.inventory.assert_not_called()

    def test_missing_or_changed_consumer_acknowledgment_never_authorizes(self):
        for key in self.env:
            with self.subTest(key=key), patch.dict(os.environ, {key: ''}), self.assertRaises(MigrationError):
                self.observation.verify()
            self.assertIsNone(self.observation.valid_until)
        self.inventory.assert_not_called()
        self.observation.verify()
        with patch.dict(os.environ, {'GITHUB_RUN_ID': '100'}), self.assertRaisesRegex(MigrationError, 'identity changed'):
            self.observation.verify()
        self.assertIsNone(self.observation.valid_until)

    def test_failed_refresh_revokes_prior_lease_and_does_not_replace_provenance(self):
        self.observation.verify()
        before = (self.observation.state_digest, self.observation.artifact_digest)
        self.clock.return_value = self.now+180
        for target in (self.inventory, self.guest, self.mutations):
            target.side_effect = MigrationError('live read failed')
            with self.subTest(target=target), self.assertRaisesRegex(MigrationError, 'live read failed'):
                self.observation.verify()
            self.assertIsNone(self.observation.valid_until)
            self.assertEqual((self.observation.state_digest, self.observation.artifact_digest), before)
            target.side_effect = None
        self.observation.verify()
        self.assertEqual(self.observation.valid_until, self.now+300)

    def test_inventory_and_secret_changes_before_or_during_observation_reject(self):
        self.observation.verify()
        for field in ('instances', 'versions_database-url-usw2', 'versions_database-url'):
            changed = copy.deepcopy(self.state)
            changed[field].append({'unexpected': True})
            for snapshots in ([changed, changed], [self.state, changed]):
                with self.subTest(field=field, during=snapshots[0] is self.state):
                    self.inventory.side_effect = snapshots
                    with self.assertRaises(MigrationError):
                        self.observation.verify()
                    self.assertIsNone(self.observation.valid_until)
        self.inventory.side_effect = None

    def test_guest_change_and_second_mutation_check_failure_reject(self):
        self.observation.verify()
        changed = copy.deepcopy(self.doc['hosts'][0])
        changed['observation']['services'][0]['process']['start_ticks'] = '200'
        self.guest.return_value = changed
        with self.assertRaisesRegex(MigrationError, 'Guest process'):
            self.observation.verify()
        self.assertIsNone(self.observation.valid_until)
        self.guest.return_value = self.doc['hosts'][0]
        self.mutations.side_effect = [None, MigrationError('another deploy started')]
        with self.assertRaisesRegex(MigrationError, 'another deploy started'):
            self.observation.verify()
        self.assertIsNone(self.observation.valid_until)

    def test_collection_runtime_and_overall_recovery_deadline_bound_renewal(self):
        self.observation.verify()
        # Download/authentication precede this timer; the live window itself
        # includes both cloud snapshots and guest observations.
        self.clock.side_effect = [self.now, self.now+121, self.now+121]
        with self.assertRaisesRegex(MigrationError, 'expired'):
            self.observation.verify()
        self.assertIsNone(self.observation.valid_until)
        self.clock.side_effect = None
        self.observation.deadline = time.monotonic()-1
        with self.assertRaisesRegex(MigrationError, 'deadline exceeded'):
            self.observation.verify()
        self.assertIsNone(self.observation.valid_until)

    def test_authenticated_provenance_cannot_be_changed_between_refreshes(self):
        for field in ('host_provenance', 'canary_provenance', 'receiver_provenance'):
            with self.subTest(field=field):
                self.observation.verify()
                saved = copy.deepcopy(self.doc[field])
                self.doc[field]['tampered'] = True
                with self.assertRaisesRegex(MigrationError, 'Authenticated provenance changed'):
                    self.observation.verify()
                self.assertIsNone(self.observation.valid_until)
                self.doc[field] = saved
        self.observation.verify()
        self.observation.artifact_digest = 'other-artifact'
        with self.assertRaisesRegex(MigrationError, 'Authenticated provenance changed'):
            self.observation.verify()

    def test_writer_identity_protects_provenance_without_collection_clock_or_run(self):
        original = evidence.sha(evidence.receiver_state(self.doc))
        refreshed = copy.deepcopy(self.doc)
        refreshed['started_at'] = refreshed['completed_at'] = self.stamp(self.now)
        refreshed['coordinated_assumption']['started_at'] = refreshed['started_at']
        refreshed['coordinated_assumption']['run_id'] = '13'
        for proof in refreshed['database_bindings'].values():
            proof['observed_at'] = refreshed['completed_at']
        self.assertEqual(evidence.sha(evidence.receiver_state(refreshed)), original)
        for field in ('host_provenance', 'canary_provenance', 'receiver_provenance'):
            changed = copy.deepcopy(refreshed)
            changed[field]['changed'] = True
            self.assertNotEqual(evidence.sha(evidence.receiver_state(changed)), original)


if __name__ == '__main__':
    unittest.main()
