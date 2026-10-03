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

    def test_failed_ssh_preserves_only_allowlisted_guest_diagnostics(self):
        safe = {'error': 'private-value', 'check': 'loaded-dropins', 'service': 'vmd',
                'error_type': 'ValueError', 'extra': 'private-value'}
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home/'.ssh').mkdir()
            for name in ('google_compute_engine', 'known_hosts'):
                (home/'.ssh'/name).write_text('fixture')
            for code in (0, 1, 255):
                for payload in (safe, dict(safe, check='private-value'), dict(safe, service=['private-value']),
                                dict(safe, error_type='private-value'), 'private-value'):
                    with self.subTest(code=code, payload=payload), patch.object(Path, 'home', return_value=home), \
                         patch.dict(os.environ, RECOVERY_SSH_USER='operator'), \
                         patch.object(collector.subprocess, 'run', return_value=SimpleNamespace(
                             returncode=code, stdout=json.dumps(payload), stderr='private-value')):
                        with self.assertRaises(MigrationError) as caught:
                            collector.guest_observation(collector.Reader(time.monotonic()+30),
                                {'name': 'host', 'zone': 'zones/us-west2-a', 'id': '1'})
                    message = str(caught.exception)
                    self.assertNotIn('private-value', message)
                    self.assertEqual('loaded-dropins' in message, payload == safe)

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

    def test_only_exact_pre_retained_deleted_job_is_classified_terminated(self):
        known = collector.RETIRED_RECEIVERS['events'][0]
        event = {'timestamp': known['timestamp'], 'receiveTimestamp': known['receiveTimestamp'],
                 'protoPayload': {'methodName': known['method'], 'resourceName': known['resource'], 'status': {}}}
        state = copy.deepcopy(self.state)
        state['deleted_receivers'] = [event]
        doc = copy.deepcopy(self.doc)
        doc['inventory_before'] = doc['inventory_after'] = evidence.sha(state)
        self.validate(doc, state)
        cases = [lambda s: s['deleted_receivers'][0].update(timestamp='2026-10-03T00:00:00Z'),
                 lambda s: s['deleted_receivers'][0]['protoPayload'].update(status={'code': 7}),
                 lambda s: s['deleted_receivers'][0]['protoPayload'].update(resourceName='other'),
                 lambda s: s['deleted_receivers'][0]['protoPayload'].update(methodName='google.cloud.run.v2.Services.DeleteService'),
                 lambda s: s['deleted_receivers'].append(copy.deepcopy(event)),
                 lambda s: s['jobs'].append({'metadata': {'name': known['resource'].rsplit('/', 1)[-1]}}),
                 lambda s: s['active_job_executions'].append({'metadata': {'name': known['resource'].rsplit('/', 1)[-1]+'-execution'}})]
        for mutate in cases:
            changed = copy.deepcopy(state)
            mutate(changed)
            self.assertFalse(evidence.retired_receiver_history_safe(changed))

    def test_catalog_covers_pre_capability_events_but_recreated_objects_need_new_identity(self):
        state = copy.deepcopy(self.state)
        for row in state['jobs'] + state['services'] + state['revisions_us-west2'] + state['revisions_us-east4']:
            row['metadata'].update(uid='new-object', creationTimestamp='2026-10-03T00:00:00Z')
        state['deleted_receivers'] = [
            {'timestamp': e['timestamp'], 'receiveTimestamp': e['receiveTimestamp'],
             'protoPayload': {'methodName': e['method'], 'resourceName': e['resource'],
                              'status': {'code': e['status_code']} if e['status_code'] else {}}}
            for e in collector.RETIRED_RECEIVERS['events']]
        self.assertTrue(evidence.retired_receiver_history_safe(state))
        state['jobs'][0]['metadata']['creationTimestamp'] = '2026-07-01T00:00:00Z'
        self.assertFalse(evidence.retired_receiver_history_safe(state))
        state['jobs'][0]['metadata']['creationTimestamp'] = '2026-10-03T00:00:00Z'
        del state['jobs'][0]['metadata']['uid']
        self.assertFalse(evidence.retired_receiver_history_safe(state))

    def test_verified_direct_service_origin_does_not_require_its_own_load_balancer(self):
        state, doc = copy.deepcopy(self.state), copy.deepcopy(self.doc)
        origin = state['services'][0]['status']['url']
        state['service_dns'][origin] = ['203.0.113.10']
        for entry in doc['hosts'][0]['observation']['services']:
            for route in (entry['process']['routing'], entry['restart_routing']):
                route.update(origin=origin, resolved_addresses=['203.0.113.10'])
        doc['inventory_before'] = doc['inventory_after'] = evidence.sha(state)
        self.validate(doc, state)
        doc['hosts'][0]['observation']['services'][0]['process']['routing']['origin'] = 'https://unverified.run.app'
        with self.assertRaises(MigrationError):
            self.validate(doc, state)

    def test_optional_dropin_hashes_do_not_admit_unknown_or_missing_required_files(self):
        doc = copy.deepcopy(self.doc)
        build = doc['host_provenance']['vmd']
        build['dropins'] = {'required.conf': '1'*64}
        build['optional_dropins'] = {'identity.conf': '2'*64}
        entry = doc['hosts'][0]['observation']['services'][0]
        entry['dropins'] = {'required.conf': '1'*64, 'identity.conf': '2'*64}
        self.validate(doc)
        for actual in ({'identity.conf': '2'*64}, {'required.conf': '1'*64, 'identity.conf': '3'*64},
                       {'required.conf': '1'*64, 'other.conf': '2'*64}):
            entry['dropins'] = actual
            with self.assertRaises(MigrationError):
                self.validate(doc)

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
        def cloud(*args, **kwargs):
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
        self.assertEqual(len(calls), 4)
        self.assertEqual({arg for call in calls for arg in call if arg.startswith('--region=')},
                         {'--region=us-west2', '--region=us-east4', '--region=europe-west1', '--region=us-central1'})
        audit = [call.args for call in reader.cloud.call_args_list if call.args[:2] == ('logging', 'read')]
        self.assertIn('DeleteJob', audit[0][2])

    def test_history_delta_query_includes_late_old_events_and_only_metadata(self):
        reader = Mock()
        reader.cloud.return_value = []
        collector.deletion_history(reader, '2026-07-01T00:00:00Z', '2026-10-03T07:00:00Z')
        call = reader.cloud.call_args
        self.assertIn('timestamp>="2026-07-01T00:00:00Z"', call.args[2])
        self.assertIn('(timestamp>="2026-10-03T07:00:00Z" OR receiveTimestamp>="2026-10-03T07:00:00Z")', call.args[2])
        self.assertEqual(call.kwargs['fields'], 'timestamp,receiveTimestamp,protoPayload.methodName,protoPayload.resourceName,protoPayload.status')

    def test_history_cache_reuses_exact_rows_but_rejects_late_unknown_event(self):
        reader = Mock()
        def cloud(*args, **kwargs):
            if args[:3] == ('artifacts', 'docker', 'images'):
                return {'image_summary': {'digest': collector.CANARY['image']}}
            if args[:3] == ('run', 'revisions', 'list'):
                return [{'metadata': {'creationTimestamp': '2026-07-01T00:00:00Z'}}]
            return []
        reader.cloud.side_effect = cloud
        event = {'timestamp': '2026-07-02T00:00:00Z', 'receiveTimestamp': '2026-07-02T00:01:00Z'}
        history = {'earliest': '2026-07-01T00:00:00Z', 'cutoff': '2026-10-03T07:00:00Z', 'events': [event]}
        with patch.object(collector, 'deletion_history', return_value=[event]) as delta, \
             patch.object(collector.socket, 'getaddrinfo', return_value=[(0, 0, 0, 0, ('192.0.2.1', 443))]):
            self.assertEqual(collector.receiver_inventory(reader, history)['deleted_receivers'], [event])
            delta.assert_called_once_with(reader, history['earliest'], history['cutoff'])
            delta.return_value = [dict(event, receiveTimestamp='2026-10-03T07:00:01Z')]
            with self.assertRaisesRegex(MigrationError, 'late receiver deletion'):
                collector.receiver_inventory(reader, history)
            self.assertEqual(history['cutoff'], '2026-10-03T07:00:00Z')

    def test_manual_input_transport_is_exact_and_bounded(self):
        raw = '{"operator":"operator"}'
        digest = hashlib.sha256(raw.encode()).hexdigest()
        self.assertEqual(collector.load_manual_guests({'MANUAL_GUESTS_JSON': raw, 'MANUAL_GUESTS_SHA256': digest}), json.loads(raw))
        self.assertIsNone(collector.load_manual_guests({}))
        for value, hashed in [(raw+' ', digest), (raw, ''), ('', digest), ('x'*60001, digest)]:
            with self.assertRaises(MigrationError):
                collector.load_manual_guests({'MANUAL_GUESTS_JSON': value, 'MANUAL_GUESTS_SHA256': hashed})

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
            def inventory(_, history=None):
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

    def test_old_provenance_gets_fixed_lease_reused_until_renewal(self):
        # A historical artifact alone is still not a fresh authorization.
        with self.assertRaisesRegex(MigrationError, 'stale'):
            evidence.validate(self.doc, revision='a'*40, plan_hash='b'*64,
                              database_project=PROJECTS['usw2'], current=self.state, now=self.now)
        self.observation.verify()
        self.assertEqual(self.observation.valid_until, self.now+120)
        state, digest = self.observation.state_digest, self.observation.artifact_digest
        for delta in (180, 360, 540):
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

    def test_32_phase_boundaries_reuse_one_non_sliding_observation(self):
        self.observation.verify()
        for delta in range(1, 97, 3):
            self.clock.return_value = self.now+delta
            self.observation.verify()
            self.assertEqual(self.observation.valid_until, self.now+120)
        self.assertEqual(self.inventory.call_count, 2)
        self.assertEqual(self.guest.call_count, 1)
        self.assertEqual(self.mutations.call_count, 2)
        self.clock.return_value = self.now+115
        self.observation.verify()
        self.assertEqual(self.inventory.call_count, 4)
        self.assertEqual(self.observation.valid_until, self.now+235)

    def test_backward_wall_clock_revokes_lease(self):
        self.observation.verify()
        self.clock.return_value = self.now-1
        with self.assertRaisesRegex(MigrationError, 'clock moved backwards'):
            self.observation.verify()
        self.assertIsNone(self.observation.valid_until)
        self.assertIsNone(self.observation._lease)

    def test_monotonic_expiry_renews_even_if_wall_clock_has_not_advanced(self):
        with patch.object(evidence.time, 'monotonic', return_value=10):
            self.observation.verify()
        with patch.object(evidence.time, 'monotonic', return_value=131):
            self.observation.verify()
        self.assertEqual(self.inventory.call_count, 4)

    def make_manual(self, age=60):
        instance = self.state['instances'][0]
        instance.update(status='RUNNING', lastStartTimestamp=self.stamp(self.now-3600), metadata={'fingerprint': 'original'})
        other = dict(instance, id='2', name='other', zone='zones/us-east4-a')
        self.state['instances'].append(other)
        self.doc['hosts'].append(copy.deepcopy(self.doc['hosts'][0]))
        probe = hashlib.sha256(Path(collector.__file__).with_name('recovery_guest_probe.py').read_bytes()).hexdigest()
        for host, item in zip(self.doc['hosts'], self.state['instances']):
            host.update(instance_id=item['id'], instance_name=item['name'], zone=item['zone'],
                        route='operator-supplied', probe_sha256=probe, instance_sha256=evidence.sha(item))
        manual = dict(authority='operator-supplied-coordinated-window', revision='a'*40, plan_hash='b'*64,
                      project=collector.PROJECT, target='usw2', acknowledgment='accepted',
                      scope=evidence.COORDINATION_SCOPE, operator='operator',
                      started_at=self.stamp(self.now-age), completed_at=self.stamp(self.now-age+1), hosts=self.doc['hosts'])
        self.doc['manual_guests'] = manual
        self.doc['inventory_before'] = self.doc['inventory_after'] = evidence.sha(self.state)
        self.stack.enter_context(patch.dict(os.environ, {'RECOVERY_GUEST_MODE': 'manual'}))
        return manual

    def test_manual_consumer_uses_snapshot_and_caps_lease_at_original_expiry(self):
        self.make_manual(age=1700)
        self.observation.verify()
        self.assertAlmostEqual(self.observation.valid_until, self.now+100, places=5)
        self.clock.return_value = self.now+90
        self.observation.verify()
        self.assertAlmostEqual(self.observation.valid_until, self.now+100, places=5)
        self.assertEqual(self.inventory.call_count, 2)
        self.guest.assert_not_called()
        self.clock.return_value = self.now+101
        with self.assertRaisesRegex(MigrationError, 'stale'):
            self.observation.verify()
        self.assertIsNone(self.observation.valid_until)

    def test_manual_capture_rejects_identity_metadata_reboot_probe_actor_and_mode_changes(self):
        manual = self.make_manual()
        for field, value in [('revision', 'c'*40), ('operator', 'other'), ('acknowledgment', ''),
                             ('started_at', self.stamp(self.now-1801))]:
            saved = manual[field]
            manual[field] = value
            with self.subTest(field=field), self.assertRaises(MigrationError):
                self.observation.verify()
            manual[field] = saved
        host = manual['hosts'][0]
        for field in ('probe_sha256', 'instance_sha256', 'instance_id'):
            saved = host[field]
            host[field] = 'wrong'
            with self.subTest(field=field), self.assertRaises(MigrationError):
                self.observation.verify()
            host[field] = saved
        instance = self.state['instances'][0]
        for field, value in [('lastStartTimestamp', self.stamp(self.now-5)), ('status', 'STOPPING'),
                             ('metadata', {'fingerprint': 'changed'})]:
            saved = instance[field]
            instance[field] = value
            with self.subTest(field=field), self.assertRaises(MigrationError):
                self.observation.verify()
            instance[field] = saved
        with patch.dict(os.environ, {'RECOVERY_GUEST_MODE': 'automated'}), self.assertRaises(MigrationError):
            self.observation.verify()
        self.observation.verify()
        self.guest.assert_not_called()

    def test_manual_input_flows_through_real_collector_without_ssh(self):
        manual = self.make_manual()
        manual['plan_hash'] = evidence.sha({})
        raw = json.dumps(manual)
        env = dict(self.env, GITHUB_ACTOR='operator', COORDINATION_ACK='accepted',
                   MANUAL_GUESTS_JSON=raw, MANUAL_GUESTS_SHA256=hashlib.sha256(raw.encode()).hexdigest())
        reader = Mock(deadline=time.monotonic()+1800)
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary)
            (root/'supabase/recovery').mkdir(parents=True)
            (root/'supabase/recovery/retained-storage-v1.json').write_text('{}')
            stack.enter_context(patch.object(collector, 'ROOT', root))
            stack.enter_context(patch.object(collector, 'verify_dispatch'))
            for function, key in [('receiver_provenance', 'receiver_provenance'),
                                  ('verify_canary', 'canary_provenance'), ('host_provenance', 'host_provenance')]:
                stack.enter_context(patch.object(collector, function, return_value=self.doc[key]))
            def private(_, secret, start, end):
                return dict(self.doc['database_bindings'][secret], observed_at=end)
            bindings = stack.enter_context(patch.object(collector, 'private_binding', side_effect=private))
            stack.enter_context(patch.object(collector, 'utc', return_value=self.stamp(self.now)))
            output = collector.collect(reader, 'a'*40, env)
            self.assertEqual(output['manual_guests'], manual)
            self.assertEqual(output['hosts'], manual['hosts'])
            self.assertEqual(bindings.call_count, 2)
            self.guest.assert_not_called()
            self.assertEqual(len(self.inventory.call_args_list[0].args), 1)
            for call in self.inventory.call_args_list[1:]:
                self.assertEqual(call.args[1], output['deletion_history'])

    def test_manual_capture_expiring_during_observation_issues_no_lease(self):
        self.make_manual(age=1790)
        self.clock.side_effect = [self.now, self.now+11]
        with self.assertRaisesRegex(MigrationError, 'stale'):
            self.observation.verify()
        self.assertIsNone(self.observation.valid_until)

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
        self.clock.return_value = self.now+180
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
        self.clock.return_value = self.now+180
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
        self.clock.side_effect = [self.now+180, self.now+301, self.now+301]
        with self.assertRaisesRegex(MigrationError, 'expired'):
            self.observation.verify()
        self.assertIsNone(self.observation.valid_until)
        self.clock.side_effect = None
        self.clock.return_value = self.now+301
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
