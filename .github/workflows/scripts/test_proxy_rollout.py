import fcntl
import json
import tempfile
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, call, patch

SPEC = importlib.util.spec_from_file_location('proxy_rollout',Path(__file__).with_name('proxy_rollout.py'))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

OLD = {'id':'old','unit':'proxy-old.service','ports':{'public':5100}}
NEW = {'id':'new','unit':'proxy-new.service','ports':{'public':5110}}


class StandbyPromotionTests(unittest.TestCase):
    def test_same_rollout_promotes_exact_prepared_generation_and_recovers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary, unit = root / 'proxy', root / 'proxy.service'
            binary.write_bytes(b'prepared binary')
            unit.write_text('prepared unit')
            request = dict(rollout='prepared', target='standby', revision='abc', env={})
            previous = MODULE.request_identity(request, binary, unit)
            state = dict(rollout='prepared', target='standby', phase='standby_ready',
                         request_hash=previous, old=copy.deepcopy(OLD),
                         candidate=copy.deepcopy(NEW), active=copy.deepcopy(NEW))
            serving = dict(request, target='serving')
            identity = previous
            self.assertEqual(MODULE.standby_promotion_identity(state, serving, binary, unit), previous)
            ownership = Mock()
            ownership.assert_owned = Mock()
            path = root / 'state.json'
            MODULE.begin_standby_promotion(state,
                lambda value: MODULE.save_owned_state(ownership, path, value))
            recovered = json.loads(path.read_text())
            self.assertEqual(recovered['candidate'], NEW)
            self.assertEqual(recovered['request_hash'], previous)
            self.assertFalse(ownership.terminal_saved)
            MODULE.check_retry(recovered, 'prepared', identity)
            self.assertEqual(MODULE.standby_promotion_identity(recovered, serving, binary, unit), previous)
            host = Mock()
            host.local.return_value = True
            host.stop.return_value = 'drained'
            MODULE.Rollout(host, recovered,
                lambda value: MODULE.save_owned_state(ownership, path, value)).run()
            host.start.assert_called_once_with(NEW)
            host.membership.assert_any_call(NEW, True)
            self.assertEqual(recovered['phase'], 'complete')
            self.assertTrue(json.loads(path.read_text())['_promoted_standby'])
            self.assertEqual(MODULE.standby_promotion_identity(recovered, serving, binary, unit), previous)
            with self.assertRaises(RuntimeError):
                MODULE.standby_promotion_identity(recovered, request, binary, unit)

    def test_credential_renewal_preserves_original_promotion_handle(self):
        with tempfile.TemporaryDirectory() as directory:
            root, peer, upload, state, original = CredentialRenewalTests().fixture(directory)
            original['target'] = 'standby'
            generation = root / 'generations' / OLD['id']
            (generation / 'request.json').write_text(json.dumps(original))
            state.update(target='standby', phase='standby_ready', candidate=OLD)
            renewed = json.loads(MODULE.credential_request(state, root, upload, peer).read_text())
            origin = MODULE.standby_origin(state, renewed)
            self.assertEqual(origin, original['rollout'])
            (generation / 'request.json').write_text(json.dumps(renewed))
            identity = MODULE.request_identity(renewed, upload / 'proxy', upload / 'proxy.service')
            state.update(rollout=renewed['rollout'], request_hash=identity, standby_origin=origin,
                         retired_rollouts=[original['rollout']])
            serving = MODULE.resolve_standby_promotion_request(
                state, dict(original, target='serving'), root)
            self.assertEqual(serving['rollout'], renewed['rollout'])
            self.assertEqual(serving['credential_generation'], 'certificate-b')
            self.assertEqual(MODULE.standby_promotion_identity(
                state, serving, upload / 'proxy', upload / 'proxy.service'), identity)
            self.assertEqual(MODULE.standby_origin(
                state, dict(renewed, rollout='credentials-again')), origin)
            changed = MODULE.resolve_standby_promotion_request(
                state, dict(original, target='serving', revision='changed'), root)
            with self.assertRaisesRegex(RuntimeError, 'immutable'):
                MODULE.standby_promotion_identity(state, changed, upload / 'proxy', upload / 'proxy.service')
            unrelated = dict(original, target='serving', rollout='another')
            self.assertEqual(MODULE.resolve_standby_promotion_request(state, unrelated, root), unrelated)

    def test_promotion_rejects_changed_inputs_or_unfinished_preparation(self):
        with tempfile.TemporaryDirectory() as directory:
            binary, unit = Path(directory) / 'proxy', Path(directory) / 'proxy.service'
            binary.write_bytes(b'prepared')
            unit.write_text('unit')
            request = dict(rollout='prepared', target='standby', revision='abc', env={})
            state = dict(rollout='prepared', target='standby', phase='standby_ready',
                         request_hash=MODULE.request_identity(request, binary, unit))
            for changed in (dict(request, target='serving', revision='other'),
                            dict(request, target='serving', env={'NEW': 'value'})):
                with self.assertRaisesRegex(RuntimeError, 'immutable'):
                    MODULE.standby_promotion_identity(state, changed, binary, unit)
            serving = dict(request, target='serving')
            self.assertIsNone(MODULE.standby_promotion_identity(
                dict(state, phase='preparing'), serving, binary, unit))
            binary.write_bytes(b'changed')
            with self.assertRaisesRegex(RuntimeError, 'immutable'):
                MODULE.standby_promotion_identity(state, serving, binary, unit)

    def test_preparation_reuses_snapshot_and_updates_only_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generation = root / 'generations' / NEW['id']
            generation.mkdir(parents=True)
            prepared = dict(rollout='prepared', target='standby', revision='abc', env={})
            (generation / 'request.json').write_text(json.dumps(prepared))
            (generation / 'proxy').write_bytes(b'prepared binary')
            host = Mock()
            host.assert_owned = Mock()
            serving = dict(prepared, target='serving')
            with patch.object(MODULE, 'ROOT', root), patch.object(MODULE.shutil, 'copyfile'), \
                    patch.object(MODULE, 'command'):
                MODULE.prepare(host, NEW, serving, root)
                MODULE.prepare(host, NEW, serving, root)
                self.assertEqual(json.loads((generation / 'request.json').read_text()), serving)
                self.assertEqual((generation / 'proxy').read_bytes(), b'prepared binary')
                for invalid in (prepared, dict(serving, env={'CHANGED': 'yes'})):
                    with self.assertRaisesRegex(RuntimeError, 'immutable'):
                        MODULE.prepare(host, NEW, invalid, root)


class CredentialRenewalTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        active = root / 'generations' / OLD['id']
        active.mkdir(parents=True)
        request = dict(rollout='code-deploy', revision='revision-a',
                       env={'PROXY_DOMAIN': 'example.test', 'PROXY_DRAIN_GRACE': '30s'})
        (active / 'request.json').write_text(json.dumps(request))
        (active / 'proxy').write_bytes(b'immutable executable')
        (active / 'credential-generation').write_text('certificate-a')
        (active / 'unit.template').write_text('@GENERATION@')
        peer = root / 'peer'
        peer.mkdir()
        (peer / 'certificate-b').mkdir()
        (peer / 'current').symlink_to('certificate-b')
        upload = root / 'upload'
        upload.mkdir()
        state = dict(phase='complete', active=OLD, rollout='code-deploy')
        return root, peer, upload, state, request

    def test_renewal_preserves_binary_revision_configuration_and_retry_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root, peer, upload, state, original = self.fixture(directory)
            path = MODULE.credential_request(state, root, upload, peer)
            request = json.loads(path.read_text())
            self.assertEqual(request['revision'], original['revision'])
            self.assertEqual(request['env'], original['env'])
            self.assertEqual(request['credential_generation'], 'certificate-b')
            self.assertTrue(request['rollout'].startswith('credentials-'))
            self.assertEqual((upload / 'proxy').read_bytes(), b'immutable executable')
            self.assertEqual((upload / 'proxy.service').read_text(), '@GENERATION@')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual((root / 'credential-request.json').stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(MODULE.credential_request(state, root, upload, peer).read_text()), request)
            # Resume even if preparation never produced the candidate directory:
            # a rotated publication regenerates the snapshot request while
            # preserving the in-flight renewal identity.
            state.update(phase='preparing', old=OLD, candidate=NEW,
                         rollout=request['rollout'])
            (peer / 'current').unlink()
            (peer / 'certificate-c').mkdir()
            (peer / 'current').symlink_to('certificate-c')
            regenerated = json.loads(MODULE.credential_request(state, root, upload, peer).read_text())
            self.assertEqual(regenerated['rollout'], request['rollout'])
            self.assertEqual(regenerated['credential_generation'], 'certificate-c')
            self.assertNotEqual(regenerated, request)
            self.assertEqual(state['request_hash'], MODULE.request_identity(
                regenerated, upload / 'proxy', upload / 'proxy.service'))

    def test_interrupted_renewal_after_starting_can_be_abandoned(self):
        with tempfile.TemporaryDirectory() as directory:
            root, peer, upload, state, _ = self.fixture(directory)
            request = json.loads(MODULE.credential_request(state, root, upload, peer).read_text())
            state.update(phase='starting', old=OLD, candidate=NEW,
                         rollout=request['rollout'], request_hash=MODULE.request_identity(
                             request, upload / 'proxy', upload / 'proxy.service'))
            (peer / 'current').unlink()
            (peer / 'certificate-c').mkdir()
            (peer / 'current').symlink_to('certificate-c')
            resumed = json.loads(MODULE.credential_request(state, root, upload, peer).read_text())
            self.assertEqual(resumed['credential_generation'], 'certificate-c')
            host = Mock()
            host.config = {'routes': [{'listener': 'public'}]}
            host.cloud.member.return_value = False
            with patch.object(MODULE, 'command', return_value='inactive'):
                MODULE.abandon_preparation(host, state, lambda value: None)
            self.assertEqual(state['phase'], 'rolled_back')
            host.verify.assert_called_once_with(OLD)

    def test_rotated_credentials_replace_an_existing_interrupted_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root, peer, upload, state, _ = self.fixture(directory)
            request = json.loads(MODULE.credential_request(state, root, upload, peer).read_text())
            state.update(phase='starting', old=OLD, candidate=NEW,
                         rollout=request['rollout'], request_hash=MODULE.request_identity(
                             request, upload / 'proxy', upload / 'proxy.service'))
            candidate = root / 'generations' / NEW['id']
            candidate.mkdir()
            (candidate / 'request.json').write_text(json.dumps(request))
            (candidate / 'proxy').write_bytes(b'stale executable')
            (candidate / 'unit.template').write_text('@GENERATION@')
            (peer / 'current').unlink()
            (peer / 'certificate-c').mkdir()
            (peer / 'current').symlink_to('certificate-c')

            regenerated = json.loads(MODULE.credential_request(state, root, upload, peer).read_text())

            self.assertNotEqual(regenerated['rollout'], request['rollout'])
            self.assertEqual(regenerated['credential_generation'], 'certificate-c')
            self.assertEqual(state['_credential_recovery']['previous_rollout'], request['rollout'])
            self.assertEqual(state['_credential_previous_rollout'], request['rollout'])
            self.assertEqual(state['_credential_previous_request_hash'],
                             MODULE.request_identity(request, root / 'generations' / OLD['id'] / 'proxy',
                                                     root / 'generations' / OLD['id'] / 'unit.template'))

    def test_rotated_renewal_reconciles_a_running_unregistered_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / 'generations' / NEW['id']
            candidate.mkdir(parents=True)
            (candidate / 'proxy').write_bytes(b'stale')
            units = root / 'units'
            units.mkdir()
            (units / NEW['unit']).write_text('stale unit')
            host = Mock(root=root, unit_root=units)
            host.config = {'routes': [{'listener': 'public'}]}
            host.cloud.member.return_value = False
            state = dict(phase='starting', old=OLD, candidate=NEW)
            saved = []
            with patch.object(MODULE, 'command', side_effect=['active', 'daemon-reloaded']):
                MODULE.reconcile_credential_renewal(
                    host, state, lambda value: saved.append(copy.deepcopy(value)),
                    {'previous_rollout': 'credentials-old', 'credential_generation': 'certificate-c'})
            self.assertEqual(state['phase'], 'rolled_back')
            host.stop.assert_called_once_with(NEW)
            self.assertFalse(candidate.exists())
            self.assertFalse((units / NEW['unit']).exists())

    def test_rotated_renewal_reconciles_a_registered_candidate_in_rollback_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / 'generations' / NEW['id']
            candidate.mkdir(parents=True)
            (candidate / 'proxy').write_bytes(b'stale')
            units = root / 'units'
            units.mkdir()
            (units / NEW['unit']).write_text('stale unit')
            host = Mock(root=root, unit_root=units)
            host.config = {'routes': [{'listener': 'public'}]}
            host.cloud.member.return_value = True
            events = []

            host.membership.side_effect = lambda generation, present: events.append(
                ('membership', generation['id'], present))
            host.verify.side_effect = lambda generation: events.append(
                ('verify', generation['id']))
            host.switch_private.side_effect = lambda generation: events.append(
                ('private', generation['id']))
            host.propagated.side_effect = lambda generation, old: events.append(
                ('propagated', generation['id'], old['id']))
            host.stop.side_effect = lambda generation: events.append(
                ('stop', generation['id']))

            def save(value):
                events.append(('phase', value['phase']))

            remove_tree = MODULE.shutil.rmtree

            def cleanup(path):
                events.append(('cleanup', Path(path)))
                remove_tree(path)

            state = dict(phase='cutover_verified', old=OLD, candidate=NEW)
            with patch.object(MODULE, 'command', side_effect=['active', 'daemon-reloaded']), \
                 patch.object(MODULE.shutil, 'rmtree', side_effect=cleanup):
                MODULE.reconcile_credential_renewal(
                    host, state, save,
                    {'previous_rollout': 'credentials-old', 'credential_generation': 'certificate-c'})

            self.assertEqual(state['phase'], 'rolled_back')
            host.cloud.member.assert_called_once_with(host.config['routes'][0], NEW['ports']['public'])
            self.assertEqual(host.membership.call_args_list, [call(OLD, True), call(NEW, False)])
            host.verify.assert_called_once_with(OLD)
            host.stop.assert_called_once_with(NEW)
            self.assertFalse(candidate.exists())
            self.assertFalse((units / NEW['unit']).exists())

            index = lambda predicate: next(i for i, event in enumerate(events) if predicate(event))
            self.assertLess(index(lambda event: event == ('membership', 'old', True)),
                            index(lambda event: event == ('membership', 'new', False)))
            self.assertLess(index(lambda event: event == ('membership', 'new', False)),
                            index(lambda event: event == ('verify', 'old')))
            self.assertLess(index(lambda event: event == ('verify', 'old')),
                            index(lambda event: event == ('propagated', 'old', 'new')))
            self.assertLess(index(lambda event: event == ('propagated', 'old', 'new')),
                            index(lambda event: event == ('stop', 'new')))
            self.assertLess(index(lambda event: event == ('stop', 'new')),
                            index(lambda event: event[0] == 'cleanup'))

    def test_intermediate_rollback_keeps_owner_markers_until_replacement_is_saved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            ownership = Mock(spec=MODULE.CellLock)
            ownership.terminal_saved = False
            recovery = {'previous_rollout': 'credentials-old',
                        'credential_generation': 'certificate-c'}
            state = dict(phase='rolled_back', rollout='credentials-old',
                         request_hash='replacement-inputs', active=OLD, old=OLD,
                         candidate=NEW, _credential_recovery=recovery,
                         _credential_previous_request_hash='original-inputs',
                         _credential_previous_rollout='credentials-old')

            MODULE.save_owned_state(ownership, path, state)
            persisted = json.loads(path.read_text())
            self.assertEqual(persisted['_credential_recovery'], recovery)
            self.assertEqual(persisted['_credential_previous_request_hash'], 'original-inputs')
            self.assertEqual(persisted['_credential_previous_rollout'], 'credentials-old')
            self.assertFalse(ownership.terminal_saved)

            state = dict(persisted, phase='preparing', rollout='credentials-new')
            state.pop('_credential_recovery')
            MODULE.save_owned_state(ownership, path, state)
            self.assertEqual(json.loads(path.read_text())['_credential_previous_request_hash'],
                             'original-inputs')
            state['phase'] = 'complete'
            MODULE.save_owned_state(ownership, path, state)
            self.assertNotIn('_credential_previous_request_hash', json.loads(path.read_text()))
            self.assertNotIn('_credential_previous_rollout', json.loads(path.read_text()))
            self.assertTrue(ownership.terminal_saved)

    def test_rotated_renewal_resumes_cleanup_after_rollback_was_saved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / 'generations' / NEW['id']
            candidate.mkdir(parents=True)
            units = root / 'units'
            units.mkdir()
            (units / NEW['unit']).touch()
            host = Mock(root=root, unit_root=units)
            state = dict(phase='rolled_back', old=OLD, candidate=NEW, active=OLD)
            with patch.object(MODULE, 'command', return_value='') as command:
                MODULE.reconcile_credential_renewal(
                    host, state, Mock(), {'previous_rollout': 'credentials-old'})
            self.assertFalse(candidate.exists())
            self.assertFalse((units / NEW['unit']).exists())
            host.verify.assert_not_called()
            host.stop.assert_not_called()
            command.assert_called_once_with('systemctl', 'daemon-reload')

    def test_current_snapshot_needs_no_rollout_and_unfinished_code_deploy_is_not_stolen(self):
        with tempfile.TemporaryDirectory() as directory:
            root, peer, upload, state, _ = self.fixture(directory)
            (root / 'generations' / OLD['id'] / 'credential-generation').write_text('certificate-b')
            self.assertIsNone(MODULE.credential_request(state, root, upload, peer))
            state.update(phase='starting')
            with self.assertRaisesRegex(RuntimeError, 'unfinished deployment'):
                MODULE.credential_request(state, root, upload, peer)

    def test_legacy_credential_refresh_reloads_the_running_proxy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            peer = root / 'peer'
            peer.mkdir()
            (peer / 'identity.json').write_text(json.dumps({'spiffe_uri': 'spiffe://example.test'}))
            (peer / 'certificate-b').mkdir()
            (peer / 'current').symlink_to('certificate-b')
            env = root / 'proxy.env'
            env.write_text('PEER_PROXY_SPIFFE_URI=spiffe://example.test\n')
            with patch.object(MODULE, 'Path', side_effect=lambda value: env if str(value) == '/etc/sandbox/proxy.env' else Path(value)), \
                 patch.object(MODULE, 'command') as command:
                self.assertTrue(MODULE.reload_legacy_proxy(peer))
            command.assert_called_once_with('systemctl', 'try-restart', 'proxy.service')
            self.assertEqual((peer / 'loaded-generation').read_text(), 'certificate-b')

    def test_bootstrap_legacy_state_has_no_generation_request_to_renew(self):
        with tempfile.TemporaryDirectory() as directory:
            state = {'phase': 'bootstrap_ready', 'old': {'id': ''}}
            self.assertIsNone(MODULE.credential_request(state, Path(directory), Path(directory)))

    def test_failed_renewal_gets_new_identity_without_replaying_terminal_rollout(self):
        with tempfile.TemporaryDirectory() as directory:
            root, peer, upload, state, _ = self.fixture(directory)
            first = json.loads(MODULE.credential_request(state, root, upload, peer).read_text())
            state.update(phase='rolled_back', rollout=first['rollout'])
            second = json.loads(MODULE.credential_request(state, root, upload, peer).read_text())
            self.assertNotEqual(first['rollout'], second['rollout'])

    def test_snapshots_are_private_and_do_not_follow_later_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root, peer, upload, _, _ = self.fixture(directory)
            env = {}
            for key, name in [('PEER_PROXY_CERT_FILE', 'peer-cert'),
                              ('PEER_PROXY_KEY_FILE', 'peer-key'), ('PEER_PROXY_CA_FILE', 'peer-ca')]:
                source = peer / 'certificate-b' / name
                source.write_bytes(b'original ' + name.encode())
                env[key] = str(source)
            original = dict(env)
            destination = root / 'generations' / NEW['id']
            unit = MODULE.snapshot_credentials(env, upload, destination,
                                               {'credential_generation': 'certificate-b'}, peer / 'current')
            for source in original.values():
                Path(source).write_bytes(b'replaced')
                snapshot = upload / Path(source).name
                self.assertTrue(snapshot.read_bytes().startswith(b'original '))
                self.assertEqual(snapshot.stat().st_mode & 0o777, 0o600)
                self.assertIn(f'LoadCredential={snapshot.name}:{destination / snapshot.name}', unit)
            self.assertEqual(env, {})
            with self.assertRaisesRegex(RuntimeError, 'publication changed'):
                MODULE.snapshot_credentials(dict(original), upload, destination,
                                            {'credential_generation': 'certificate-a'}, peer / 'current')


class BootstrapManifestTests(unittest.TestCase):
    def test_fresh_generation_deploy_requires_completed_bootstrap(self):
        legacy = {'id': '', 'unit': 'proxy.service', 'ports': {'public': 5007}}
        with self.assertRaisesRegex(RuntimeError, 'completed bootstrap'):
            MODULE.ensure_bootstrap_ready(
                {'phase': 'complete', 'active': legacy, 'rollout': 'previous'},
                'next-rollout', False)

        # The bootstrap operation itself, an interrupted retry, a completed
        # bootstrap, and a durable rollback are all valid recovery paths.
        MODULE.ensure_bootstrap_ready(
            {'phase': 'preparing', 'old': legacy, 'rollout': 'next-rollout'},
            'next-rollout', False)
        with self.assertRaisesRegex(RuntimeError, 'completed bootstrap'):
            MODULE.ensure_bootstrap_ready(
                {'phase': 'complete', 'active': legacy, 'rollout': 'next-rollout'},
                'next-rollout', False)
        MODULE.ensure_bootstrap_ready(
            {'phase': 'complete', 'active': legacy, 'rollout': 'previous'},
            'next-rollout', True)
        MODULE.ensure_bootstrap_ready(
            {'phase': 'bootstrap_ready', 'old': legacy, 'rollout': 'next-rollout'},
            'next-rollout', False)
        MODULE.ensure_bootstrap_ready(
            {'phase': 'complete', 'active': legacy, 'bootstrap': True, 'rollout': 'previous'},
            'next-rollout', False)
        MODULE.ensure_bootstrap_ready(
            {'phase': 'rolled_back', 'active': legacy, 'rollout': 'previous'},
            'next-rollout', False)

    def bootstrap(self, directory, state=None, actual_instance='example-host', migrated=False,
                 frontend_backend_references=None):
        root = Path(directory)
        config = dict(project='example-project', instance='example-host', zone='us-central1-a',
                      ip='192.0.2.10', migration_complete=migrated,
                      routes=[dict(name='public-http', listener='public', neg='public-neg',
                                   backend='public-backend', backend_self_link='https://compute.example/public-backend',
                                   probe='https://example.test/health'),
                              dict(name='redirect', listener='redirect', neg='redirect-neg',
                                   backend='redirect-backend', backend_self_link='https://compute.example/redirect-backend',
                                   probe='http://example.test/health')],
                      frontend_backend_references={
                          'public-http': ['https://compute.example/public-backend'],
                          'redirect': ['https://compute.example/redirect-backend'],
                      })
        if frontend_backend_references is not None:
            config['frontend_backend_references'] = frontend_backend_references
        upload = root / 'manifest.json'
        upload.write_text(json.dumps(config))
        request = root / 'request.json'
        request.write_text(json.dumps(dict(rollout='migration', revision='abc', env={'PROXY_DOMAIN': 'example.test'})))
        (root / 'proxy').write_bytes(b'immutable binary')
        (root / 'proxy.service').write_text('@GENERATION@')
        (root / 'refresh-peer-credentials.py').write_text('# credential helper')
        installed = root / 'etc' / 'sandbox' / 'proxy-rollout.json'
        (root / 'etc' / 'systemd' / 'system').mkdir(parents=True, exist_ok=True)
        (root / 'run' / 'lock').mkdir(parents=True, exist_ok=True)
        if state is not None:
            (root / 'state.json').write_text(json.dumps(state))
        host = Mock()
        host.local.return_value = True
        host.stop.return_value = {}
        host.external.return_value = True
        def metadata(request, **kwargs):
            key = request.full_url.split('/computeMetadata/v1/')[1]
            value = {'instance/name': actual_instance, 'instance/zone': config['zone'],
                     'instance/id': '123456789', 'instance/network-interfaces/0/ip': config['ip'],
                     'project/project-id': config['project']}[key]
            response = Mock()
            response.read.return_value = value.encode()
            return response
        def path(value):
            value = str(value)
            return root / value.lstrip('/') if value.startswith(('/etc/', '/run/', '/usr/local/')) else Path(value)
        with patch.object(MODULE, 'ROOT', root), patch.object(MODULE, 'Path', side_effect=path), \
             patch.object(MODULE, 'Host', return_value=host), \
             patch.object(MODULE, 'CellLock', autospec=True) as ownership, \
             patch.object(MODULE, 'prepare') as prepare, patch.object(MODULE, 'prune_generations') as prune_generations, \
             patch.object(MODULE, 'command') as command, patch.object(MODULE, 'install_credential_timer') as install_credential_timer, \
             patch.object(MODULE.urllib.request, 'urlopen', side_effect=metadata), \
             patch('sys.argv', ['controller', '--manifest', str(upload), '--bootstrap', '--request', str(request)]):
            ownership.return_value.__enter__.return_value = ownership.return_value
            MODULE.main()
            if not migrated:
                self.assertFalse(ownership.return_value.terminal_saved)
                prepare.assert_not_called()
            prune_generations.assert_not_called()
            install_credential_timer.assert_called_once_with()
            command.assert_not_called()
            self.assertEqual((root / 'controller.py').read_text(), Path(MODULE.__file__).read_text())
            self.assertEqual((root / 'usr' / 'local' / 'sbin' / 'refresh-peer-credentials').read_text(),
                             '# credential helper')
        return installed, config, host, json.loads((root / 'state.json').read_text())

    def test_bootstrap_persists_candidate_then_resumes_with_applied_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            installed, config, host, state = self.bootstrap(directory)
            self.assertEqual(json.loads(installed.read_text()), config)
            self.assertEqual(installed.stat().st_mode & 0o777, 0o600)
            self.assertEqual(state['phase'], 'bootstrap_ready')
            self.assertEqual(state['endpoint_context']['ip'], config['ip'])
            self.assertEqual(state['endpoint_context']['routes'], config['routes'])
            self.assertLessEqual(state['timestamps']['preparing'], state['timestamps']['bootstrap_ready'])
            self.assertEqual(state['old']['ports']['redirect'], 5008)
            self.assertEqual(state['candidate']['ports']['redirect'], 5008)
            host.membership.assert_called_once_with(state['candidate'], True)
            host.stop.assert_not_called()
            _, _, resumed, complete = self.bootstrap(directory, migrated=True)
            self.assertEqual(complete['candidate'], state['candidate'])
            self.assertEqual(complete['phase'], 'complete')
            resumed.verify.assert_called_once_with(complete['candidate'])
            resumed.stop.assert_not_called()

    def test_pre_migration_bootstrap_retry_ignores_legacy_frontend_references(self):
        legacy_references = {
            'public-http': ['https://compute.example/legacy-public-backend'],
            'redirect': ['https://compute.example/legacy-redirect-backend'],
        }
        with tempfile.TemporaryDirectory() as directory:
            _, _, _, state = self.bootstrap(
                directory,
                frontend_backend_references=legacy_references,
            )
            self.assertEqual(state['phase'], 'bootstrap_ready')

            _, _, retried, retried_state = self.bootstrap(
                directory,
                frontend_backend_references=legacy_references,
            )

            self.assertEqual(retried_state['phase'], 'bootstrap_ready')
            retried.verify.assert_not_called()
            retried.stop.assert_not_called()

    def test_wrong_host_does_not_install_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, 'does not describe this host'):
                self.bootstrap(directory, actual_instance='other-host')
            self.assertFalse((Path(directory) / 'etc' / 'sandbox').exists())

    def test_bootstrap_refuses_unfinished_normal_rollout(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, 'before the first generation rollout'):
                self.bootstrap(directory, state={'phase': 'withdrawn'})
            self.assertFalse((Path(directory) / 'etc' / 'sandbox').exists())

    def test_migration_requires_applied_frontend_references_for_every_route(self):
        config = {
            'routes': [
                {'name': 'public-http', 'backend': 'public',
                 'backend_self_link': 'https://compute.example/public'},
                {'name': 'redirect', 'backend': 'redirect',
                 'backend_self_link': 'https://compute.example/redirect'},
            ],
            'frontend_backend_references': {
                'public-http': ['https://compute.example/public'],
                'redirect': ['https://compute.example/old-redirect'],
            },
        }
        with self.assertRaisesRegex(RuntimeError, 'redirect.*replacement backend'):
            MODULE.verify_frontend_references(config)

    def test_migration_rejects_partial_frontend_reference_inventory(self):
        config = {
            'routes': [{'name': 'public-http', 'backend': 'public',
                        'backend_self_link': 'https://compute.example/public'}],
            'frontend_backend_references': {},
        }
        with self.assertRaisesRegex(RuntimeError, 'do not cover declared routes'):
            MODULE.verify_frontend_references(config)

    def test_claimed_complete_migration_still_requires_applied_references(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, 'redirect.*replacement backend'):
                self.bootstrap(
                    directory,
                    migrated=True,
                    frontend_backend_references={
                        'public-http': ['https://compute.example/public-backend'],
                        'redirect': ['https://compute.example/legacy-redirect-backend'],
                    },
                )
            self.assertFalse((Path(directory) / 'etc' / 'sandbox').exists())


class BootstrapRuntimeTests(unittest.TestCase):
    def test_bootstrap_runtime_installs_helper_service_and_timer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = root / 'request.json'
            request.write_text('{}')
            (root / 'refresh-peer-credentials.py').write_text('# helper')
            (root / 'etc' / 'systemd' / 'system').mkdir(parents=True)

            def path(value):
                value = str(value)
                return root / value.lstrip('/') if value.startswith(('/etc/', '/usr/local/')) else Path(value)

            with patch.object(MODULE, 'ROOT', root), patch.object(MODULE, 'Path', side_effect=path), \
                 patch.object(MODULE, 'command') as command:
                MODULE.install_credential_runtime(request, required=True)

            helper = root / 'usr' / 'local' / 'sbin' / 'refresh-peer-credentials'
            units = root / 'etc' / 'systemd' / 'system'
            self.assertEqual(helper.read_text(), '# helper')
            self.assertEqual(helper.stat().st_mode & 0o777, 0o755)
            self.assertTrue((root / 'controller.py').exists())
            self.assertIn('ExecStart=/usr/bin/python3 /var/lib/proxy-rollout/controller.py --refresh-credentials',
                          (units / 'proxy-credential-rollout.service').read_text())
            self.assertIn('OnUnitInactiveSec=1min', (units / 'proxy-credential-rollout.timer').read_text())
            command.assert_has_calls([
                call('systemctl', 'daemon-reload'),
                call('systemctl', 'enable', '--now', 'proxy-credential-rollout.timer'),
            ])


class BootstrapTests(unittest.TestCase):
    def fixture(self):
        legacy = dict(id='', unit='proxy.service', ports=dict(public=5007, redirect=5008))
        state = dict(phase='preparing', rollout='migration', revision='abc',
                     bootstrap=True, old=legacy, candidate=copy.deepcopy(legacy))
        host = Mock()
        host.local.return_value = True
        snapshots = []
        runner = MODULE.Bootstrap(host, state, lambda value: snapshots.append(copy.deepcopy(value)))
        return runner, host, state, snapshots

    def test_bootstrap_adopts_legacy_without_starting_or_public_probe(self):
        runner, host, state, snapshots = self.fixture()
        runner.run(False)
        self.assertEqual(state['phase'], 'bootstrap_ready')
        host.start.assert_not_called()
        host.membership.assert_called_once_with(state['candidate'], True)
        host.local.assert_called_once_with(state['candidate'])
        self.assertLess(host.mock_calls.index(call.local(state['candidate'])),
                        host.mock_calls.index(call.membership(state['candidate'], True)))
        host.registered_ready.assert_not_called()
        host.verify.assert_not_called()
        host.propagated.assert_not_called()
        host.stop.assert_not_called()
        host.switch_private.assert_not_called()
        self.assertIn('bootstrap_registering', [s['phase'] for s in snapshots])

    def test_bootstrap_rejects_a_distinct_generation_candidate(self):
        runner, host, state, _ = self.fixture()
        state['candidate'] = copy.deepcopy(NEW)
        with self.assertRaisesRegex(RuntimeError, 'cannot create a replacement generation'):
            runner.run(False)
        host.start.assert_not_called()
        host.membership.assert_not_called()
        host.stop.assert_not_called()

    def test_migration_verifies_without_legacy_shutdown(self):
        runner, host, state, _ = self.fixture()
        runner.run(False)
        host.reset_mock()
        runner.run(True)
        self.assertEqual(state['phase'], 'complete')
        host.membership.assert_called_once_with(state['candidate'], True)
        host.verify.assert_called_once_with(state['candidate'])
        host.start.assert_not_called()
        host.stop.assert_not_called()
        host.propagated.assert_not_called()

    def test_failed_cutover_waits_for_terraform_restore_without_stopping_proxy(self):
        runner, host, state, _ = self.fixture()
        runner.run(False)
        host.verify.side_effect = RuntimeError('wrong candidate identity')
        with self.assertRaisesRegex(RuntimeError, 'restore legacy frontends with Terraform'):
            runner.run(True)
        self.assertEqual(state['phase'], 'migration_rollback_waiting')
        host.stop.assert_not_called()
        host.reset_mock()
        with self.assertRaisesRegex(RuntimeError, 'restore legacy frontends with Terraform'):
            runner.run(True)
        host.membership.assert_not_called()
        with self.assertRaisesRegex(RuntimeError, 'bootstrap rolled back'):
            runner.run(False)
        self.assertEqual(state['phase'], 'rolled_back')
        host.legacy_propagated.assert_called_once_with(state['old'])
        host.membership.assert_called_once_with(state['candidate'], False)
        host.stop.assert_not_called()

    def test_failed_legacy_restore_preserves_candidate(self):
        runner, host, state, _ = self.fixture()
        state['phase'] = 'migration_rollback_waiting'
        host.legacy_propagated.side_effect = RuntimeError('legacy unavailable')
        with self.assertRaisesRegex(RuntimeError, 'legacy unavailable'):
            runner.run(False)
        host.membership.assert_not_called()
        host.stop.assert_not_called()

    def test_interrupted_bootstrap_rechecks_local_without_starting_a_process(self):
        for interrupted in ('membership', 'local'):
            with self.subTest(interrupted=interrupted):
                runner, host, state, _ = self.fixture()
                getattr(host, interrupted).side_effect = Interrupted()
                with self.assertRaises(Interrupted):
                    runner.run(False)
                getattr(host, interrupted).side_effect = None
                host.reset_mock()
                runner.run(False)
                host.local.assert_called_once_with(state['candidate'])
                self.assertEqual(state['phase'], 'bootstrap_ready')
                host.stop.assert_not_called()

    def test_interrupted_migration_and_rollback_reconcile(self):
        for interrupted in ('verify', 'membership'):
            with self.subTest(interrupted=interrupted):
                runner, host, state, _ = self.fixture()
                runner.run(False)
                getattr(host, interrupted).side_effect = Interrupted()
                with self.assertRaises(Interrupted):
                    runner.run(True)
                getattr(host, interrupted).side_effect = None
                runner.run(True)
                self.assertEqual(state['phase'], 'complete')
        for interrupted in ('legacy_propagated', 'membership'):
            with self.subTest(rollback=interrupted):
                runner, host, state, _ = self.fixture()
                state['phase'] = 'migration_rollback_waiting'
                getattr(host, interrupted).side_effect = Interrupted()
                with self.assertRaises(Interrupted):
                    runner.run(False)
                getattr(host, interrupted).side_effect = None
                with self.assertRaisesRegex(RuntimeError, 'bootstrap rolled back'):
                    runner.run(False)
                self.assertEqual(state['phase'], 'rolled_back')

    def test_frontend_restore_after_interruption_enters_rollback(self):
        runner, host, state, _ = self.fixture()
        state.update(phase='migration_verifying', migration_started=True)
        with self.assertRaisesRegex(RuntimeError, 'bootstrap rolled back'):
            runner.run(False)
        host.start.assert_not_called()
        host.stop.assert_not_called()

    def test_failed_candidate_health_before_migration_restores_only_legacy(self):
        runner, host, state, _ = self.fixture()
        host.membership.side_effect = [RuntimeError('registration failed'), None]
        with self.assertRaisesRegex(RuntimeError, 'registration failed'):
            runner.run(False)
        self.assertEqual(state['phase'], 'rolled_back')
        host.propagated.assert_not_called()
        host.legacy_propagated.assert_called_once_with(state['old'])
        host.stop.assert_not_called()

    def test_failure_after_frontend_switch_keeps_legacy_process_running(self):
        runner, host, state, _ = self.fixture()
        host.verify.side_effect = RuntimeError('wrong candidate identity')
        with self.assertRaisesRegex(RuntimeError, 'restore legacy frontends with Terraform'):
            runner.run(True)
        self.assertEqual(state['phase'], 'migration_rollback_waiting')
        host.legacy_propagated.assert_not_called()
        host.reset_mock()
        with self.assertRaisesRegex(RuntimeError, 'restore legacy frontends with Terraform'):
            runner.run(True)
        host.start.assert_not_called()
        host.stop.assert_not_called()

    def test_manifest_migration_signal_does_not_change_static_identity(self):
        config = dict(instance='example-host', routes=[dict(listener='redirect')], migration_complete=False,
                      frontend_backend_references={'redirect': ['legacy-backend']},
                      serving_host={'instance': 'example-serving', 'ip': '192.0.2.10'})
        original = MODULE.manifest_identity(config)
        config['migration_complete'] = True
        config['frontend_backend_references'] = {'redirect': ['replacement-backend']}
        config['frontend_resources'] = {'redirect': ['target-tcp-proxy:example-redirect']}
        config['serving_host'] = {'instance': 'example-host', 'ip': '192.0.2.11'}
        self.assertEqual(MODULE.manifest_identity(config), original)
        config['routes'][0]['listener'] = 'public'
        self.assertNotEqual(MODULE.manifest_identity(config), original)

    def test_prepared_standby_accepts_legacy_hash_when_serving_host_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / 'proxy-rollout.json'
            prepared = dict(project='example-project', zone='us-central1-a',
                            instance='example-standby', ip='192.0.2.11',
                            routes=[dict(listener='public', backend='example-backend')],
                            serving_host={'instance': 'example-serving', 'ip': '192.0.2.10'})
            manifest.write_text(json.dumps(prepared))
            state = {'config_hash': MODULE.manifest_identity(
                prepared, include_serving_host=True)}
            promoted = copy.deepcopy(prepared)
            promoted['serving_host'] = {'instance': 'example-standby', 'ip': '192.0.2.11'}
            current = MODULE.check_manifest_identity(promoted, state, manifest)
            self.assertEqual(current, MODULE.manifest_identity(promoted))
            changed = copy.deepcopy(promoted)
            changed['routes'][0]['backend'] = 'different-backend'
            with self.assertRaisesRegex(RuntimeError, 'static rollout manifest changed'):
                MODULE.check_manifest_identity(changed, state, manifest)

            state['config_hash'] = current
            manifest.write_text(json.dumps(promoted))
            self.assertEqual(MODULE.check_manifest_identity(promoted, state, manifest), current)


class PreparationArtifactTests(unittest.TestCase):
    def test_prepare_without_peer_ingress_does_not_require_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            etc = root / 'etc'
            (etc / 'sandbox').mkdir(parents=True)
            (etc / 'systemd' / 'system').mkdir(parents=True)
            (etc / 'sandbox' / 'proxy.env').write_text('')
            (etc / 'sandbox' / 'vmd.env').write_text(
                'PROXY_HEALTH_URL=http://127.0.0.1:5007/health\n')
            upload = root / 'upload'
            upload.mkdir()
            (upload / 'proxy').write_bytes(b'immutable executable')
            (upload / 'proxy.service').write_text(
                (Path(__file__).parents[3] / 'deploy' / 'proxy-generation.service').read_text())

            generation = {
                'id': '0123456789abcdef0123',
                'unit': 'proxy-0123456789abcdef0123.service',
                'ports': {'public': 5110, 'redirect': 5111, 'peer': 5112, 'local': 5113},
            }
            request = {
                'rollout': 'example-rollout',
                'revision': 'revision-a',
                'env': {
                    'PROXY_DOMAIN': 'example.test',
                    'PEER_ROUTING_ENABLED': '0',
                    'PEER_PROXY_LISTEN_ADDR': '',
                    'PEER_PROXY_CERT_FILE': '/missing/tls.crt',
                    'PEER_PROXY_KEY_FILE': '/missing/tls.key',
                    'PEER_PROXY_CA_FILE': '/missing/ca.crt',
                },
            }
            host = Mock(config={'ip': '192.0.2.10', 'instance': 'example-host'},
                        assert_owned=Mock())

            def map_path(value):
                path = Path(value)
                return root / path.relative_to('/') if path.is_absolute() else path

            with patch.object(MODULE, 'ROOT', root / 'var' / 'lib' / 'proxy-rollout'), \
                 patch.object(MODULE, 'Path', side_effect=map_path), \
                 patch.object(MODULE, 'command') as command:
                MODULE.prepare(host, generation, request, upload)

            artifact = root / 'var' / 'lib' / 'proxy-rollout' / 'generations' / generation['id']
            generated_env = (artifact / 'proxy.env').read_text()
            for key in ('PEER_PROXY_CERT_FILE', 'PEER_PROXY_KEY_FILE', 'PEER_PROXY_CA_FILE'):
                self.assertNotIn(key, generated_env)
            self.assertFalse((artifact / 'credential-generation').exists())
            self.assertFalse((artifact / 'peer-cert').exists())
            self.assertFalse((artifact / 'peer-key').exists())
            self.assertFalse((artifact / 'peer-ca').exists())
            command.assert_called_once_with('systemctl', 'daemon-reload')

    def test_prepare_client_only_routing_snapshots_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            etc = root / 'etc'
            (etc / 'sandbox').mkdir(parents=True)
            (etc / 'systemd' / 'system').mkdir(parents=True)
            (etc / 'sandbox' / 'proxy.env').write_text('')
            (etc / 'sandbox' / 'vmd.env').write_text(
                'PROXY_HEALTH_URL=http://127.0.0.1:5007/health\n')
            sources = root / 'credential-sources'
            sources.mkdir()
            for name, content in (('cert', b'certificate'), ('key', b'private key'),
                                  ('ca', b'certificate authority')):
                (sources / name).write_bytes(content)
            upload = root / 'upload'
            upload.mkdir()
            (upload / 'proxy').write_bytes(b'immutable executable')
            (upload / 'proxy.service').write_text(
                (Path(__file__).parents[3] / 'deploy' / 'proxy-generation.service').read_text())

            generation = {
                'id': '0123456789abcdef0123',
                'unit': 'proxy-0123456789abcdef0123.service',
                'ports': {'public': 5110, 'redirect': 5111, 'peer': 5112, 'local': 5113},
            }
            request = {
                'rollout': 'example-rollout',
                'revision': 'revision-a',
                'env': {
                    'PROXY_DOMAIN': 'example.test',
                    'PEER_ROUTING_ENABLED': '1',
                    'PEER_PROXY_LISTEN_ADDR': '',
                    'PEER_PROXY_CERT_FILE': str(sources / 'cert'),
                    'PEER_PROXY_KEY_FILE': str(sources / 'key'),
                    'PEER_PROXY_CA_FILE': str(sources / 'ca'),
                },
            }
            host = Mock(config={'ip': '192.0.2.10', 'instance': 'example-host'},
                        assert_owned=Mock())
            original_snapshot = MODULE.snapshot_credentials

            def snapshot(env, pending, destination, snapshot_request):
                return original_snapshot(env, pending, destination, snapshot_request,
                                         published=etc / 'superserve' / 'peer' / 'current')

            def map_path(value):
                path = Path(value)
                return root / path.relative_to('/') if path.is_absolute() else path

            with patch.object(MODULE, 'ROOT', root / 'var' / 'lib' / 'proxy-rollout'), \
                 patch.object(MODULE, 'Path', side_effect=map_path), \
                 patch.object(MODULE, 'snapshot_credentials', side_effect=snapshot), \
                 patch.object(MODULE, 'command'):
                MODULE.prepare(host, generation, request, upload)

            artifact = root / 'var' / 'lib' / 'proxy-rollout' / 'generations' / generation['id']
            unit = (artifact / 'proxy.service').read_text()
            for name, content in (('peer-cert', b'certificate'), ('peer-key', b'private key'),
                                  ('peer-ca', b'certificate authority')):
                self.assertEqual((artifact / name).read_bytes(), content)
            self.assertIn('LoadCredential=peer-cert:', unit)
            self.assertIn('LoadCredential=peer-key:', unit)
            self.assertIn('LoadCredential=peer-ca:', unit)
            self.assertEqual((artifact / 'credential-generation').read_text(), '')

    def test_prepare_publishes_generation_scoped_artifacts_and_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            etc = root / 'etc'
            (etc / 'sandbox').mkdir(parents=True)
            (etc / 'superserve' / 'peer').mkdir(parents=True)
            (etc / 'systemd' / 'system').mkdir(parents=True)
            (etc / 'sandbox' / 'proxy.env').write_text(
                'PEER_PROXY_LISTEN_ADDR="192.0.2.10:5009"\n'
                'PEER_PROXY_MAX_STREAMS="128"\n')
            (etc / 'sandbox' / 'vmd.env').write_text(
                'PROXY_HEALTH_URL=http://127.0.0.1:5007/health\n'
                'PEER_PROXY_LISTEN_ADDR=192.0.2.10:5009\n')
            (etc / 'sandbox' / 'host-identity.env').write_text('HOST_ID=host-identity\n')
            (etc / 'superserve' / 'peer' / 'identity.json').write_text(
                json.dumps({'spiffe_uri': 'spiffe://example.test/host'}))
            published = etc / 'superserve' / 'peer' / 'certificate-a'
            published.mkdir()
            (etc / 'superserve' / 'peer' / 'current').symlink_to('certificate-a')

            credential_sources = root / 'credential-sources'
            credential_sources.mkdir()
            for name, content in (('cert', b'certificate'), ('key', b'private key'),
                                  ('ca', b'certificate authority')):
                (credential_sources / name).write_bytes(content)
            upload = root / 'upload'
            upload.mkdir()
            (upload / 'proxy').write_bytes(b'immutable executable')
            (upload / 'proxy.service').write_text(
                (Path(__file__).parents[3] / 'deploy' / 'proxy-generation.service').read_text())

            generation = {
                'id': '0123456789abcdef0123',
                'unit': 'proxy-0123456789abcdef0123.service',
                'ports': {'public': 5110, 'redirect': 5111, 'peer': 5112, 'local': 5113},
            }
            request = {
                'rollout': 'example-rollout',
                'revision': 'revision-a',
                'require_identity': True,
                'env': {
                    'PROXY_DOMAIN': 'example.test',
                    'PEER_PROXY_LISTEN_ADDR': '192.0.2.10:5009',
                    'PEER_PROXY_CERT_FILE': str(credential_sources / 'cert'),
                    'PEER_PROXY_KEY_FILE': str(credential_sources / 'key'),
                    'PEER_PROXY_CA_FILE': str(credential_sources / 'ca'),
                },
            }
            original_request = copy.deepcopy(request)
            host = Mock(config={'ip': '192.0.2.10'}, assert_owned=Mock())
            original_snapshot = MODULE.snapshot_credentials

            def snapshot(env, pending, destination, snapshot_request):
                return original_snapshot(env, pending, destination, snapshot_request,
                                         published=etc / 'superserve' / 'peer' / 'current')

            def map_path(value):
                path = Path(value)
                return root / path.relative_to('/') if path.is_absolute() else path

            with patch.object(MODULE, 'ROOT', root / 'var' / 'lib' / 'proxy-rollout'), \
                 patch.object(MODULE, 'Path', side_effect=map_path), \
                 patch.object(MODULE, 'snapshot_credentials', side_effect=snapshot), \
                 patch.object(MODULE, 'command') as command:
                MODULE.prepare(host, generation, request, upload)

            artifact = root / 'var' / 'lib' / 'proxy-rollout' / 'generations' / generation['id']
            generated_env = (artifact / 'proxy.env').read_text()
            self.assertEqual((artifact / 'proxy.env').stat().st_mode & 0o777, 0o600)
            self.assertIn('PROXY_GENERATION="0123456789abcdef0123"', generated_env)
            self.assertIn('PROXY_ADDR=":5110"', generated_env)
            self.assertIn('PROXY_REDIRECT_ADDR=":5111"', generated_env)
            self.assertIn('PEER_PROXY_LISTEN_ADDR="192.0.2.10:5112"', generated_env)
            self.assertIn('PEER_PROXY_TARGET_ADDR="127.0.0.1:5113"', generated_env)
            self.assertIn('PEER_PROXY_SPIFFE_URI="spiffe://example.test/host"', generated_env)
            self.assertIn('PEER_PROXY_MAX_STREAMS="128"', generated_env)
            self.assertIn('HOST_ID="host-identity"', generated_env)
            for legacy_port in ('5007', '5008', '5009', '5010'):
                self.assertNotIn(':' + legacy_port, generated_env)
            for key in ('PEER_PROXY_CERT_FILE', 'PEER_PROXY_KEY_FILE', 'PEER_PROXY_CA_FILE'):
                self.assertNotIn(key, generated_env)

            unit = (artifact / 'proxy.service').read_text()
            self.assertIn('Description=Superserve Edge Proxy generation 0123456789abcdef0123', unit)
            self.assertIn('ExecStart=/var/lib/proxy-rollout/generations/0123456789abcdef0123/proxy', unit)
            self.assertIn('EnvironmentFile=/var/lib/proxy-rollout/generations/0123456789abcdef0123/proxy.env', unit)
            self.assertIn('SyslogIdentifier=proxy-0123456789abcdef0123', unit)
            self.assertIn('LoadCredential=peer-cert:' + str(artifact / 'peer-cert'), unit)
            self.assertIn('LoadCredential=peer-key:' + str(artifact / 'peer-key'), unit)
            self.assertIn('LoadCredential=peer-ca:' + str(artifact / 'peer-ca'), unit)
            self.assertIn('Environment=PEER_PROXY_CERT_FILE=%d/peer-cert', unit)
            self.assertIn('Environment=PEER_PROXY_KEY_FILE=%d/peer-key', unit)
            self.assertIn('Environment=PEER_PROXY_CA_FILE=%d/peer-ca', unit)
            self.assertEqual((artifact / 'unit.template').read_text(),
                             (Path(__file__).parents[3] / 'deploy' / 'proxy-generation.service').read_text())
            self.assertEqual((artifact / 'proxy').read_bytes(), b'immutable executable')
            self.assertEqual((artifact / 'proxy').stat().st_mode & 0o777, 0o755)
            self.assertEqual(json.loads((artifact / 'generation.json').read_text()), generation)
            self.assertEqual((artifact / 'generation.json').stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads((artifact / 'request.json').read_text()), request)
            self.assertEqual((artifact / 'request.json').stat().st_mode & 0o777, 0o600)
            self.assertEqual(request, original_request)
            self.assertEqual((artifact / 'credential-generation').read_text(), 'certificate-a')
            for name, content in (('peer-cert', b'certificate'), ('peer-key', b'private key'),
                                  ('peer-ca', b'certificate authority')):
                self.assertEqual((artifact / name).read_bytes(), content)
                self.assertEqual((artifact / name).stat().st_mode & 0o777, 0o600)
            self.assertEqual((etc / 'systemd' / 'system' / generation['unit']).read_text(), unit)
            self.assertFalse(artifact.with_name(artifact.name + '.preparing').exists())
            command.assert_called_once_with('systemctl', 'daemon-reload')


class ReadinessRoutingTests(unittest.TestCase):
    def host(self):
        return MODULE.Host(dict(project='example-project', zone='us-central1-a',
                                instance='example-host', ip='192.0.2.10',
                                routes=[dict(listener='public', probe='https://east.example.test/health')]))

    def test_manifest_probes_must_reach_bare_domain_health(self):
        config = self.host().config
        env = {'PROXY_DOMAIN': 'east.example.test'}
        MODULE.validate_probes(config, env)
        for url in ('https://preview.east.example.test/health',
                    'https://proxy-readiness.invalid/health',
                    'http://east.example.test/health',
                    'https://east.example.test/preview',
                    'https://east.example.test/health?token=example',
                    'https://user:password@east.example.test/health',
                    'https://east.example.test:5100/health'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                MODULE.validate_probes({'routes': [dict(listener='public', probe=url)]}, env)
        MODULE.validate_probes({'routes': [dict(listener='redirect', probe='http://east.example.test/health')]}, env)

    def test_registration_gate_never_calls_external(self):
        host = self.host()
        host.local = Mock(return_value=True)
        host.health = Mock(return_value=True)
        host.external = Mock(side_effect=AssertionError('pre-cutover public probe'))
        host.registered_ready(NEW)
        host.external.assert_not_called()

    def test_external_preserves_real_host_and_tls_route(self):
        host = self.host()
        with patch.object(MODULE, 'command', return_value=json.dumps(
                dict(generation='new', resolver_ready=True))) as command:
            self.assertTrue(host.external(NEW))
        args = command.call_args.args
        self.assertEqual(args[-1], 'https://east.example.test/health')
        self.assertFalse(any(arg.lower().startswith('host:') for arg in args))
        self.assertNotIn('--insecure', args)
        self.assertIn('Connection: close', args)

    def test_external_checks_each_frontend_address_with_normal_host_and_tls(self):
        host = self.host()
        base = host.config['routes'][0]
        host.config['routes'] = [dict(base, probe_ip=address)
                                 for address in ('192.0.2.1', '192.0.2.2')]
        response = json.dumps(dict(generation='new', resolver_ready=True))
        with patch.object(MODULE, 'command', return_value=response) as command:
            self.assertTrue(host.external(NEW))
        self.assertEqual(command.call_count, 2)
        for call, address in zip(command.call_args_list, ('192.0.2.1', '192.0.2.2')):
            args = call.args
            self.assertEqual(args[args.index('--resolve') + 1],
                             f'east.example.test:443:{address}')
            self.assertEqual(args[-1], base['probe'])
            self.assertNotIn('--insecure', args)
            self.assertFalse(any(arg.lower().startswith('host:') for arg in args))
        with patch.object(MODULE, 'command', side_effect=[response,
                json.dumps(dict(generation='old', resolver_ready=True))]):
            self.assertFalse(host.external(NEW))

    def test_null_probe_address_preserves_retry_identity_but_new_address_does_not(self):
        config = self.host().config
        legacy_hash = MODULE.manifest_identity(config)
        config['routes'][0]['probe_ip'] = None
        self.assertEqual(MODULE.manifest_identity(config), legacy_hash)
        config['routes'][0]['probe_ip'] = '192.0.2.1'
        self.assertNotEqual(MODULE.manifest_identity(config), legacy_hash)

    def test_probe_address_validation_and_redirect_pinning(self):
        route = dict(listener='redirect', probe='http://east.example.test/health',
                     probe_ip='192.0.2.1')
        self.assertEqual(MODULE.probe_args(route),
                         ['--noproxy', '*', '--resolve', 'east.example.test:80:192.0.2.1'])
        self.assertEqual(MODULE.probe_args(dict(route, probe_ip=None)), [])
        for address in ('', 'example.test', '192.0.2.1:443', '::1', '192.0.2.1,192.0.2.2', 123, True):
            with self.subTest(address=address), self.assertRaises(ValueError):
                MODULE.validate_probes({'routes': [dict(route, probe_ip=address)]},
                                       {'PROXY_DOMAIN': 'east.example.test'})

    def test_redirect_verification_preserves_301_and_requires_candidate_readiness(self):
        host = self.host()
        host.config['routes'] = [dict(listener='redirect', probe='http://east.example.test/health')]
        response = ('HTTP/1.1 301 Moved Permanently\r\n'
                    'Location: https://east.example.test/health\r\n'
                    'X-Proxy-Generation: new\r\nX-Proxy-Resolver-Ready: true\r\n\r\n')
        with patch.object(MODULE, 'command', return_value=response) as command:
            self.assertTrue(host.external(NEW))
            self.assertNotIn('--location', command.call_args.args)
            self.assertNotIn('-L', command.call_args.args)
        for invalid in (response.replace('new', 'old'), response.replace('true', 'false'),
                        response.replace('301', '200'), response.replace('https://', 'http://'),
                        response.replace('X-Proxy-Generation: new\r\n', ''), 'not headers'):
            with self.subTest(invalid=invalid), patch.object(MODULE, 'command', return_value=invalid):
                self.assertFalse(host.external(NEW))
        legacy = response.replace('X-Proxy-Generation: new\r\nX-Proxy-Resolver-Ready: true\r\n', '')
        with patch.object(MODULE, 'command', return_value=legacy):
            self.assertTrue(host.external(dict(id='')))
            self.assertFalse(host.external(NEW))

    def test_external_rejects_bad_generation_or_resolver_and_transport_errors(self):
        host = self.host()
        for body in ('not-json', '{}', '[]',
                     '{"generation":"old","resolver_ready":true}',
                     '{"generation":"new","resolver_ready":false}'):
            with self.subTest(body=body), patch.object(MODULE, 'command', return_value=body):
                self.assertFalse(host.external(NEW))
        with patch.object(MODULE, 'command', side_effect=MODULE.subprocess.TimeoutExpired('curl', 5)):
            self.assertFalse(host.external(NEW))


class HostPropagationTests(unittest.TestCase):
    class Clock:
        def __init__(self, step=61):
            self.now = 0
            self.step = step

        def monotonic(self):
            return self.now

        def sleep(self, _seconds):
            self.now += self.step

    def host(self):
        return MODULE.Host(dict(
            project='example-project', zone='us-central1-a',
            instance='example-host', ip='192.0.2.10',
            routes=[dict(listener='public', probe='https://example.test/health')]))

    def command_responses(self, clock, external=None):
        local = json.dumps(dict(generation='new', resolver_ready=True))
        external = external or local

        def response(*args, **_kwargs):
            if any('127.0.0.2:' in str(arg) for arg in args):
                return local
            return external(clock.now) if callable(external) else external

        return response

    def configure_cloud(self, host, old_member=False, healthy=True):
        host.cloud.member = Mock(side_effect=lambda _route, port: (
            old_member if port == OLD['ports']['public'] else True))
        host.cloud.healthy = Mock(return_value=healthy)

    def test_propagated_requires_old_absence_and_sustained_real_readiness(self):
        host = self.host()
        clock = self.Clock()
        self.configure_cloud(host)
        with patch.object(MODULE, 'command', side_effect=self.command_responses(clock)), \
             patch.object(MODULE.time, 'monotonic', side_effect=clock.monotonic), \
             patch.object(MODULE.time, 'sleep', side_effect=clock.sleep):
            host.propagated(NEW, OLD)

        self.assertGreaterEqual(clock.now, 60)
        self.assertIn(call(host.config['routes'][0], OLD['ports']['public']),
                      host.cloud.member.call_args_list)
        self.assertIn(call(host.config['routes'][0], NEW['ports']['public']),
                      host.cloud.member.call_args_list)
        self.assertTrue(host.cloud.healthy.called)

    def test_propagated_rejects_candidate_that_loses_lb_health(self):
        host = self.host()
        clock = self.Clock()
        self.configure_cloud(host, healthy=False)
        with patch.object(MODULE, 'command', side_effect=self.command_responses(clock)), \
             patch.object(MODULE.time, 'monotonic', side_effect=clock.monotonic), \
             patch.object(MODULE.time, 'sleep', side_effect=clock.sleep):
            with self.assertRaisesRegex(RuntimeError, 'candidate lost readiness'):
                host.propagated(NEW, OLD)

    def test_propagated_rejects_candidate_that_loses_local_readiness(self):
        host = self.host()
        clock = self.Clock()
        self.configure_cloud(host)
        local = json.dumps(dict(generation='old', resolver_ready=True))
        external = json.dumps(dict(generation='new', resolver_ready=True))

        def response(*args, **_kwargs):
            return local if any('127.0.0.2:' in str(arg) for arg in args) else external

        with patch.object(MODULE, 'command', side_effect=response), \
             patch.object(MODULE.time, 'monotonic', side_effect=clock.monotonic), \
             patch.object(MODULE.time, 'sleep', side_effect=clock.sleep):
            with self.assertRaisesRegex(RuntimeError, 'candidate lost readiness'):
                host.propagated(NEW, OLD)

    def test_propagated_times_out_when_old_endpoint_remains_registered(self):
        host = self.host()
        clock = self.Clock()
        self.configure_cloud(host, old_member=True)
        with patch.object(MODULE, 'command', side_effect=self.command_responses(clock)), \
             patch.object(MODULE.time, 'monotonic', side_effect=clock.monotonic), \
             patch.object(MODULE.time, 'sleep', side_effect=clock.sleep):
            with self.assertRaisesRegex(RuntimeError, 'did not remain externally ready'):
                host.propagated(NEW, OLD)

    def test_propagated_starts_sustained_window_only_after_old_endpoint_disappears(self):
        host = self.host()
        clock = self.Clock(step=61)
        host.cloud.member = Mock(side_effect=lambda _route, port: (
            port == NEW['ports']['public']
            or (port == OLD['ports']['public'] and clock.now < 61)))
        host.cloud.healthy = Mock(return_value=True)
        with patch.object(MODULE, 'command', side_effect=self.command_responses(clock)), \
             patch.object(MODULE.time, 'monotonic', side_effect=clock.monotonic), \
             patch.object(MODULE.time, 'sleep', side_effect=clock.sleep):
            host.propagated(NEW, OLD)

        # The first ready probe occurs while the old endpoint is still present;
        # the full readiness window starts only after the next membership check.
        self.assertGreaterEqual(clock.now, 122)

    def test_propagated_restarts_window_after_transient_external_failure(self):
        host = self.host()
        clock = self.Clock(step=30)
        self.configure_cloud(host)
        external = lambda now: json.dumps(dict(
            generation='old' if now < 30 else 'new', resolver_ready=True))
        with patch.object(MODULE, 'command', side_effect=self.command_responses(clock, external)), \
             patch.object(MODULE.time, 'monotonic', side_effect=clock.monotonic), \
             patch.object(MODULE.time, 'sleep', side_effect=clock.sleep):
            host.propagated(NEW, OLD)

        self.assertGreaterEqual(clock.now, 90)

    def test_legacy_propagated_requires_sustained_real_local_and_external_readiness(self):
        host = self.host()
        clock = self.Clock()
        responses = iter([
            json.dumps(dict(generation='new', resolver_ready=True)),
            json.dumps(dict(generation='old', resolver_ready=True)),
            json.dumps(dict(generation='new', resolver_ready=True)),
            json.dumps(dict(generation='new', resolver_ready=True)),
        ])

        def response(*_args, **_kwargs):
            return next(responses, json.dumps(dict(generation='new', resolver_ready=True)))

        with patch.object(MODULE, 'command', side_effect=response), \
             patch.object(MODULE.time, 'monotonic', side_effect=clock.monotonic), \
             patch.object(MODULE.time, 'sleep', side_effect=clock.sleep):
            host.legacy_propagated(NEW)

        self.assertGreaterEqual(clock.now, 60)

    def test_legacy_propagated_retries_after_transient_local_readiness_loss(self):
        host = self.host()
        clock = self.Clock(step=30)
        responses = iter([
            json.dumps(dict(generation='old', resolver_ready=True)),
            json.dumps(dict(generation='new', resolver_ready=True)),
            json.dumps(dict(generation='new', resolver_ready=True)),
            json.dumps(dict(generation='new', resolver_ready=True)),
            json.dumps(dict(generation='new', resolver_ready=True)),
            json.dumps(dict(generation='new', resolver_ready=True)),
            json.dumps(dict(generation='new', resolver_ready=True)),
        ])

        with patch.object(MODULE, 'command', side_effect=lambda *_args, **_kwargs: next(responses)), \
             patch.object(MODULE.time, 'monotonic', side_effect=clock.monotonic), \
             patch.object(MODULE.time, 'sleep', side_effect=clock.sleep):
            host.legacy_propagated(NEW)

        # A local failure must clear the sustained-readiness timer rather than
        # allowing rollback to complete from an unverified interval.
        self.assertGreaterEqual(clock.now, 90)


class PrivateRoutingTests(unittest.TestCase):
    def test_cutover_only_rewrites_new_stable_port_connections(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            host = MODULE.Host(dict(project='example-project', zone='us-central1-a',
                                    instance='example-host', ip='192.0.2.10'), root)
            generation = dict(id='candidate', ports=dict(public=5110, peer=5112))
            marker = root / 'ready'
            with patch.object(MODULE, 'command') as command, \
                 patch.object(MODULE.subprocess, 'run', return_value=Mock(returncode=0)), \
                 patch.object(MODULE, 'Path', side_effect=lambda value: marker if str(value) ==
                              '/run/proxy-private-routing-ready' else Path(value)):
                host.switch_private(generation)
            self.assertEqual(command.call_count, 1)
            self.assertEqual(command.call_args.args,
                             ('iptables-restore', '--wait', '10', '--noflush'))
            rules = command.call_args.kwargs['input'].splitlines()
            self.assertIn('-A PROXY_GENERATION -d 192.0.2.10/32 -p tcp --dport 5009 '
                          '-j DNAT --to-destination 192.0.2.10:5112', rules)
            self.assertIn('-A PROXY_GENERATION -d 127.0.0.1/32 -p tcp --dport 5007 '
                          '-j DNAT --to-destination 127.0.0.1:5110', rules)
            self.assertEqual(rules[:3], ['*nat', ':PROXY_GENERATION - [0:0]',
                                        '-F PROXY_GENERATION'])
            self.assertEqual(rules[-1], 'COMMIT')
            self.assertEqual(len(rules), 6)
            self.assertEqual(json.loads((root / 'private.json').read_text()), generation)

    def test_failed_rule_commit_does_not_publish_private_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            host = MODULE.Host(dict(project='example-project', zone='us-central1-a',
                                    instance='example-host', ip='192.0.2.10'), root)
            previous = dict(id='old', ports=dict(public=5100, peer=5102))
            MODULE.atomic(root / 'private.json', previous)
            with patch.object(MODULE, 'command', side_effect=RuntimeError('rule commit failed')):
                with self.assertRaisesRegex(RuntimeError, 'rule commit failed'):
                    host.switch_private(dict(id='candidate', ports=dict(public=5110, peer=5112)))
            self.assertEqual(json.loads((root / 'private.json').read_text()), previous)


class Interrupted(BaseException):
    pass


class OwnershipStore:
    def __init__(self):
        self.generation = 0
        self.record = None

    def request(self, method, path, data=None):
        query = MODULE.urllib.parse.parse_qs(MODULE.urllib.parse.urlsplit(path).query)
        expected = query.get('ifGenerationMatch', [None])[0]
        current = str(self.generation) if self.record is not None else '0'
        if expected is not None and expected != current:
            raise MODULE.urllib.error.HTTPError(path, 412, 'precondition', {}, None)
        if method == 'POST':
            self.generation += 1
            self.record = copy.deepcopy(data)
        elif self.record is None:
            raise MODULE.urllib.error.HTTPError(path, 404, 'missing', {}, None)
        elif method == 'DELETE':
            self.record = None
            return
        elif query.get('alt') == ['media']:
            return copy.deepcopy(self.record)
        return {'generation': str(self.generation)}


class CellOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.state = Path(self.directory.name) / 'state.json'
        self.store = OwnershipStore()

    def owner(self, host='example-host', rollout='run', identity='inputs', instance_id='123456789'):
        config = dict(ownership_bucket='example-cell-ownership', instance=host, zone='us-central1-a')
        owner = MODULE.CellLock(config, rollout, identity, self.state, instance_id)
        owner.request = self.store.request
        return owner

    def test_other_hosts_and_new_rollouts_cannot_steal_unfinished_ownership(self):
        first = self.owner()
        first.acquire()
        for other in (self.owner(host='other-host'), self.owner(rollout='new-run'),
                      self.owner(instance_id='987654321'),
                      self.owner(identity='changed-inputs')):
            with self.assertRaisesRegex(RuntimeError, 'resume rollout run on example-host'):
                other.acquire()
        first.assert_owned()

    def test_interruption_retains_ownership_and_same_host_retry_fences_old_controller(self):
        original = self.owner()
        with self.assertRaises(Interrupted), original:
            MODULE.atomic(self.state, dict(rollout='run', request_hash='inputs', phase='withdrawn'))
            raise Interrupted()
        recovered = self.owner()
        recovered.acquire()
        with self.assertRaises(MODULE.OwnershipLost):
            original.assert_owned()
        with self.assertRaises(MODULE.OwnershipLost):
            original.release()
        recovered.assert_owned()

    def test_terminal_state_releases_for_another_host(self):
        for phase in ('complete', 'rolled_back'):
            with self.subTest(phase=phase), self.owner():
                MODULE.atomic(self.state, dict(rollout='run', request_hash='inputs', phase=phase))
            self.assertIsNone(self.store.record)
            other = self.owner(host='other-host', rollout='next-run')
            other.acquire()
            other.release()

    def test_old_terminal_state_does_not_release_interrupted_retry(self):
        MODULE.atomic(self.state, dict(rollout='run', request_hash='inputs', phase='rolled_back'))
        with self.assertRaises(Interrupted), self.owner():
            raise Interrupted()
        self.assertIsNotNone(self.store.record)

    def test_terminal_rollback_retry_releases_ownership_after_verifying_old(self):
        owner = self.owner()
        state = dict(rollout='run', request_hash='inputs', phase='rolled_back',
                     old=copy.deepcopy(OLD), candidate=copy.deepcopy(NEW))

        def save(value):
            MODULE.atomic(self.state, value)
            owner.terminal_saved = value['phase'] in MODULE.TERMINAL_PHASES

        MODULE.atomic(self.state, state)
        host = Mock()
        with self.assertRaisesRegex(RuntimeError, 'use a new rollout identity'), owner:
            MODULE.Rollout(host, state, save).run()

        host.verify.assert_called_once_with(OLD)
        self.assertIsNone(self.store.record)

    def test_failed_rollout_releases_only_after_durable_rollback(self):
        owner = self.owner()
        with self.assertRaises(RuntimeError), owner:
            MODULE.atomic(self.state, dict(rollout='run', request_hash='inputs', phase='rolled_back'))
            owner.terminal_saved = True
            raise RuntimeError('candidate failed')
        self.assertIsNone(self.store.record)

    def test_create_and_release_use_generation_preconditions(self):
        first, second = self.owner(), self.owner(host='other-host')
        request = first.request
        def race(method, path, data=None):
            if method == 'POST':
                second.acquire()
            return request(method, path, data)
        first.request = race
        with self.assertRaises(MODULE.urllib.error.HTTPError) as error:
            first.acquire()
        self.assertEqual(error.exception.code, 412)
        second.assert_owned()
        original_request = second.request
        def replace_before_delete(method, path, data=None):
            if method == 'DELETE':
                self.store.generation += 1
            return original_request(method, path, data)
        second.request = replace_before_delete
        with self.assertRaises(MODULE.urllib.error.HTTPError):
            second.release()
        self.assertIsNotNone(self.store.record)

    def test_ownership_loss_prevents_host_and_cloud_mutations(self):
        owner = self.owner()
        owner.acquire()
        self.store.generation += 1
        host = MODULE.Host(dict(project='example-project', zone='us-central1-a',
                                instance='example-host', ip='192.0.2.10'))
        host.ownership = host.cloud.ownership = owner
        with patch.object(MODULE, 'command') as command, \
             patch.object(host.cloud, 'request') as cloud_request:
            for mutation in (lambda: host.start(NEW), lambda: host.stop(OLD),
                             lambda: host.switch_private(NEW),
                             lambda: host.cloud.operation('endpoint', {})):
                with self.assertRaises(MODULE.OwnershipLost):
                    mutation()
            command.assert_not_called()
            cloud_request.assert_not_called()

    def test_ownership_read_failure_is_fail_closed(self):
        owner = self.owner()
        owner.acquire()
        owner.request = Mock(side_effect=TimeoutError('unavailable'))
        with self.assertRaises(MODULE.OwnershipLost):
            owner.assert_owned()

    def test_lost_controller_does_not_attempt_rollback(self):
        for lost_at in ('save', 'start'):
            with self.subTest(lost_at=lost_at):
                host = Mock()
                state = dict(phase='withdrawn', old=OLD, candidate=NEW)
                save = Mock()
                mutation = save if lost_at == 'save' else host.start
                mutation.side_effect = MODULE.OwnershipLost('replaced')
                with self.assertRaises(MODULE.OwnershipLost):
                    MODULE.Rollout(host, state, save).run()
                host.membership.assert_not_called()
                host.switch_private.assert_not_called()
                host.stop.assert_not_called()
                save.assert_called_once_with(state)
                self.assertEqual(state['phase'], 'starting')
                if lost_at == 'save':
                    host.start.assert_not_called()
                else:
                    host.start.assert_called_once_with(NEW)


class Host:
    def __init__(self):
        self.events=[]
        self.members={'old'}
        self.running={'old'}
        self.failure=None
        self.interrupt=None

    def event(self,name):
        self.events.append(name)
        if self.failure == name:
            self.failure=None
            raise RuntimeError(name)
        if self.interrupt == name:
            self.interrupt=None
            raise Interrupted()

    def start(self,g):
        self.running.add(g['id'])
        self.event('start '+g['id'])

    def local(self,g):
        self.event('local '+g['id'])
        return g['id'] in self.running

    def membership(self,g,present):
        if present: self.members.add(g['id'])
        else: self.members.discard(g['id'])
        self.event(('add ' if present else 'remove ')+g['id'])
        assert self.members, 'last endpoint removed'

    def health(self,g):
        self.event('health '+g['id'])
        return g['id'] in self.members and g['id'] in self.running

    def registered_ready(self,g):
        self.event('registered_ready '+g['id'])
        assert self.health(g) and self.local(g)

    def verify(self,g):
        self.registered_ready(g)
        self.event('verify '+g['id'])

    def switch_private(self,g):
        self.event('private '+g['id'])

    def propagated(self,g,old):
        self.event('propagated '+g['id'])
        assert g['id'] in self.members and old['id'] not in self.members

    def stop(self,g):
        self.running.discard(g['id'])
        self.event('stop '+g['id'])
        return 'success'


class RolloutTests(unittest.TestCase):
    def controller(self,host,phase='preparing'):
        state = dict(phase=phase,old=copy.deepcopy(OLD),candidate=copy.deepcopy(NEW),rollout='run',revision='abc')
        self.persisted=[]
        return MODULE.Rollout(host,state,lambda value:self.persisted.append(copy.deepcopy(value)))

    def test_standby_rollout_is_local_only(self):
        host = Mock()
        host.local.return_value = True
        state = dict(phase='preparing', old=copy.deepcopy(OLD), candidate=copy.deepcopy(NEW),
                     rollout='standby-run', revision='abc', target='standby')
        persisted = []
        MODULE.Rollout(host, state, lambda value: persisted.append(copy.deepcopy(value))).run()

        self.assertEqual(state['phase'], 'standby_ready')
        self.assertIs(state['active'], state['candidate'])
        host.start.assert_not_called()
        host.local.assert_not_called()
        host.membership.assert_not_called()
        host.registered_ready.assert_not_called()
        host.verify.assert_not_called()
        host.switch_private.assert_not_called()
        host.propagated.assert_not_called()
        host.stop.assert_not_called()

    def test_standby_retry_remains_preparation_only(self):
        host = Mock()
        host.local.return_value = True
        state = dict(phase='standby_ready', old=copy.deepcopy(OLD), candidate=copy.deepcopy(NEW),
                     active=copy.deepcopy(NEW), rollout='standby-run', revision='abc', target='standby')
        MODULE.StandbyRollout(host, state, lambda value: None).run()

        host.local.assert_not_called()
        host.start.assert_not_called()
        host.membership.assert_not_called()
        host.switch_private.assert_not_called()

    def test_host_lock_excludes_a_second_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'lock'
            with path.open('w') as first, path.open('w') as second:
                fcntl.flock(first,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(second,fcntl.LOCK_EX|fcntl.LOCK_NB)
                fcntl.flock(first,fcntl.LOCK_UN)
                fcntl.flock(second,fcntl.LOCK_EX|fcntl.LOCK_NB)

    def test_atomic_state_replacement_preserves_complete_document(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'state.json'
            MODULE.atomic(path,{'phase':'withdrawn','candidate':NEW})
            MODULE.atomic(path,{'phase':'stopping','candidate':NEW})
            self.assertEqual(json.loads(path.read_text())['phase'],'stopping')
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            self.assertFalse(path.with_suffix('.tmp').exists())

    def test_readiness_rejects_wrong_generation_false_and_malformed(self):
        for response in ({'generation':'old','resolver_ready':True},{'generation':'new','resolver_ready':False},
                         {'generation':'new','resolver_ready':1},{},[],None):
            self.assertFalse(MODULE.ready(response,'new'))
        self.assertTrue(MODULE.ready({'generation':'new','resolver_ready':True},'new'))

    def test_retry_inputs_are_fenced_before_preparation(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'proxy'
            binary.write_bytes(b'original binary')
            request = {'rollout': 'run', 'revision': 'abc', 'env': {'PROXY_DOMAIN': 'example.test'}}
            identity = MODULE.request_identity(request, binary)
            state = {'rollout': 'run', 'request_hash': identity, 'phase': 'preparing'}
            MODULE.check_retry(state, 'run', MODULE.request_identity(dict(reversed(list(request.items()))), binary))
            for replacement in (
                {**request, 'revision': 'different'},
                {**request, 'env': {'PROXY_DOMAIN': 'changed.example.test'}},
            ):
                with self.assertRaises(RuntimeError):
                    MODULE.check_retry(state, 'run', MODULE.request_identity(replacement, binary))
            binary.write_bytes(b'different binary')
            with self.assertRaises(RuntimeError):
                MODULE.check_retry(state, 'run', MODULE.request_identity(request, binary))
            MODULE.check_retry(state, 'another-run', 'different')

    def test_retry_cannot_change_unit_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            binary, unit = Path(directory) / 'proxy', Path(directory) / 'proxy.service'
            binary.write_bytes(b'original binary')
            unit.write_text('original unit')
            request = {'rollout': 'run'}
            identity = MODULE.request_identity(request, binary, unit)
            unit.write_text('changed unit')
            with self.assertRaisesRegex(RuntimeError, 'immutable rollout inputs'):
                MODULE.check_retry({'rollout': 'run', 'request_hash': identity},
                                   'run', MODULE.request_identity(request, binary, unit))

    def test_retired_rollout_cannot_be_replayed_after_artifact_cleanup(self):
        first = {'rollout': 'first', 'phase': 'complete'}
        second = {'rollout': 'second', 'phase': 'rolled_back',
                  'retired_rollouts': MODULE.retired_rollouts(first)}
        current = {'rollout': 'current', 'request_hash': 'current-inputs',
                   'retired_rollouts': MODULE.retired_rollouts(second)}
        for stale in ('first', 'second'):
            with self.subTest(rollout=stale), self.assertRaisesRegex(RuntimeError, 'stale rollout'):
                MODULE.check_retry(current, stale, 'any-inputs')
        MODULE.check_retry(current, 'current', 'current-inputs')
        MODULE.check_retry(current, 'new-redeployment', 'old-revision')

    def test_pruning_retired_failed_candidates_preserves_current_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            units = root / 'units'
            units.mkdir()
            keep = {'a' * 20, 'b' * 20}
            retired = 'c' * 20
            for generation in keep | {retired}:
                artifact = root / 'generations' / generation
                artifact.mkdir(parents=True)
                (artifact / 'proxy.env').write_text('example configuration')
                (artifact / 'generation.json').write_text(json.dumps(dict(
                    id=generation, unit=f'proxy-{generation}.service', ports={'public': 5100})))
                (units / f'proxy-{generation}.service').touch()
            host = Mock(assert_owned=Mock(), config={'routes': [dict(listener='public')]})
            host.cloud.member.return_value = False
            with patch.object(MODULE, 'command', return_value='inactive\n') as command:
                MODULE.prune_generations(root, keep, host, units)
            self.assertEqual({p.name for p in (root / 'generations').iterdir()}, keep)
            self.assertEqual({p.name for p in units.iterdir()}, {f'proxy-{g}.service' for g in keep})
            command.assert_any_call('systemctl', 'disable', f'proxy-{retired}.service')
            host.cloud.member.assert_called_once_with(dict(listener='public'), 5100)
            for call in command.call_args_list:
                self.assertFalse(any(f'proxy-{g}.service' in call.args for g in keep))

    def test_pruning_refuses_running_or_restarting_generation(self):
        for status in ('active', 'activating', 'deactivating', 'unknown', ''):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                artifact = root / 'generations' / ('d' * 20)
                artifact.mkdir(parents=True)
                with patch.object(MODULE, 'command', return_value=status) as command:
                    with self.assertRaisesRegex(RuntimeError, 'active retained generation'):
                        MODULE.prune_generations(root, set(), Mock(assert_owned=Mock()), root)
                self.assertTrue(artifact.exists())
                self.assertEqual(command.call_count, 1)

    def test_interrupted_preparation_is_removed_without_touching_live_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, candidate = 'a' * 20, 'b' * 20
            live = root / 'generations' / active
            live.mkdir(parents=True)
            (live / 'proxy').write_bytes(b'serving')
            pending = root / 'generations' / (candidate + '.preparing')
            pending.mkdir()
            (pending / 'proxy').write_bytes(b'partial upload')
            with patch.object(MODULE, 'command') as command:
                MODULE.prune_generations(root, {active, candidate}, Mock(assert_owned=Mock()), root / 'units')
            self.assertFalse(pending.exists())
            self.assertEqual((live / 'proxy').read_bytes(), b'serving')
            command.assert_called_once_with('systemctl', 'daemon-reload')

    def test_pruning_never_deletes_registered_or_unidentified_artifacts(self):
        for mode in ('registered', 'missing', 'wrong_identity', 'cloud_unavailable'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                generation = 'c' * 20
                artifact = root / 'generations' / generation
                artifact.mkdir(parents=True)
                metadata = dict(id=generation, unit=f'proxy-{generation}.service',
                                ports={'public': 5100})
                if mode == 'wrong_identity':
                    metadata['id'] = 'd' * 20
                if mode != 'missing':
                    (artifact / 'generation.json').write_text(json.dumps(metadata))
                host = Mock(assert_owned=Mock(), config={'routes': [dict(listener='public')]})
                host.cloud.member.return_value = mode == 'registered'
                if mode == 'cloud_unavailable':
                    host.cloud.member.side_effect = RuntimeError('health API unavailable')
                with patch.object(MODULE, 'command', return_value='inactive') as command:
                    with self.assertRaises((RuntimeError, FileNotFoundError)):
                        MODULE.prune_generations(root, set(), host, root / 'units')
                self.assertTrue(artifact.exists())
                self.assertEqual(command.call_count, 1)

    def test_generation_publication_flushes_artifacts_before_rename(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pending, target = root / 'generation.preparing', root / 'generation'
            pending.mkdir()
            (pending / 'proxy').write_bytes(b'executable')
            (pending / 'peer-key').write_bytes(b'invented credential')
            events = []
            rename = MODULE.os.rename
            def publish(source, destination):
                events.append('rename')
                rename(source, destination)
            with patch.object(MODULE.os, 'fsync', side_effect=lambda fd: events.append('sync')), \
                 patch.object(MODULE.os, 'rename', side_effect=publish):
                MODULE.publish_generation(pending, target)
            self.assertEqual(events, ['sync', 'sync', 'sync', 'rename', 'sync'])
            self.assertEqual((target / 'proxy').read_bytes(), b'executable')
            self.assertFalse(pending.exists())

    def test_failed_artifact_flush_does_not_publish_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pending, target = root / 'generation.preparing', root / 'generation'
            pending.mkdir()
            (pending / 'proxy').write_bytes(b'executable')
            with patch.object(MODULE.os, 'fsync', side_effect=OSError('disk failure')):
                with self.assertRaisesRegex(OSError, 'disk failure'):
                    MODULE.publish_generation(pending, target)
            self.assertFalse(target.exists())
            self.assertTrue(pending.exists())

    def test_preparation_failure_releases_only_a_never_started_candidate(self):
        for active, member, releasable in (
            ('inactive', False, True), ('failed', False, True),
            ('active', False, False), ('activating', False, False),
            ('deactivating', False, False), ('', False, False),
            ('inactive', True, False),
        ):
            with self.subTest(active=active, member=member):
                host = Mock()
                host.config = {'routes': [{'listener': 'public'}]}
                host.cloud.member.return_value = member
                controller = self.controller(host)
                with patch.object(MODULE, 'command', return_value=active):
                    MODULE.abandon_preparation(host, controller.state, controller.save)
                self.assertEqual(controller.state['phase'], 'rolled_back' if releasable else 'preparing')
                if releasable:
                    host.verify.assert_called_once_with(OLD)
                    self.assertEqual(controller.state['active'], OLD)
                else:
                    host.verify.assert_not_called()

    def test_preparation_failure_does_not_release_state_when_old_is_unverified(self):
        host = Mock()
        host.config = {'routes': [{'listener': 'public'}]}
        host.cloud.member.return_value = False
        host.verify.side_effect = RuntimeError('old external readiness failed')
        controller = self.controller(host)
        with patch.object(MODULE, 'command', return_value='inactive'):
            with self.assertRaisesRegex(RuntimeError, 'old external readiness failed'):
                MODULE.abandon_preparation(host, controller.state, controller.save)
        self.assertEqual(controller.state['phase'], 'preparing')
        self.assertEqual(self.persisted, [])

    def test_legacy_retirement_stops_socket_only_after_grace(self):
        with tempfile.TemporaryDirectory() as directory:
            dropin = Path(directory) / 'generation-retirement.conf'
            events = []

            def command(*args, **kwargs):
                events.append(args)
                return 'loaded' if 'LoadState' in args else ''

            def stop(args, **kwargs):
                events.append(tuple(args))

            host = MODULE.Host({'project': 'example', 'zone': 'us-central1-a',
                                'instance': 'example-host', 'ip': '192.0.2.1'})
            legacy = {'id': '', 'unit': 'proxy.service', 'drain_started': 100, 'drain_seconds': 30}
            with patch.object(MODULE, 'Path', return_value=dropin), \
                 patch.object(MODULE, 'command', side_effect=command), \
                 patch.object(MODULE.subprocess, 'run', side_effect=stop), \
                 patch.object(MODULE.time, 'time', return_value=110), \
                 patch.object(MODULE.time, 'sleep', side_effect=lambda seconds: events.append(('sleep', seconds))):
                result = host.stop(legacy)
            retirement = ('systemctl', 'disable', '--now', 'proxy.service', 'proxy.socket')
            self.assertLess(events.index(('sleep', 20)), events.index(retirement))
            self.assertIn('KillSignal=SIGKILL', dropin.read_text())
            self.assertTrue(result['legacy_forced'])

    def test_order_and_irreversible_boundary(self):
        host=Host()
        controller=self.controller(host)
        controller.run()
        self.assertLess(host.events.index('registered_ready new'),host.events.index('remove old'))
        self.assertGreater(host.events.index('verify new'),host.events.index('remove old'))
        self.assertLess(host.events.index('propagated new'),host.events.index('stop old'))
        self.assertEqual(controller.state['phase'],'complete')
        self.assertEqual(self.persisted[-2]['phase'],'stopping')
        self.assertEqual(host.members,{'new'})

    def test_failure_restores_old_before_candidate_stop(self):
        for event in ('start new','local new','registered_ready new','health new','remove old','private new','propagated new'):
            with self.subTest(event=event):
                host=Host();host.failure=event
                controller=self.controller(host)
                with self.assertRaises(RuntimeError): controller.run()
                self.assertEqual(controller.state['phase'],'rolled_back')
                self.assertEqual(host.members,{'old'})
                self.assertNotIn('stop old',host.events)
                self.assertLess(host.events.index('remove new'),host.events.index('verify old'))
                self.assertLess(host.events.index('remove new'),host.events.index('health old'))
                self.assertLess(host.events.index('propagated old'),host.events.index('stop new'))

    def test_failure_after_shutdown_never_restores_stopped_old(self):
        host=Host();host.failure='stop old'
        controller=self.controller(host)
        with self.assertRaises(RuntimeError):controller.run()
        self.assertEqual(controller.state['phase'],'stopping')
        self.assertEqual(host.members,{'new'})
        controller.run()
        self.assertEqual(controller.state['phase'],'complete')
        self.assertNotIn('add old',host.events)

    def test_interruption_after_side_effect_before_persistence_reconciles(self):
        for event in ('start new','add new','remove old','private new','stop old'):
            with self.subTest(event=event):
                host=Host();host.interrupt=event
                controller=self.controller(host)
                with self.assertRaises(Interrupted):controller.run()
                controller.run()
                self.assertEqual(controller.state['phase'],'complete')
                self.assertEqual(host.members,{'new'})

    def test_retry_of_interrupted_rollback_never_resumes_forward_cutover(self):
        for event in ('add old', 'private old', 'remove new', 'stop new'):
            with self.subTest(event=event):
                host = Host()
                host.failure = 'propagated new'
                host.interrupt = event
                controller = self.controller(host)
                with self.assertRaises(Interrupted):
                    controller.run()
                host.events.clear()
                with self.assertRaisesRegex(RuntimeError, 'rollback completed'):
                    controller.run()
                self.assertEqual(controller.state['phase'], 'rolled_back')
                self.assertEqual(host.members, {'old'})
                self.assertEqual(host.running, {'old'})
                self.assertNotIn('start new', host.events)
                self.assertNotIn('remove old', host.events)

    def test_terminal_rollback_retry_does_not_start_candidate(self):
        host = Host()
        controller = self.controller(host, phase='rolled_back')
        with self.assertRaisesRegex(RuntimeError, 'use a new rollout identity'):
            controller.run()
        self.assertEqual(host.running, {'old'})
        self.assertNotIn('start new', host.events)

    def test_failed_old_restoration_preserves_candidate(self):
        host=Host();host.failure='propagated new'
        controller=self.controller(host)
        def fail(g):
            if g['id']=='old':raise RuntimeError('old unhealthy')
            return True
        host.local=fail
        with self.assertRaises(RuntimeError):controller.run()
        self.assertEqual(host.members, {'old'})
        self.assertNotIn('stop new',host.events)

    def test_failed_old_external_verification_preserves_candidate(self):
        host = Host()
        host.failure = 'propagated new'
        controller = self.controller(host)
        verify = host.verify

        def external_failure(generation):
            verify(generation)
            if generation['id'] == 'old':
                raise RuntimeError('old external probe failed')

        host.verify = external_failure
        with self.assertRaisesRegex(RuntimeError, 'old external probe failed'):
            controller.run()
        self.assertEqual(controller.state['phase'], 'rollback_restoring')
        self.assertEqual(host.members, {'old'})
        self.assertLess(host.events.index('remove new'), host.events.index('verify old'))
        self.assertNotIn('stop new', host.events)

    def test_rollback_detaches_candidate_before_verifying_old_route(self):
        host = Host()
        host.failure = 'propagated new'
        controller = self.controller(host)
        original_verify = host.verify

        def verify_old_only(generation):
            if generation['id'] == 'old':
                self.assertNotIn('new', host.members)
            original_verify(generation)

        host.verify = verify_old_only
        with self.assertRaises(RuntimeError):
            controller.run()
        self.assertEqual(host.members, {'old'})
        self.assertLess(host.events.index('remove new'), host.events.index('verify old'))
        self.assertLess(host.events.index('verify old'), host.events.index('stop new'))


if __name__ == '__main__':
    unittest.main()
