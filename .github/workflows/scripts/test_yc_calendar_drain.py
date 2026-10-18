import copy
import unittest

import yc_calendar_drain as drain


IMAGE = drain.common.IMAGE + '@sha256:' + 'a' * 64


class Provider:
    def __init__(self):
        self.service = {'name': drain.SERVICE, 'uid': 'synthetic-service', 'etag': '1',
                        'generation': '1', 'observedGeneration': '1',
                        'terminalCondition': {'state': 'CONDITION_SUCCEEDED'},
                        'latestReadyRevision': drain.SERVICE + '/revisions/old',
                        'scaling': {'scalingMode': 'AUTOMATIC', 'minInstanceCount': 1, 'maxInstanceCount': 5},
                        'template': {'containers': [{'image': 'synthetic-old-image', 'env': [
                            {'name': name, 'valueSource': {'secretKeyRef': {'secret': secret, 'version': 'latest'}}}
                            for name, secret in drain.common.SECRETS.items()]}]},
                        'traffic': [{'revision': 'old', 'percent': 100, 'tag': 'old-tag'}]}
        self.revisions = [self.revision('old', self.service['template']['containers'])]
        self.mutations = []
        self.retire = True
        self.fail_patch = None

    def revision(self, name, containers):
        return {'name': drain.SERVICE + '/revisions/' + name, 'uid': 'synthetic-' + name,
                'generation': '1', 'observedGeneration': '1', 'containers': copy.deepcopy(containers),
                'conditions': [{'type': 'Ready', 'state': 'CONDITION_SUCCEEDED'}]}

    def request(self, path, body=None, mask=None):
        if body is not None:
            self.mutations.append(copy.deepcopy(body))
            if self.fail_patch == len(self.mutations):
                raise drain.common.GateError('Synthetic provider failure')
            if body['etag'] != self.service['etag']:
                raise drain.common.GateError('Synthetic etag conflict')
            for key in mask.split(','):
                self.service[key] = copy.deepcopy(body[key])
            self.service['generation'] = self.service['observedGeneration'] = str(len(self.mutations) + 1)
            self.service['etag'] = self.service['generation']
            self.service['trafficStatuses'] = copy.deepcopy(self.service.get('traffic', []))
            if 'template' in body:
                name = body['template']['revision']
                self.revisions.append(self.revision(name, body['template']['containers']))
                self.service['latestReadyRevision'] = drain.SERVICE + '/revisions/' + name
                if self.retire:
                    for revision in self.revisions[:-1]:
                        revision['conditions'] = [{'type': 'Ready', 'state': 'CONDITION_FAILED', 'revisionReason': 'RETIRED'}]
            return {'name': drain.PARENT + '/operations/synthetic', 'done': True,
                    'response': {'name': drain.SERVICE, 'generation': self.service['generation']}}
        if path == drain.SERVICE:
            return copy.deepcopy(self.service)
        if path == drain.SERVICE + '/revisions':
            return {'revisions': copy.deepcopy(self.revisions)}
        raise AssertionError(path)


class DrainTests(unittest.TestCase):
    def setUp(self):
        self.provider = Provider()
        self.events = []
        self.runner = drain.Drain(drain.inventory(self.provider.request), IMAGE, '123',
                                  versions={k: '9' for k in drain.common.SECRETS},
                                  get=self.provider.request, sleep=lambda _: None,
                                  audit=lambda phase, state: self.events.append(phase))

    def test_only_inert_entrypoint_before_verified_migration(self):
        original_scaling = copy.deepcopy(self.provider.service['scaling'])
        self.runner.pause()
        self.runner.barrier()
        self.assertEqual(self.provider.service['template']['containers'][0]['command'], ['/bin/sleep'])
        self.assertNotIn('old-tag', str(self.provider.service['traffic']))
        with self.assertRaisesRegex(drain.common.GateError, 'Verified migration'):
            self.runner.resume(False)
        self.assertEqual(len(self.provider.mutations), 2)
        self.runner.resume(True)
        application = self.provider.service['template']['containers'][0]
        self.assertNotIn('command', application)
        self.assertEqual(application['image'], IMAGE)
        self.assertEqual(self.provider.service['scaling'], original_scaling)
        self.assertEqual({e['valueSource']['secretKeyRef']['version'] for e in application['env']}, {'9'})
        self.assertLess(self.events.index('old_revisions_retired'), self.events.index('application_start_requested'))

    def test_scaling_change_invalidates_preflight_even_without_template_change(self):
        self.provider.service['scaling']['minInstanceCount'] = 2
        with self.assertRaisesRegex(drain.common.GateError, 'Runtime changed'):
            self.runner.pause()
        self.assertEqual(self.provider.mutations, [])

    def test_no_telemetry_or_nonterminal_status_is_not_retirement(self):
        self.provider.retire = False
        self.runner.pause()
        for conditions in ([], [{'revisionReason': 'RETIRING', 'state': 'CONDITION_FAILED'}],
                           [{'revisionReason': 'RETIRED', 'state': 'CONDITION_RECONCILING'}]):
            self.provider.revisions[0]['conditions'] = conditions
            with self.assertRaisesRegex(drain.common.GateError, 'not verifiably retired'):
                self.runner.barrier()
        self.assertEqual(len(self.provider.mutations), 2)

    def test_retirement_from_an_old_generation_is_not_evidence(self):
        self.runner.pause()
        self.provider.revisions[0]['observedGeneration'] = '0'
        with self.assertRaisesRegex(drain.common.GateError, 'not verifiably retired'):
            self.runner.barrier()

    def test_missing_or_invalid_generations_cannot_prove_retirement(self):
        for generation in (None, '', '0', 'unknown'):
            with self.subTest(generation=generation):
                provider = Provider()
                revision = provider.revisions[0]
                revision.pop('generation', None)
                revision.pop('observedGeneration', None)
                if generation is not None:
                    revision.update(generation=generation, observedGeneration=generation)
                runner = drain.Drain(drain.inventory(provider.request), IMAGE, '123',
                                     versions={k: '9' for k in drain.common.SECRETS},
                                     get=provider.request, sleep=lambda _: None)
                runner.pause()
                with self.assertRaisesRegex(drain.common.GateError, 'not verifiably retired'):
                    runner.barrier()

    def test_missing_service_generations_do_not_prove_readiness(self):
        self.provider.service.pop('generation')
        self.provider.service.pop('observedGeneration')
        with self.assertRaisesRegex(drain.common.GateError, 'reconciling'):
            drain.inventory(self.provider.request)

    def test_missing_revision_is_not_assumed_deleted(self):
        self.runner.pause()
        self.provider.revisions.pop(0)
        with self.assertRaisesRegex(drain.common.GateError, 'inventory changed'):
            self.runner.barrier()

    def test_new_revision_or_reintroduced_tag_blocks_barrier(self):
        self.runner.pause()
        self.provider.service['traffic'].append({'revision': 'old', 'tag': 'escape'})
        with self.assertRaisesRegex(drain.common.GateError, 'traffic'):
            self.runner.barrier()

    def test_accepted_but_failed_update_never_counts_as_pause(self):
        self.provider.service['terminalCondition'] = {'state': 'CONDITION_FAILED'}
        with self.assertRaisesRegex(drain.common.GateError, 'not ready'):
            self.runner.pause()
        self.assertEqual(self.provider.mutations, [])

    def test_provider_partial_failure_has_no_automatic_rollback(self):
        self.provider.fail_patch = 2
        with self.assertRaisesRegex(drain.common.GateError, 'Synthetic provider failure'):
            self.runner.pause()
        self.assertEqual(self.provider.service['scaling']['manualInstanceCount'], 0)
        self.assertEqual(len(self.provider.mutations), 2)
        self.assertNotIn('application_start_requested', self.events)

    def test_resume_failure_reports_start_requested_without_claiming_paused(self):
        self.runner.pause()
        self.provider.fail_patch = 4
        with self.assertRaises(drain.common.GateError):
            self.runner.resume(True)
        self.assertIn('application_start_requested', self.events)
        self.assertNotIn('compatible_runtime_resumed', self.events)
        self.assertEqual(len(self.provider.mutations), 4)

    def test_second_container_cannot_escape_entrypoint_override(self):
        self.provider.service['template']['containers'].append({'image': 'synthetic-sidecar'})
        with self.assertRaisesRegex(drain.common.GateError, 'one-container'):
            drain.inventory(self.provider.request)

    def test_failed_asynchronous_resume_cannot_claim_success(self):
        self.runner.pause()
        original = self.provider.request
        def request(path, body=None, mask=None):
            if body is not None and mask == 'scaling':
                return {'name': drain.PARENT + '/operations/failed'}
            if path.endswith('/operations/failed'):
                return {'name': path, 'done': True, 'error': {'code': 13}}
            return original(path, body, mask)
        self.runner.get = request
        with self.assertRaisesRegex(drain.common.GateError, 'mutation failed'):
            self.runner.resume(True)
        self.assertNotIn('compatible_runtime_resumed', self.events)
        self.assertEqual(self.provider.service['scaling']['manualInstanceCount'], 0)

    def test_pending_operation_does_not_accept_previous_ready_service(self):
        original = self.provider.request
        def request(path, body=None, mask=None):
            if body is not None or '/operations/' in path:
                return {'name': drain.PARENT + '/operations/pending', 'done': False}
            return original(path)
        self.runner.get = request
        with self.assertRaisesRegex(drain.common.GateError, 'operation incomplete'):
            self.runner.pause()
        self.assertEqual(self.provider.mutations, [])

    def test_revision_pagination_is_exhausted(self):
        original = self.provider.request
        def get(path, *args):
            if path.endswith('/revisions'):
                return {'revisions': [], 'nextPageToken': 'next'}
            if path.endswith('?pageToken=next'):
                return original(drain.SERVICE + '/revisions')
            return original(path, *args)
        self.assertEqual(len(drain.inventory(get)['revisions']), 1)


if __name__ == '__main__':
    unittest.main()
