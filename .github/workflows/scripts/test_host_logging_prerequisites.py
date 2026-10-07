"""Exercise metadata preservation, immutable targeting, and propagation retries."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location(
    'prerequisites', ROOT / 'infra/modules/host-logging/prerequisites.py')
prerequisites = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prerequisites)

CONFIG = dict(project_id='example-project', zone='example-a',
              instance_name='example-host', instance_id='123456')
BASE = 'https://compute.googleapis.com/compute/v1/projects/example-project/zones/example-a'


def instance(items=None, fingerprint='original'):
    return dict(id='123456', name='example-host',
                metadata=dict(fingerprint=fingerprint, items=items or []))


def operation(**values):
    return dict(dict(name='operation-example', targetId='123456', status='DONE'), **values)


class MetadataTests(unittest.TestCase):
    def test_preserves_unrelated_metadata_and_rechecks_success(self):
        original = [{'key': 'ssh-keys', 'value': 'example-key'},
                    {'key': 'startup-script', 'value': 'example script'},
                    {'key': 'other-setting', 'value': 'keep me'},
                    {'key': 'enable-osconfig', 'value': 'FALSE'}]
        enabled = [item for item in original if item['key'] != 'enable-osconfig']
        enabled.append({'key': 'enable-osconfig', 'value': 'TRUE'})
        with patch.object(prerequisites, 'request', side_effect=[
                instance(original), operation(status='PENDING'), operation(),
                instance(enabled)]) as request, patch.object(prerequisites, 'pause'):
            prerequisites.instance_metadata(CONFIG, 100)
        self.assertEqual(request.call_args_list[1].args,
                         ('POST', BASE + '/instances/123456/setMetadata',
                          {'fingerprint': 'original', 'items': enabled}))
        self.assertEqual(request.call_args_list[2].args,
                         ('GET', BASE + '/operations/operation-example'))
        self.assertEqual(request.call_args_list[-1].args,
                         ('GET', BASE + '/instances/123456'))

    def test_already_enabled_does_not_write(self):
        with patch.object(prerequisites, 'request', return_value=instance([
                {'key': 'enable-osconfig', 'value': 'true'}])) as request:
            prerequisites.instance_metadata(CONFIG, 100)
        request.assert_called_once_with('GET', BASE + '/instances/123456')

    def test_conflict_rereads_and_preserves_concurrent_key(self):
        concurrent = [{'key': 'new-setting', 'value': 'concurrent change'}]
        enabled = concurrent + [{'key': 'enable-osconfig', 'value': 'TRUE'}]
        with patch.object(prerequisites, 'request', side_effect=[
                instance(), prerequisites.ApiError(412),
                instance(concurrent, 'fresh'), operation(), instance(enabled)]) as request, \
                patch.object(prerequisites, 'pause'):
            prerequisites.instance_metadata(CONFIG, 100)
        self.assertEqual(request.call_args_list[3].args[2],
                         {'fingerprint': 'fresh', 'items': enabled})

    def test_wrong_identity_or_missing_fingerprint_never_writes(self):
        for key, value in (('id', '999999'), ('name', 'replaced-host'),
                           ('metadata', {'items': []})):
            with self.subTest(key=key):
                current = instance()
                current[key] = value
                with patch.object(prerequisites, 'request', return_value=current) as request:
                    with self.assertRaises(RuntimeError):
                        prerequisites.instance_metadata(CONFIG, 100)
                self.assertEqual(request.call_count, 1)

    def test_failed_or_mistargeted_operation_is_not_success(self):
        for result in (operation(targetId='999999'), operation(error={'errors': [{}]})):
            with self.subTest(result=result):
                with patch.object(prerequisites, 'request', side_effect=[instance(), result]):
                    with self.assertRaises(RuntimeError):
                        prerequisites.instance_metadata(CONFIG, 100)

    def test_metadata_conflict_is_bounded(self):
        with patch.object(prerequisites, 'request', side_effect=[
                instance(), prerequisites.ApiError(412)]) as request, \
                patch.object(prerequisites.time, 'monotonic', return_value=101):
            with self.assertRaises(TimeoutError):
                prerequisites.instance_metadata(CONFIG, 100)
        self.assertEqual(request.call_count, 2)


class ProjectTests(unittest.TestCase):
    def test_full_feature_set_is_noop(self):
        with patch.object(prerequisites, 'request', return_value={
                'patchAndConfigFeatureSet': 'OSCONFIG_C'}) as request:
            prerequisites.project_features('example-project', 100)
        self.assertEqual(request.call_count, 1)

    def test_patch_changes_only_feature_field_and_retries_permission_propagation(self):
        with patch.object(prerequisites, 'request', side_effect=[
                prerequisites.ApiError(403),
                {'patchAndConfigFeatureSet': 'OSCONFIG_B', 'unrelated': 'preserved'},
                {'patchAndConfigFeatureSet': 'OSCONFIG_C'},
                {'patchAndConfigFeatureSet': 'OSCONFIG_C'}]) as request, \
                patch.object(prerequisites, 'pause'):
            prerequisites.project_features('example-project', 100)
        name = 'projects/example-project/locations/global/projectFeatureSettings'
        self.assertEqual(request.call_args_list[2].args,
                         ('PATCH', 'https://osconfig.googleapis.com/v1/' + name +
                          '?updateMask=patchAndConfigFeatureSet',
                          {'name': name, 'patchAndConfigFeatureSet': 'OSCONFIG_C'}))

    def test_permanent_failure_is_not_retried(self):
        with patch.object(prerequisites, 'request', side_effect=prerequisites.ApiError(400)) as request:
            with self.assertRaises(prerequisites.ApiError):
                prerequisites.project_features('example-project', 100)
        self.assertEqual(request.call_count, 1)


class ViewTests(unittest.TestCase):
    view = 'projects/example-project/locations/global/buckets/_Default/views/example-heartbeats'
    policy = {'version': 3, 'etag': 'original', 'bindings': [{
        'role': 'roles/logging.viewAccessor', 'members': ['user:reader@example.test'],
        'condition': {'title': 'example', 'expression': 'true'}}]}

    def test_get_allowed_set_denied_waits_then_roundtrips_policy_unchanged(self):
        with patch.object(prerequisites, 'request', side_effect=[
                self.policy, prerequisites.ApiError(403), self.policy, self.policy]) as request, \
                patch.object(prerequisites, 'pause') as pause:
            prerequisites.view_permissions(self.view, 100)
        self.assertEqual(pause.call_count, 1)
        url = 'https://logging.googleapis.com/v2/' + self.view
        self.assertEqual([call.args for call in request.call_args_list], [
            ('POST', url + ':getIamPolicy', {'options': {'requestedPolicyVersion': 3}}),
            ('POST', url + ':setIamPolicy', {'policy': self.policy})] * 2)

    def test_conflict_rereads_and_keeps_concurrent_binding(self):
        for code in (409, 412):
            with self.subTest(code=code):
                fresh = {'version': 3, 'etag': 'fresh', 'bindings': self.policy['bindings'] + [{
                    'role': 'roles/logging.viewAccessor', 'members': ['user:second@example.test']}]}
                with patch.object(prerequisites, 'request', side_effect=[
                        self.policy, prerequisites.ApiError(code), fresh, fresh]) as request, \
                        patch.object(prerequisites, 'pause'):
                    prerequisites.view_permissions(self.view, 100)
                self.assertEqual(request.call_args_list[3].args[2], {'policy': fresh})

    def test_empty_policy_is_safe_but_missing_etag_never_writes(self):
        with patch.object(prerequisites, 'request', return_value={'etag': 'empty'}) as request:
            prerequisites.view_permissions(self.view, 100)
        self.assertEqual(request.call_args_list[1].args[2], {'policy': {'etag': 'empty'}})
        with patch.object(prerequisites, 'request', return_value={}) as request:
            with self.assertRaises(RuntimeError):
                prerequisites.view_permissions(self.view, 100)
        self.assertEqual(request.call_count, 1)

    def test_denied_set_times_out(self):
        with patch.object(prerequisites, 'request', side_effect=[self.policy, prerequisites.ApiError(403)]), \
                patch.object(prerequisites.time, 'monotonic', return_value=101):
            with self.assertRaises(TimeoutError):
                prerequisites.view_permissions(self.view, 100)

    def test_permanent_failure_is_not_retried(self):
        with patch.object(prerequisites, 'request', side_effect=[
                self.policy, prerequisites.ApiError(400)]) as request:
            with self.assertRaises(prerequisites.ApiError):
                prerequisites.view_permissions(self.view, 100)
        self.assertEqual(request.call_count, 2)


if __name__ == '__main__':
    unittest.main()
