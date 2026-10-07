"""A partial IAM grant or an unready API must not release policy creation."""
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import urllib.error

spec = importlib.util.spec_from_file_location(
    'host_iam', Path(__file__).with_name('wait_host_logging_iam.py'))
host_iam = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host_iam)


def response(value):
    return io.BytesIO(json.dumps(value).encode())


class HostLoggingPermissionTest(unittest.TestCase):
    @patch.object(host_iam.subprocess, 'check_output', return_value='example-token')
    def test_requires_full_lifecycle_before_querying_each_zone(self, token):
        with patch.object(host_iam.urllib.request, 'urlopen', side_effect=[
            response({'permissions': host_iam.PERMISSIONS}), response({}), response({}),
        ]) as send:
            self.assertTrue(host_iam.ready('example-project', ['example-zone-a', 'example-zone-b']))
        requests = [call.args[0] for call in send.call_args_list]
        self.assertEqual(json.loads(requests[0].data)['permissions'], host_iam.PERMISSIONS)
        self.assertEqual(requests[0].full_url, 'https://cloudresourcemanager.googleapis.com/v1/projects/example-project:testIamPermissions')
        for request, zone in zip(requests[1:], ['example-zone-a', 'example-zone-b']):
            self.assertEqual(request.get_method(), 'GET')
            self.assertEqual(request.full_url, f'https://osconfig.googleapis.com/v1/projects/example-project/locations/{zone}/osPolicyAssignments?pageSize=1')

    @patch.object(host_iam.subprocess, 'check_output', return_value='example-token')
    def test_each_missing_lifecycle_permission_blocks_creation(self, token):
        for missing in host_iam.PERMISSIONS:
            with self.subTest(missing=missing), patch.object(host_iam.urllib.request, 'urlopen',
                return_value=response({'permissions': [p for p in host_iam.PERMISSIONS if p != missing]})) as send:
                self.assertFalse(host_iam.ready('example-project', ['example-zone']))
                self.assertEqual(send.call_count, 1)

    @patch.object(host_iam.subprocess, 'check_output', return_value='example-token')
    def test_granted_iam_does_not_bypass_api_readiness(self, token):
        for status in (403, 429, 503, 404):
            failure = urllib.error.HTTPError('example-url', status, 'example error', {}, None)
            with self.subTest(status=status), patch.object(host_iam.urllib.request, 'urlopen',
                side_effect=[response({'permissions': host_iam.PERMISSIONS}), failure]):
                if status == 404:
                    with self.assertRaises(RuntimeError):
                        host_iam.ready('example-project', ['example-zone'])
                else:
                    self.assertFalse(host_iam.ready('example-project', ['example-zone']))

    def test_eventual_propagation_and_timeout(self):
        with patch.object(host_iam, 'ready', side_effect=[False, True]) as check, patch.object(host_iam.time, 'sleep') as sleep:
            host_iam.wait_for_permissions('example-project', ['example-zone'])
        self.assertEqual(check.call_count, 2)
        sleep.assert_called_once()
        with patch.object(host_iam, 'ready', return_value=False), patch.object(host_iam.time, 'monotonic', side_effect=[0, 601]), patch.object(host_iam.time, 'sleep') as sleep:
            with self.assertRaises(TimeoutError):
                host_iam.wait_for_permissions('example-project', ['example-zone'])
            sleep.assert_not_called()


if __name__ == '__main__':
    unittest.main()
