"""Permission propagation must gate regional applies and fail closed."""
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import urllib.error

spec = importlib.util.spec_from_file_location(
    'wait_iam', Path(__file__).with_name('wait_credentials_key_iam.py'))
wait_iam = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wait_iam)


class PermissionWaitTest(unittest.TestCase):
    @patch.object(wait_iam.subprocess, 'check_output', return_value='example-token\n')
    def test_checks_exact_key_and_write_permission(self, token):
        response = io.BytesIO(json.dumps({'permissions': [wait_iam.PERMISSION]}).encode())
        with patch.object(wait_iam.urllib.request, 'urlopen', return_value=response) as request:
            self.assertTrue(wait_iam.has_permission('example-project'))
        sent = request.call_args.args[0]
        self.assertEqual(sent.full_url, 'https://cloudkms.googleapis.com/v1/projects/example-project/locations/us-central1/keyRings/superserve/cryptoKeys/credentials-kek:testIamPermissions')
        self.assertEqual(json.loads(sent.data), {'permissions': [wait_iam.PERMISSION]})
        self.assertEqual(sent.get_method(), 'POST')

    @patch.object(wait_iam.subprocess, 'check_output', return_value='example-token')
    def test_read_permission_does_not_satisfy_gate(self, token):
        response = io.BytesIO(b'{"permissions":["cloudkms.cryptoKeys.getIamPolicy"]}')
        with patch.object(wait_iam.urllib.request, 'urlopen', return_value=response):
            self.assertFalse(wait_iam.has_permission('example-project'))

    @patch.object(wait_iam.subprocess, 'check_output', return_value='example-token')
    def test_transient_denial_retries_but_bad_resource_fails(self, token):
        for status in (403, 429, 503, 404):
            error = urllib.error.HTTPError('example-url', status, 'example error', {}, None)
            with patch.object(wait_iam.urllib.request, 'urlopen', side_effect=error):
                if status == 404:
                    with self.assertRaises(RuntimeError):
                        wait_iam.has_permission('example-project')
                else:
                    self.assertFalse(wait_iam.has_permission('example-project'))

    @patch.object(wait_iam.subprocess, 'check_output', return_value='example-token')
    def test_transport_failure_retries_then_observes_permission(self, token):
        for failure in (urllib.error.URLError('DNS unavailable'), TimeoutError('timed out'), ConnectionResetError('reset')):
            with self.subTest(failure=type(failure).__name__):
                response = io.BytesIO(json.dumps({'permissions': [wait_iam.PERMISSION]}).encode())
                with patch.object(wait_iam.urllib.request, 'urlopen', side_effect=[failure, response]) as request, patch.object(wait_iam.time, 'sleep') as sleep:
                    wait_iam.wait_for_permission('example-project')
                self.assertEqual(request.call_count, 2)
                sleep.assert_called_once()

    def test_waits_until_permission_is_effective(self):
        with patch.object(wait_iam, 'has_permission', side_effect=[False, True]) as check, patch.object(wait_iam.time, 'sleep') as sleep:
            wait_iam.wait_for_permission('example-project')
        self.assertEqual(check.call_count, 2)
        sleep.assert_called_once()

    def test_timeout_blocks_deployment(self):
        with patch.object(wait_iam, 'has_permission', return_value=False), patch.object(wait_iam.time, 'monotonic', side_effect=[0, 601]), patch.object(wait_iam.time, 'sleep') as sleep:
            with self.assertRaises(TimeoutError):
                wait_iam.wait_for_permission('example-project')
        sleep.assert_not_called()


if __name__ == '__main__':
    unittest.main()
