import copy
import importlib.util
import pathlib
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "oslogin_2fa", pathlib.Path(__file__).with_name("oslogin-2fa.py"))
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

CONFIG = dict(project_id="example-project", zone="us-central1-a",
              instance_name="example-host", instance_id="12345", value="TRUE")


def instance(value=None):
    items = [{"key": "enable-oslogin", "value": "TRUE"},
             {"key": "startup-script", "value": "keep startup"},
             {"key": "unknown-writer", "value": "keep unknown"}]
    if value is not None:
        items.append({"key": "enable-oslogin-2fa", "value": value})
    return dict(id="12345", name="example-host",
                metadata=dict(fingerprint="first", items=items))


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.current = instance()
        self.posts = []
        self.conflict = False

    def request(self, method, url, body=None):
        if method == "GET":
            self.assertTrue(url.endswith("/instances/12345"))
            return copy.deepcopy(self.current)
        self.assertEqual(method, "POST")
        self.assertTrue(url.endswith("/instances/12345/setMetadata"))
        self.posts.append(copy.deepcopy(body))
        if self.conflict:
            self.conflict = False
            self.current["metadata"]["fingerprint"] = "concurrent"
            self.current["metadata"]["items"].append({"key": "concurrent", "value": "keep"})
            raise policy.ApiError(412)
        self.current["metadata"]["items"] = body["items"]
        return dict(name="operation-1", targetId="12345", status="DONE")

    def run_policy(self, config=CONFIG):
        with patch.object(policy, "request", side_effect=self.request), patch.object(policy, "pause"):
            policy.configure(config)

    def test_preserves_unknown_metadata_and_is_idempotent(self):
        before = copy.deepcopy(self.current["metadata"]["items"])
        self.run_policy()
        self.run_policy()
        self.assertEqual(len(self.posts), 1)
        for item in before:
            self.assertIn(item, self.posts[0]["items"])
        self.assertIn({"key": "enable-oslogin-2fa", "value": "TRUE"}, self.posts[0]["items"])

    def test_conflict_refetches_and_preserves_concurrent_key(self):
        self.conflict = True
        self.run_policy()
        self.assertEqual(len(self.posts), 2)
        self.assertEqual(self.posts[1]["fingerprint"], "concurrent")
        self.assertIn({"key": "concurrent", "value": "keep"}, self.posts[1]["items"])

    def test_rollback_sets_false_without_removing_other_policy(self):
        self.current = instance("TRUE")
        self.run_policy(dict(CONFIG, value="FALSE"))
        self.assertIn({"key": "enable-oslogin", "value": "TRUE"}, self.posts[0]["items"])
        self.assertIn({"key": "enable-oslogin-2fa", "value": "FALSE"}, self.posts[0]["items"])

    def test_identity_change_and_missing_fingerprint_fail_before_write(self):
        for field, value in [("id", "999"), ("name", "different")]:
            with self.subTest(field=field):
                self.current = instance()
                self.current[field] = value
                with self.assertRaisesRegex(RuntimeError, "identity changed"):
                    self.run_policy()
        self.current = instance()
        del self.current["metadata"]["fingerprint"]
        with self.assertRaisesRegex(RuntimeError, "fingerprint"):
            self.run_policy()
        self.assertEqual(self.posts, [])

    def test_disabled_oslogin_is_not_silently_enabled(self):
        self.current["metadata"]["items"][0]["value"] = "FALSE"
        with self.assertRaisesRegex(RuntimeError, "already be enabled"):
            self.run_policy()
        self.assertEqual(self.posts, [])

    def test_inherited_oslogin_is_pinned_without_other_changes(self):
        self.current["metadata"]["items"].pop(0)
        def inherited(method, url, body=None):
            if url.endswith("/projects/example-project"):
                return {"commonInstanceMetadata": {"items": [{"key": "enable-oslogin", "value": "TRUE"}]}}
            return self.request(method, url, body)
        with patch.object(policy, "request", side_effect=inherited), patch.object(policy, "pause"):
            policy.configure(CONFIG)
        self.assertIn({"key": "enable-oslogin", "value": "TRUE"}, self.posts[0]["items"])

    def test_api_failure_is_not_retried_or_reported_as_success(self):
        with patch.object(policy, "request", side_effect=policy.ApiError(403)) as request:
            with self.assertRaises(policy.ApiError):
                policy.configure(CONFIG)
        self.assertEqual(request.call_count, 1)

    def test_operation_errors_and_wrong_target_are_rejected(self):
        for operation in [dict(name="op-1", targetId="999", status="DONE"),
                          dict(name="op-1", targetId="12345", status="DONE", error={"errors": []})]:
            with self.subTest(operation=operation):
                with patch.object(policy, "request", side_effect=[instance(), operation]):
                    with self.assertRaisesRegex(RuntimeError, "operation"):
                        policy.configure(CONFIG)

    def test_operation_is_polled_and_metadata_reread(self):
        responses = [instance(), dict(name="op-1", targetId="12345", status="PENDING"),
                     dict(name="op-1", targetId="12345", status="DONE"), instance("TRUE")]
        with patch.object(policy, "request", side_effect=responses) as request, patch.object(policy, "pause"):
            policy.configure(CONFIG)
        self.assertTrue(request.call_args_list[2].args[1].endswith("/operations/op-1"))
        self.assertTrue(request.call_args_list[3].args[1].endswith("/instances/12345"))

    def test_invalid_input_never_calls_api(self):
        for config in [dict(CONFIG, instance_id="example-host"), dict(CONFIG, value="anything"),
                       dict(CONFIG, project_id="example/other")]:
            with patch.object(policy, "request") as request:
                with self.assertRaises(ValueError):
                    policy.configure(config)
                request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
