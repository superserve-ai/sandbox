import argparse
import copy
import importlib.util
import json
import re
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "prerequisites", Path(__file__).with_name("check-control-plane-prerequisites.py"),
)
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)
ROOT = Path(__file__).resolve().parents[1]

CONTRACT = {
    "runtime_service_account": "reader@example-project.iam.gserviceaccount.com",
    "deployment_identity": "deployer@example-project.iam.gserviceaccount.com",
    "backup_bucket": "example-backups",
    "secret_ids": ["example-secret"],
    "host_identities_unchanged": ["host@example-project.iam.gserviceaccount.com"],
    "region": "example-region",
    "kms_key_resource": None,
}


class ContractTests(unittest.TestCase):
    def test_reads_planned_contract_without_requiring_prior_state_output(self):
        plan = {"output_changes": {"controlplane_identity_contract": {
            "before": None, "after": CONTRACT, "after_unknown": False,
        }}}
        self.assertEqual(CHECK.contract_from_plan(plan), CONTRACT)

    def test_unknown_or_missing_prerequisite_is_rejected_before_probes(self):
        for field in ("deployment_identity", "backup_bucket", "secret_ids", "region", "kms_key_resource"):
            with self.subTest(field=field):
                plan = {"output_changes": {"controlplane_identity_contract": {
                    "after": CONTRACT, "after_unknown": {field: True},
                }}}
                with self.assertRaises(CHECK.VERIFY.VerificationError):
                    CHECK.contract_from_plan(plan)
        for plan in ({}, {"output_changes": {"controlplane_identity_contract": {"after": CONTRACT, "after_unknown": True}}}):
            with self.assertRaises(CHECK.VERIFY.VerificationError):
                CHECK.contract_from_plan(plan)


class ProbeTests(unittest.TestCase):
    def test_collects_multiple_failures_and_still_runs_later_checks(self):
        with tempfile.TemporaryDirectory() as root:
            evidence = CHECK.VERIFY.Evidence(Path(root))
            preflight = CHECK.Preflight(evidence, attempts=1)
            seen = []
            def operation(name, success):
                seen.append(name)
                CHECK.require(success, "private details")
            for name, success in (("first", False), ("second", False), ("last", True)):
                preflight.check(name, lambda name=name, success=success: operation(name, success))
            preflight.run()
            self.assertEqual(seen, ["first", "second", "last"])
            self.assertEqual([c["status"] for c in evidence.index], ["FAIL", "FAIL", "PASS"])

    def test_retries_failed_probes_together_and_retains_attempt_evidence(self):
        with tempfile.TemporaryDirectory() as root, patch.object(CHECK.time, "sleep") as sleep:
            evidence = CHECK.VERIFY.Evidence(Path(root))
            preflight = CHECK.Preflight(evidence, attempts=3, retry_delay=10)
            counts = {"delayed": 0, "broken": 0, "ready": 0}
            def operation(name):
                counts[name] += 1
                CHECK.require(name == "ready" or (name == "delayed" and counts[name] > 1), "not propagated")
            for name in counts:
                preflight.check(name, lambda name=name: operation(name))
            preflight.run()
            self.assertEqual(counts, {"delayed": 2, "broken": 3, "ready": 1})
            self.assertEqual(sleep.call_count, 2)
            rows = {row["name"]: row for row in evidence.index}
            self.assertEqual(rows["delayed"]["status"], "PASS")
            self.assertEqual([x["status"] for x in rows["delayed"]["attempts"]], ["FAIL", "PASS"])
            self.assertEqual(rows["broken"]["status"], "FAIL")

    def run_cell(self, *, kms=False, failures=None, contract_override=None):
        calls = []
        failures = failures or {}
        contract = copy.deepcopy(CONTRACT if contract_override is None else contract_override)
        if kms:
            contract["kms_key_resource"] = "projects/example-project/locations/example-region/keyRings/example/cryptoKeys/example"
        args = argparse.Namespace(
            project="example-project", region="example-region", service="example-api",
            deployment_identity=CONTRACT["deployment_identity"], other_bucket=["example-east", "example-west"],
        )
        with tempfile.TemporaryDirectory() as root:
            evidence = CHECK.VERIFY.Evidence(Path(root))
            def command(name, argv):
                calls.append((name, argv))
                evidence.index.append({"name": name, "argv": argv, "status": "PASS"})
                if name in failures:
                    return failures[name]
                if name == "deployment-identity": return CONTRACT["deployment_identity"]
                if name == "verification-apis": return "cloudasset.googleapis.com\npolicytroubleshooter.googleapis.com\n"
                if name == "service-readiness": return '{"status":{"traffic":[{"percent":100,"revisionName":"old-revision"}]}}'
                if argv[1:3] == ["policy-troubleshoot", "iam"]: return '{"access":"NOT_GRANTED"}'
                if argv[1:3] == ["asset", "analyze-iam-policy"]: return '{"fullyExplored":true,"analysisResults":[]}'
                if name.startswith("secret-version-"): return '{"state":"ENABLED"}'
                if name == "kms-primary": return '{"primary":{"state":"ENABLED"}}'
                return '{}'
            evidence.command = command
            preflight = CHECK.Preflight(evidence, attempts=1)
            CHECK.check_prerequisites(args, contract, preflight)
            preflight.run()
            return calls, evidence.index

    def test_first_migration_probes_tooling_without_computed_runtime_or_host_emails(self):
        planned = copy.deepcopy(CONTRACT)
        del planned["runtime_service_account"]
        del planned["host_identities_unchanged"]
        contract = CHECK.contract_from_plan({"output_changes": {"controlplane_identity_contract": {
            "after": planned, "after_unknown": {"runtime_service_account": True, "host_identities_unchanged": [True]},
        }}})
        calls, checks = self.run_cell(contract_override=contract)
        self.assertTrue(all(row["status"] == "PASS" for row in checks))
        for _, argv in calls:
            if argv[1:3] == ["policy-troubleshoot", "iam"]:
                self.assertIn(f"--principal-email={CONTRACT['deployment_identity']}", argv)
            if "--analyze-service-account-impersonation" in argv:
                self.assertIn(f"--identity=serviceAccount:{CONTRACT['deployment_identity']}", argv)
                self.assertIn(f"--full-resource-name=//iam.googleapis.com/projects/example-project/serviceAccounts/{CONTRACT['deployment_identity']}", argv)

    def test_all_cells_probe_cross_project_policies_and_pending_runtime_grants_are_not_required(self):
        for kms in (False, True):
            with self.subTest(kms=kms):
                calls, checks = self.run_cell(kms=kms)
                self.assertTrue(all(row["status"] == "PASS" for row in checks))
                argv = [cmd for _, cmd in calls]
                self.assertTrue(any("--expand-groups" in cmd and "--analyze-service-account-impersonation" in cmd for cmd in argv))
                self.assertEqual(sum(cmd[1:4] == ["storage", "buckets", "get-iam-policy"] for cmd in argv), 3)
                self.assertEqual(sum(cmd[1:3] == ["policy-troubleshoot", "iam"] for cmd in argv), 26)
                self.assertFalse(any("--impersonate-service-account" in word for cmd in argv for word in cmd))
                self.assertFalse(any(word in {"apply", "update-traffic", "update", "delete", "create", "access"} for cmd in argv for word in cmd))
                self.assertFalse(any(cmd[1:3] in (["storage", "cat"], ["storage", "objects"]) for cmd in argv))
                self.assertEqual(any(name == "kms-primary" for name, _ in calls), kms)

    def test_unknown_policies_incomplete_analysis_and_disabled_secrets_all_fail(self):
        calls, checks = self.run_cell(failures={
            "policy-visibility-sandbox-get-permission-check": '{"access":"UNKNOWN_INFO"}',
            "effective-iam": '{"fullyExplored":false}',
            "secret-version-1": '{"state":"DISABLED"}',
        })
        failures = {row["name"] for row in checks if row["status"] == "FAIL"}
        self.assertEqual(failures, {"policy-visibility-sandbox-get-permission-check", "effective-iam", "secret-version-1"})
        self.assertTrue(any(name == "secret-version-1" for name, _ in calls))

    def test_current_grants_are_allowed_only_by_preflight_not_cutover_verifier(self):
        _, checks = self.run_cell(failures={"policy-visibility-sandbox-get-permission-check": '{"access":"GRANTED"}'})
        self.assertTrue(all(row["status"] == "PASS" for row in checks))
        # The existing cutover suite separately rejects GRANTED for this probe.

    def test_disabled_kms_primary_is_rejected(self):
        _, checks = self.run_cell(kms=True, failures={"kms-primary": '{"primary":{"state":"DISABLED"}}'})
        self.assertEqual({row["name"] for row in checks if row["status"] == "FAIL"}, {"kms-primary"})


class WorkflowTests(unittest.TestCase):
    def test_branch_rollout_requires_explicit_manual_branch_confirmation(self):
        workflow = (ROOT / '.github/workflows/control-plane-identity-rollout.yml').read_text()
        for job in ('bootstrap', 'staging'):
            block = workflow.split(f'  {job}:\n', 1)[1].split('    runs-on:', 1)[0]
            condition = re.search(r"^    if: \$\{\{ (.+) \}\}$", block, re.MULTILINE).group(1)
            for event in ('workflow_dispatch', 'push', 'pull_request'):
                for ref, ref_type in (('refs/heads/main', 'branch'), ('refs/heads/example-fix', 'branch'), ('refs/tags/example', 'tag')):
                    for confirmation in ('', 'apply', 'apply-branch'):
                        with self.subTest(job=job, event=event, ref=ref, confirmation=confirmation):
                            context = {
                                'github': SimpleNamespace(event_name=event, ref=ref, ref_type=ref_type),
                                'inputs': SimpleNamespace(confirm=confirmation),
                            }
                            allowed = eval(condition.replace('&&', ' and ').replace('||', ' or '),
                                           {'__builtins__': {}}, context)
                            expected = event == 'workflow_dispatch' and ref_type == 'branch' and (
                                (ref == 'refs/heads/main' and confirmation == 'apply') or
                                (ref != 'refs/heads/main' and confirmation == 'apply-branch'))
                            self.assertEqual(allowed, expected)

    def test_all_environment_preflights_gate_the_serial_rollout(self):
        workflow = (ROOT / '.github/workflows/control-plane-identity-rollout.yml').read_text()
        bootstrap = workflow.split('  bootstrap:\n')[1].split('\n  prerequisites:')[0]
        preflight = workflow.split('  prerequisites:\n')[1].split('\n  staging:')[0]
        staging = workflow.split('  staging:\n')[1].split('\n  production-use4:')[0]
        self.assertIn('fail-fast: false', bootstrap)
        self.assertIn('fail-fast: false', preflight)
        self.assertIn('needs: [bootstrap]', preflight)
        self.assertIn('needs: [prerequisites]', staging)
        for cell in ('staging', 'production-use4', 'production-usw2'):
            self.assertIn(f'- cell: {cell}\n', preflight)
        self.assertNotIn('terraform apply', preflight)
        self.assertNotIn('update-traffic', preflight)
        self.assertIn('needs: [staging]', workflow)
        self.assertIn('needs: [production-use4]', workflow)
        self.assertIn('scripts/sanitize-control-plane-evidence.py', preflight)
        self.assertNotIn('control-plane-policy-visibility', workflow)
        key = bootstrap.split('verification_kms_key: ', 1)[1].splitlines()[0]
        for job in ('production-use4', 'production-usw2'):
            block = workflow.split(f'  {job}:\n', 1)[1].split('\n  production-', 1)[0]
            self.assertIn(f'TF_VAR_verification_kms_key: {key}', block)
        self.assertIn('TF_VAR_verification_kms_key: ${{ matrix.verification_kms_key }}', bootstrap)


if __name__ == '__main__':
    unittest.main()
