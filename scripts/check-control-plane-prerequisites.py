#!/usr/bin/env python3
"""Check rollout tooling as the deployment identity before changing Cloud Run."""

import argparse
import importlib.util
import json
from pathlib import Path
import sys
import time

SPEC = importlib.util.spec_from_file_location(
    "identity_verifier", Path(__file__).with_name("verify-control-plane-identity.py"),
)
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class Preflight:
    def __init__(self, evidence, attempts=6, retry_delay=10):
        self.evidence = evidence
        self.attempts = attempts
        self.retry_delay = retry_delay
        self.pending = []

    def check(self, name, operation):
        self.pending.append((name, operation, []))

    def run(self):
        # Retry failed probes together, so widespread IAM propagation does not
        # add a separate minute of waiting for every check.
        for attempt in range(self.attempts):
            retry = []
            for name, operation, history in self.pending:
                start = len(self.evidence.index)
                try:
                    operation()
                    passed, error = True, None
                except (VERIFY.VerificationError, ValueError, KeyError, TypeError, AttributeError, OSError) as exc:
                    passed, error = False, str(exc)
                history.append({
                    "status": "PASS" if passed else "FAIL", "error": error,
                    "commands": self.evidence.index[start:],
                })
                del self.evidence.index[start:]
                if passed or attempt + 1 == self.attempts:
                    self.evidence.index.append({
                        "name": name, "status": "PASS" if passed else "FAIL", "attempts": history,
                    })
                    print(f"{name}: {'PASS' if passed else 'FAIL'}")
                else:
                    retry.append((name, operation, history))
            self.pending = retry
            if not retry:
                break
            time.sleep(self.retry_delay)

    def command(self, name, argv, validate=lambda _: None):
        self.check(name, lambda: validate(self.evidence.command(name, argv)))


def require(condition, message):
    if not condition:
        raise VERIFY.VerificationError(message)


def contract_from_plan(plan):
    change = plan.get("output_changes", {}).get("controlplane_identity_contract", {})
    contract = change.get("after")
    fields = (
        "deployment_identity", "backup_bucket", "secret_ids", "region", "kms_key_resource",
    )
    unknown = change.get("after_unknown") or {}
    require(isinstance(contract, dict), "Plan has no control-plane identity contract")
    require(isinstance(unknown, dict), "Identity contract is not known until apply")
    for field in fields:
        require(field in contract and not unknown.get(field), f"Contract field {field} is unknown")
    for field in ("deployment_identity", "backup_bucket", "region"):
        require(isinstance(contract[field], str) and bool(contract[field]), f"Invalid contract field {field}")
    require(isinstance(contract["secret_ids"], list) and bool(contract["secret_ids"]) and
            all(isinstance(value, str) and value for value in contract["secret_ids"]), "Invalid secret_ids")
    return contract


def check_prerequisites(args, contract, preflight):
    evidence = preflight.evidence
    command = preflight.command
    # New runtime/host account emails may still be computed in the plan. Probe
    # tooling with the existing caller; the cutover verifier checks the actual
    # newly provisioned identities, grants, and isolation after apply.
    identity = contract["deployment_identity"]
    bucket = contract["backup_bucket"]
    require(contract["deployment_identity"] == args.deployment_identity, "Plan names a different deployment identity")
    require(contract["region"] == args.region, "Plan names a different region")
    require(identity.endswith(f"@{args.project}.iam.gserviceaccount.com"), "Plan names a different deployment project")
    (evidence.root / "contract.json").write_text(json.dumps(contract, indent=2) + "\n")

    command("deployment-identity", VERIFY.gcloud("auth", "list", "--filter=status:ACTIVE", "--format=value(account)"),
            lambda text: require(text.strip() == args.deployment_identity, "Preflight is not running as the deployment account"))
    command("verification-apis", VERIFY.gcloud("services", "list", "--enabled", f"--project={args.project}", "--format=value(config.name)"),
            lambda text: require({"cloudasset.googleapis.com", "policytroubleshooter.googleapis.com"} <= set(text.splitlines()), "Verification APIs are not enabled"))
    command("service-readiness", VERIFY.gcloud("run", "services", "describe", args.service, f"--project={args.project}", f"--region={args.region}", "--format=json"),
            lambda text: require(any(entry.get("percent") == 100 and entry.get("revisionName") for entry in json.loads(text).get("status", {}).get("traffic", [])), "No 100% rollback revision"))
    command("project-policy", VERIFY.gcloud("projects", "get-iam-policy", args.project, "--format=json"))
    for index, target in enumerate([bucket, *args.other_bucket], 1):
        command(f"bucket-policy-{index}", VERIFY.gcloud("storage", "buckets", "get-iam-policy", f"gs://{target}", "--format=json"))

    # These probes check whether tooling can reach a definite decision. Current
    # grants may change during the regional apply; the cutover verifier still
    # requires explicit denial for every isolation check afterwards.
    for name, target, obj, permission in VERIFY.storage_denial_checks(bucket, args.other_bucket, "templates/.permission-probe"):
        command(f"policy-visibility-{name.removesuffix('-denied')}", VERIFY.gcloud("policy-troubleshoot", "iam", VERIFY.storage_object_resource(target, obj),
                f"--project={args.project}", f"--principal-email={identity}", f"--permission={permission}", "--format=json"),
                lambda text: require(VERIFY.policy_troubleshooter_access(text) in {"GRANTED", "NOT_GRANTED", "DENIED"},
                    "Policy decision is unknown; inspect inherited policies, custom roles, and group visibility"))
    command("impersonation-analysis", VERIFY.host_effective_iam_command(args.project, identity, identity), VERIFY.iam_analysis_results)
    command("effective-iam", VERIFY.effective_iam_command(args.project, identity, bucket), VERIFY.iam_analysis_results)
    for index, secret in enumerate(contract["secret_ids"], 1):
        command(f"secret-version-{index}", VERIFY.gcloud("secrets", "versions", "describe", "latest", f"--secret={secret}", f"--project={args.project}", "--format=json"),
                lambda text: require(json.loads(text).get("state") == "ENABLED", "Latest secret version is not enabled"))
    if contract["kms_key_resource"]:
        command("kms-policy", VERIFY.gcloud("kms", "keys", "get-iam-policy", contract["kms_key_resource"], "--format=json"))
        command("kms-primary", VERIFY.gcloud("kms", "keys", "describe", contract["kms_key_resource"], "--format=json"),
                lambda text: require(json.loads(text).get("primary", {}).get("state") == "ENABLED", "KMS primary version is not enabled"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("cell", "project", "region", "service", "deployment-identity"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--plan-file", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--other-bucket", action="append", default=[])
    args = parser.parse_args()
    evidence = VERIFY.Evidence(args.evidence_dir)
    try:
        contract = contract_from_plan(json.loads(args.plan_file.read_text()))
        preflight = Preflight(evidence)
        check_prerequisites(args, contract, preflight)
        preflight.run()
        passed = bool(evidence.index) and all(check["status"] == "PASS" for check in evidence.index)
    except (VERIFY.VerificationError, ValueError, KeyError, TypeError, AttributeError, OSError) as exc:
        (evidence.root / "failure.txt").write_text(str(exc) + "\n")
        evidence.index.append({"name": "prerequisite-contract", "status": "FAIL"})
        passed = False
    evidence.write_index("PASS" if passed else "FAIL")
    if not passed:
        print("Rollout prerequisites failed; inspect private evidence before changing service identity or traffic.", file=sys.stderr)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
