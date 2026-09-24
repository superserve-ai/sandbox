#!/usr/bin/env python3
"""Verify and persist the control-plane identity rollout contract.

This is an operator-time check.  It deliberately runs outside Cloud Run's
startup path and writes command output to a private evidence directory rather
than printing policies or object contents to CI logs.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import posixpath
import re
import subprocess
import sys
from pathlib import Path


PERMISSION_DENIED = re.compile(
    r"permission.?denied|permission_denied|forbidden|403|not authorized|"
    r"does not have storage\.",
    re.IGNORECASE,
)
OBJECT_URI = re.compile(r"gs://[^\"'\s,]+|(?:templates|bases)/[A-Za-z0-9_./-]+")
TEMPLATE_MANIFEST = re.compile(
    r"templates/[^/]+/[^/]+/[^/]+/manifest\.json"
)


class VerificationError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cell", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--service", required=True)
    parser.add_argument("--contract-file", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--previous-revision")
    parser.add_argument("--candidate-revision")
    parser.add_argument("--allow-pending-traffic", action="store_true")
    parser.add_argument("--route-traffic", action="store_true")
    parser.add_argument("--other-bucket", action="append", default=[])
    parser.add_argument("--manifest-object")
    parser.add_argument("--referenced-object", action="append", default=[])
    args = parser.parse_args()
    if args.route_traffic and not args.candidate_revision:
        parser.error("--route-traffic requires --candidate-revision")
    return args


class Evidence:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "commands").mkdir(exist_ok=True)
        self.index: list[dict[str, object]] = []
        self.sequence = 0

    def command(
        self,
        name: str,
        argv: list[str],
        *,
        expect_denied: bool = False,
        redact_stdout: bool = False,
        stream_stdout: bool = False,
        env: dict[str, str] | None = None,
    ) -> str:
        self.sequence += 1
        stem = f"{self.sequence:02d}-{name}"
        if stream_stdout:
            # Artifact probes can return arbitrarily large, non-UTF-8 bodies.
            # Send those bytes directly to the OS sink instead of asking
            # subprocess to decode or buffer them in memory.
            result = subprocess.run(
                argv,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                env=env,
            )
            stdout = "<redacted>\n" if redact_stdout else "<binary stdout streamed>\n"
            observed_stdout = ""
            raw_stderr = result.stderr or b""
            stderr = (
                raw_stderr.decode("utf-8", errors="replace")
                if isinstance(raw_stderr, bytes)
                else str(raw_stderr)
            )
        else:
            result = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
            stdout = "<redacted>\n" if redact_stdout else result.stdout
            observed_stdout = result.stdout
            stderr = result.stderr
        (self.root / "commands" / f"{stem}.stdout").write_text(stdout)
        (self.root / "commands" / f"{stem}.stderr").write_text(stderr)
        observed = observed_stdout + stderr
        denied = bool(PERMISSION_DENIED.search(observed))
        passed = (result.returncode != 0 and denied) if expect_denied else result.returncode == 0
        self.index.append(
            {
                "name": name,
                "argv": argv,
                "returncode": result.returncode,
                "expected_permission_denial": expect_denied,
                "stdout_redacted": redact_stdout,
                "stdout_streamed": stream_stdout,
                "permission_denied_observed": denied,
                "status": "PASS" if passed else "FAIL",
            }
        )
        if not passed:
            expectation = "permission denial" if expect_denied else "success"
            raise VerificationError(
                f"{name}: expected {expectation}, got exit {result.returncode}; "
                f"see {self.root / 'commands' / f'{stem}.stderr'}"
            )
        return observed_stdout

    def write_index(self, status: str) -> None:
        (self.root / "evidence.json").write_text(
            json.dumps(
                {
                    "status": status,
                    "observed_at": dt.datetime.now(dt.UTC).isoformat(),
                    "checks": self.index,
                },
                indent=2,
            )
            + "\n"
        )

    def require_passes(self, names: list[str]) -> None:
        """Fail closed if a rollout omitted one of the required evidence rows."""
        passed = {
            str(check["name"])
            for check in self.index
            if check.get("status") == "PASS"
        }
        missing = sorted(name for name in names if name not in passed)
        if missing:
            raise VerificationError(
                "rollout evidence is incomplete; missing PASS checks: "
                + ", ".join(missing)
            )


def gcloud(*args: str) -> list[str]:
    return ["gcloud", *args]


def effective_iam_command(project: str, identity: str, bucket: str) -> list[str]:
    """Build the project-scoped effective IAM analysis command."""
    return gcloud(
        "asset",
        "analyze-iam-policy",
        f"--project={project}",
        f"--identity=serviceAccount:{identity}",
        f"--full-resource-name=//storage.googleapis.com/projects/_/buckets/{bucket}",
        "--format=json",
    )


def iam_analysis_results(response: str) -> list[object]:
    """Accept results only when the entire IAM analysis was fully explored."""
    try:
        value = json.loads(response)
    except json.JSONDecodeError as exc:
        raise VerificationError("effective IAM analysis returned invalid JSON") from exc

    def results(analysis: object) -> list[object]:
        if not isinstance(analysis, dict) or analysis.get("fullyExplored") is not True:
            raise VerificationError("effective IAM analysis was incomplete")
        if analysis.get("nonCriticalErrors", []) != []:
            raise VerificationError("effective IAM analysis reported errors")
        # Protobuf JSON omits empty repeated fields, including analysisResults.
        entries = analysis.get("analysisResults", [])
        if not isinstance(entries, list):
            raise VerificationError("effective IAM analysis had invalid results")
        return entries

    direct = results(value)
    if "mainAnalysis" not in value:
        if "serviceAccountImpersonationAnalysis" in value:
            raise VerificationError("effective IAM analysis had no main analysis")
        return direct
    impersonation = value.get("serviceAccountImpersonationAnalysis", [])
    if not isinstance(impersonation, list):
        raise VerificationError("effective IAM analysis had invalid impersonation results")
    combined = direct + results(value["mainAnalysis"])
    for analysis in impersonation:
        combined.extend(results(analysis))
    return combined


def storage_list_command(bucket: str, prefix: str, identity: str) -> list[str]:
    # A bare prefix can return only that prefix, not its descendant objects.
    return gcloud(
        "storage", "objects", "list", f"gs://{bucket}/{prefix}**",
        f"--impersonate-service-account={identity}", "--format=value(name)",
    )


def storage_denial_checks(
    bucket: str, other_buckets: list[str], manifest: str,
) -> list[tuple[str, str, str, str]]:
    """Describe non-mutating object permission probes for every storage prefix."""
    checks = [
        ("sandbox-get-permission-check", bucket, "sandboxes/.permission-probe", "storage.objects.get"),
        ("delete-permission-check", bucket, manifest, "storage.objects.delete"),
    ]
    for prefix in ("templates", "bases", "sandboxes"):
        for operation in ("create", "delete"):
            checks.append((
                f"own-{prefix}-{operation}-denied", bucket,
                f"{prefix}/.permission-probe", f"storage.objects.{operation}",
            ))
        for index, other in enumerate(other_buckets, 1):
            for operation in ("get", "create", "delete"):
                checks.append((
                    f"cross-cell-{index}-{prefix}-{operation}-denied", other,
                    f"{prefix}/.permission-probe", f"storage.objects.{operation}",
                ))
    return checks


def contract(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot read Terraform identity contract: {path}") from exc
    if not isinstance(value, dict):
        raise VerificationError("identity contract must be a JSON object")
    required = {
        "runtime_service_account",
        "legacy_runtime_account",
        "deployment_identity",
        "backup_bucket",
        "backup_object_prefix",
        "backup_object_prefixes",
        "backup_permissions",
        "secret_ids",
        "host_identities_unchanged",
    }
    missing = sorted(required - value.keys())
    if missing:
        raise VerificationError(f"identity contract is missing: {', '.join(missing)}")
    if sorted(value["backup_permissions"]) != ["storage.objects.get", "storage.objects.list"]:
        raise VerificationError("identity contract grants more than storage get/list")
    prefixes = value["backup_object_prefixes"]
    if (
        not isinstance(prefixes, list)
        or any(not isinstance(prefix, str) for prefix in prefixes)
        or sorted(prefixes) != ["bases/", "templates/"]
    ):
        raise VerificationError(
            "identity contract must restrict backup reads to the bases/ and templates/ prefixes"
        )
    if value["backup_object_prefix"] != "templates/":
        raise VerificationError("identity contract must retain templates/ as the manifest prefix")
    return value


def object_name(uri: str, bucket: str, generation_prefix: str | None = None) -> str:
    if uri.startswith("gs://"):
        prefix = f"gs://{bucket}/"
        if not uri.startswith(prefix):
            raise VerificationError(f"referenced object is outside the cell bucket: {uri}")
        return uri[len(prefix) :]
    # Shared objects are deliberately bucket-relative: the uploader stores
    # them under bases/ so generations can reuse one immutable object.
    if uri.startswith(("bases/", "templates/", "sandboxes/")):
        return uri
    if generation_prefix is None:
        return uri
    if uri.startswith("/"):
        raise VerificationError(f"referenced object escapes its generation: {uri}")
    resolved = posixpath.normpath(posixpath.join(generation_prefix, uri))
    if resolved != generation_prefix and not resolved.startswith(generation_prefix + "/"):
        raise VerificationError(f"referenced object escapes its generation: {uri}")
    return resolved


def manifest_references(manifest_text: str) -> list[str]:
    """Return every bucket object named by a generation manifest.

    Walk the decoded document instead of assuming a particular field ordering
    or stopping after the first artifact; the verifier must prove access to
    the complete published set. Ordinary uploader entries are relative to the
    manifest generation, while shared bases/ entries are bucket-relative.
    """
    try:
        value = json.loads(manifest_text)
    except json.JSONDecodeError as exc:
        raise VerificationError("template manifest is not valid JSON") from exc

    references: list[str] = []

    def visit(node: object) -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                if key == "object" and isinstance(child, str):
                    references.append(child)
                else:
                    visit(child)
        elif isinstance(node, list):
            for child in node:
                visit(child)

    visit(value)
    # Keep compatibility with an operator-supplied manifest format that
    # embeds object URIs as strings rather than files[*].object fields.
    references.extend(OBJECT_URI.findall(manifest_text))
    return references


def kms_key_parts(resource: str) -> tuple[str, str, str, str]:
    match = re.fullmatch(
        r"projects/([^/]+)/locations/([^/]+)/keyRings/([^/]+)/cryptoKeys/([^/]+)",
        resource,
    )
    if not match:
        raise VerificationError(f"invalid KMS crypto-key resource: {resource}")
    return match.groups()


def storage_object_resource(bucket: str, name: str) -> str:
    """Return the IAM resource name for one Cloud Storage object."""
    return f"//storage.googleapis.com/projects/_/buckets/{bucket}/objects/{name}"


def require_permission_denied(
    evidence: Evidence,
    name: str,
    identity: str,
    bucket: str,
    object_name: str,
    permission: str,
) -> None:
    """Fail closed unless Policy Troubleshooter denies one object permission."""
    resource = storage_object_resource(bucket, object_name)
    response = evidence.command(
        name,
        gcloud(
            "policy-troubleshoot",
            "iam",
            resource,
            f"--principal-email={identity}",
            f"--permission={permission}",
            "--format=json",
        ),
    )
    try:
        access = policy_troubleshooter_access(response)
    except VerificationError:
        evidence.index[-1]["status"] = "FAIL"
        raise
    evidence.index[-1].update(
        {
            "principal": identity,
            "resource": resource,
            "permission": permission,
            "access": access,
        }
    )
    # The v2alpha1 CLI reports a denied permission as NOT_GRANTED; accept
    # DENIED as well for older Policy Troubleshooter response versions.
    if access not in {"NOT_GRANTED", "DENIED"}:
        evidence.index[-1]["status"] = "FAIL"
        raise VerificationError(
            f"runtime identity has {permission} on {resource} ({access})"
        )


def policy_troubleshooter_access(response: str) -> str:
    """Extract the access decision from a Policy Troubleshooter response."""
    try:
        value = json.loads(response)
    except json.JSONDecodeError as exc:
        raise VerificationError("IAM Policy Troubleshooter returned invalid JSON") from exc
    if not isinstance(value, dict) or not isinstance(value.get("access"), str):
        raise VerificationError("IAM Policy Troubleshooter response has no access decision")
    return str(value["access"])


def runtime_identity(resource: dict[str, object]) -> str | None:
    spec = resource.get("spec", {})
    if not isinstance(spec, dict):
        return None
    template = spec.get("template", {})
    if isinstance(template, dict):
        nested = template.get("spec", {})
        if isinstance(nested, dict) and nested.get("serviceAccountName"):
            return str(nested["serviceAccountName"])
        if template.get("serviceAccount"):
            return str(template["serviceAccount"])
        if template.get("serviceAccountName"):
            return str(template["serviceAccountName"])
    if spec.get("serviceAccountName"):
        return str(spec["serviceAccountName"])
    return None


def main() -> int:
    args = parse_args()
    os.umask(0o077)
    evidence = Evidence(args.evidence_dir)
    try:
        cp = contract(args.contract_file)
        if not args.other_bucket:
            raise VerificationError("at least one --other-bucket is required for the isolation gate")
        identity = str(cp["runtime_service_account"])
        bucket = str(cp["backup_bucket"])
        object_prefix = str(cp["backup_object_prefix"])
        object_prefixes = [str(prefix) for prefix in cp["backup_object_prefixes"]]
        legacy = str(cp["legacy_runtime_account"])
        raw_hosts = cp["host_identities_unchanged"]
        if not isinstance(raw_hosts, list) or not all(
            isinstance(value, str) and value for value in raw_hosts
        ):
            raise VerificationError("identity contract must publish a non-empty host identity list")
        host_identities = [str(value) for value in raw_hosts]
        if not host_identities:
            raise VerificationError("identity contract must publish unchanged host identities")
        # Production keeps the legacy control-plane account for rollback, but
        # it is not a VMD host identity and therefore does not belong here.
        impersonate = f"--impersonate-service-account={identity}"

        metadata = {
            "cell": args.cell,
            "project": args.project,
            "region": args.region,
            "service": args.service,
            "runtime_service_account": identity,
            "legacy_runtime_account": legacy,
            "backup_bucket": bucket,
            "backup_object_prefix": cp["backup_object_prefix"],
            "backup_object_prefixes": object_prefixes,
            "deployment_identity": cp["deployment_identity"],
            "backup_permissions": cp["backup_permissions"],
            "secret_ids": cp["secret_ids"],
            "host_identities_unchanged": host_identities,
            "kms_key_resource": cp.get("kms_key_resource"),
            "kms_grant_principal": cp.get("kms_grant_principal"),
            "kms_grant_role": cp.get("kms_grant_role"),
            "kms_verification": cp.get("kms_verification"),
            "kms_grant_evidence": cp.get("kms_grant_evidence"),
        }
        (args.evidence_dir / "contract.json").write_text(json.dumps(metadata, indent=2) + "\n")

        service_json = evidence.command(
            "service",
            gcloud(
                "run",
                "services",
                "describe",
                args.service,
                f"--region={args.region}",
                f"--project={args.project}",
                "--format=json",
            ),
        )
        service = json.loads(service_json)
        actual_identity = runtime_identity(service)
        if actual_identity != identity:
            raise VerificationError(
                f"Cloud Run service uses {actual_identity!r}, expected {identity!r}"
            )
        # A zero-traffic candidate can be retired while latestReadyRevisionName
        # still names the previous serving revision. Pin verification to the
        # revision captured after apply, and use that same name for cutover.
        candidate = args.candidate_revision or service.get("status", {}).get("latestReadyRevisionName")
        traffic = service.get("status", {}).get("traffic", [])
        serving = sum(
            int(entry.get("percent", 0))
            for entry in traffic
            if entry.get("revisionName") == candidate
        )
        if not candidate or (serving != 100 and not args.allow_pending_traffic):
            raise VerificationError(f"candidate revision {candidate!r} has {serving}% traffic")
        if args.candidate_revision and service.get("status", {}).get("latestCreatedRevisionName") != candidate:
            raise VerificationError("service changed since candidate revision was captured")
        (args.evidence_dir / "revision-traffic.json").write_text(
            json.dumps(
                {
                    "candidate_revision": candidate,
                    "runtime_service_account": actual_identity,
                    "traffic": traffic,
                },
                indent=2,
            ) + "\n"
        )
        candidate_json = evidence.command(
            "candidate-revision",
            gcloud(
                "run", "revisions", "describe", candidate,
                f"--region={args.region}", f"--project={args.project}", "--format=json",
            ),
        )
        candidate_revision = json.loads(candidate_json)
        metadata = candidate_revision.get("metadata", {})
        if (
            metadata.get("name") != candidate
            or metadata.get("labels", {}).get("serving.knative.dev/service") != args.service
        ):
            raise VerificationError("candidate revision does not belong to the requested service")
        if runtime_identity(candidate_revision) != identity:
            raise VerificationError("candidate revision does not use the expected runtime identity")
        if not any(
            condition.get("type") == "Ready" and condition.get("status") == "True"
            for condition in candidate_revision.get("status", {}).get("conditions", [])
        ):
            raise VerificationError("candidate revision is not ready")
        previous_identity = None
        if args.previous_revision:
            previous_json = evidence.command(
                "previous-revision",
                gcloud(
                    "run",
                    "revisions",
                    "describe",
                    args.previous_revision,
                    f"--region={args.region}",
                    f"--project={args.project}",
                    "--format=json",
                ),
            )
            previous = json.loads(previous_json)
            previous_identity = runtime_identity(previous)
            (args.evidence_dir / "previous-revision.json").write_text(previous_json)

        listed = evidence.command(
            "own-template-list",
            storage_list_command(bucket, object_prefix, identity),
        )
        objects = [line.strip() for line in listed.splitlines() if line.strip()]
        manifest = args.manifest_object or next(
            (name for name in objects if TEMPLATE_MANIFEST.fullmatch(name)),
            None,
        )
        if not manifest:
            raise VerificationError("no template manifest found; pass --manifest-object")
        manifest = object_name(manifest, bucket)
        if not TEMPLATE_MANIFEST.fullmatch(manifest):
            raise VerificationError(
                "manifest object must be templates/<template>/<build>/<generation>/manifest.json"
            )
        manifest_text = evidence.command(
            "manifest-read",
            gcloud("storage", "cat", f"gs://{bucket}/{manifest}", impersonate),
        )
        (args.evidence_dir / "manifest.json").write_text(manifest_text)

        generation_prefix = manifest.rsplit("/", 1)[0]
        references = list(args.referenced_object) + manifest_references(manifest_text)
        references = list(
            dict.fromkeys(
                name
                for name in (
                    object_name(ref.strip().rstrip("}]"), bucket, generation_prefix)
                    for ref in references
                )
                if name != manifest
            )
        )
        if not references:
            raise VerificationError("manifest has no discoverable referenced objects; pass --referenced-object")
        (args.evidence_dir / "referenced-objects.txt").write_text("\n".join(references) + "\n")
        for index, name in enumerate(references, 1):
            evidence.command(
                f"referenced-read-{index}",
                gcloud("storage", "cat", f"gs://{bucket}/{name}", impersonate),
                redact_stdout=True,
                stream_stdout=True,
            )

        denied_list_checks = []
        for index, other in enumerate(args.other_bucket, 1):
            # A bucket-root denial alone does not rule out a managed-folder grant.
            for prefix in ("", "templates/", "bases/", "sandboxes/"):
                name = f"cross-cell-{index}-{prefix.rstrip('/') or 'root'}-list-denied"
                denied_list_checks.append(name)
                evidence.command(
                    name, storage_list_command(other, prefix, identity),
                    expect_denied=True,
                )
        evidence.command(
            "sandbox-list-denied",
            storage_list_command(bucket, "sandboxes/", identity),
            expect_denied=True,
        )
        # Evaluate get/create/delete without touching live objects. An actual
        # mutation could destroy data or turn a retried create into an overwrite.
        denial_checks = storage_denial_checks(bucket, args.other_bucket, manifest)
        for name, target_bucket, target_object, permission in denial_checks:
            require_permission_denied(
                evidence, name, identity, target_bucket, target_object, permission,
            )

        bucket_policy_json = evidence.command(
            "bucket-iam",
            gcloud("storage", "buckets", "get-iam-policy", f"gs://{bucket}", "--format=json"),
        )
        bucket_policy = json.loads(bucket_policy_json)
        reader_member = f"serviceAccount:{identity}"
        reader_roles = {
            binding.get("role")
            for binding in bucket_policy.get("bindings", [])
            if reader_member in binding.get("members", [])
        }
        if reader_roles:
            raise VerificationError(
                "runtime identity must not receive a bucket-level backup grant: "
                f"{sorted(reader_roles)}"
            )
        for index, prefix in enumerate(object_prefixes, 1):
            managed_folder_policy_json = evidence.command(
                f"managed-folder-iam-{index}",
                gcloud(
                    "storage",
                    "managed-folders",
                    "get-iam-policy",
                    f"gs://{bucket}/{prefix}",
                    "--format=json",
                ),
            )
            managed_folder_policy = json.loads(managed_folder_policy_json)
            if not any(
                binding.get("role") == "roles/storage.objectViewer"
                and reader_member in binding.get("members", [])
                for binding in managed_folder_policy.get("bindings", [])
            ):
                raise VerificationError(
                    f"managed folder {prefix} has no objectViewer grant for {identity}"
                )
        evidence.command(
            "project-iam",
            gcloud("projects", "get-iam-policy", args.project, "--format=json"),
        )
        sa_policy_json = evidence.command(
            "service-account-iam",
            gcloud("iam", "service-accounts", "get-iam-policy", identity, "--format=json"),
        )
        sa_policy = json.loads(sa_policy_json)
        deploy_member = f"serviceAccount:{cp['deployment_identity']}"
        if not any(
            binding.get("role") == "roles/iam.serviceAccountUser"
            and deploy_member in binding.get("members", [])
            for binding in sa_policy.get("bindings", [])
        ):
            raise VerificationError(
                f"deployment identity {deploy_member} lacks scoped act-as on {identity}"
            )
        if not any(
            binding.get("role") == "roles/iam.serviceAccountTokenCreator"
            and deploy_member in binding.get("members", [])
            for binding in sa_policy.get("bindings", [])
        ):
            raise VerificationError(
                f"deployment identity {deploy_member} lacks scoped token creation on {identity}"
            )

        # Host identities must not gain a new path to impersonate the serving
        # reader.  Analyze effective IAM for each unchanged host principal so
        # project/folder inheritance, group membership, and service-account
        # impersonation paths are included. Their existing bucket grants are
        # intentionally left untouched for host behavior.
        impersonation_permissions = (
            "iam.serviceAccounts.actAs,"
            "iam.serviceAccounts.getAccessToken,"
            "iam.serviceAccounts.getOpenIdToken"
        )
        serving_resource = (
            f"//iam.googleapis.com/projects/{args.project}/"
            f"serviceAccounts/{identity}"
        )
        for index, host in enumerate(host_identities, 1):
            host_effective_json = evidence.command(
                f"host-effective-iam-{index}",
                gcloud(
                    "asset",
                    "analyze-iam-policy",
                    f"--project={args.project}",
                    f"--identity=serviceAccount:{host}",
                    f"--full-resource-name={serving_resource}",
                    f"--permissions={impersonation_permissions}",
                    "--analyze-service-account-impersonation",
                    "--expand-groups",
                    "--expand-resources",
                    "--expand-roles",
                    "--output-group-edges",
                    "--output-resource-edges",
                    "--format=json",
                ),
            )
            evidence.index[-1].update(
                {
                    "principal": host,
                    "target": identity,
                    "permissions_checked": impersonation_permissions.split(","),
                }
            )
            try:
                analysis_results = iam_analysis_results(host_effective_json)
            except VerificationError as exc:
                evidence.index[-1]["status"] = "FAIL"
                raise VerificationError(f"unchanged host identity {host}: {exc}") from exc
            if analysis_results:
                evidence.index[-1]["status"] = "FAIL"
                raise VerificationError(
                    f"unchanged host identity {host} can impersonate serving identity {identity}"
                )
        runtime_effective_json = evidence.command(
            "effective-iam",
            effective_iam_command(args.project, identity, bucket),
        )
        try:
            # Intended reader grants are valid; incomplete analysis is not.
            iam_analysis_results(runtime_effective_json)
        except VerificationError as exc:
            evidence.index[-1]["status"] = "FAIL"
            raise VerificationError(f"runtime identity {identity}: {exc}") from exc
        for index, secret in enumerate(cp["secret_ids"], 1):
            evidence.command(
                f"secret-access-{index}",
                gcloud(
                    "secrets",
                    "versions",
                    "access",
                    "latest",
                    f"--secret={secret}",
                    f"--project={args.project}",
                    impersonate,
                ),
                redact_stdout=True,
            )
        kms = cp.get("kms_key_resource")
        if kms:
            expected_kms_role = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
            if cp.get("kms_grant_principal") != identity:
                raise VerificationError(
                    "identity contract must name the serving identity as the KMS grant principal"
                )
            if cp.get("kms_grant_role") != expected_kms_role:
                raise VerificationError(
                    f"identity contract must require {expected_kms_role} for the production KMS key"
                )
            kms_policy_args = [
                "kms",
                "keys",
                "get-iam-policy",
                str(kms),
                "--format=json",
            ]
            kms_policy_json = evidence.command("kms-iam", gcloud(*kms_policy_args))
            kms_policy = json.loads(kms_policy_json)
            if not any(
                binding.get("role") == expected_kms_role
                and reader_member in binding.get("members", [])
                for binding in kms_policy.get("bindings", [])
            ):
                raise VerificationError(
                    f"KMS policy has no encrypter/decrypter grant for {identity}"
                )
            key_project, key_location, keyring, key_name = kms_key_parts(str(kms))
            plaintext = args.evidence_dir / "kms-probe-plaintext"
            ciphertext = args.evidence_dir / "kms-probe-ciphertext"
            decrypted = args.evidence_dir / "kms-probe-decrypted"
            plaintext.write_bytes(b"control-plane-kms-access-probe-v1\n")
            evidence.command(
                "kms-encrypt-as-runtime",
                gcloud(
                    "kms",
                    "encrypt",
                    f"--project={key_project}",
                    f"--location={key_location}",
                    f"--keyring={keyring}",
                    f"--key={key_name}",
                    f"--plaintext-file={plaintext}",
                    f"--ciphertext-file={ciphertext}",
                    impersonate,
                ),
            )
            evidence.command(
                "kms-decrypt-as-runtime",
                gcloud(
                    "kms",
                    "decrypt",
                    f"--project={key_project}",
                    f"--location={key_location}",
                    f"--keyring={keyring}",
                    f"--key={key_name}",
                    f"--ciphertext-file={ciphertext}",
                    f"--plaintext-file={decrypted}",
                    impersonate,
                ),
            )
            if decrypted.read_bytes() != plaintext.read_bytes():
                raise VerificationError("runtime KMS decrypt probe did not reproduce its plaintext")
            (args.evidence_dir / "kms-prerequisite.txt").write_text(
                "Terraform-managed KMS grant and runtime encrypt/decrypt probe passed before cutover.\n"
                f"identity={identity}\nkey={kms}\nrole={expected_kms_role}\n"
            )

        required_checks = [
            "service",
            "candidate-revision",
            "own-template-list",
            "manifest-read",
            "sandbox-list-denied",
            "bucket-iam",
            "project-iam",
            "service-account-iam",
            "effective-iam",
        ]
        required_checks.extend(denied_list_checks)
        required_checks.extend(check[0] for check in denial_checks)
        required_checks.extend(
            f"referenced-read-{index}" for index, _ in enumerate(references, 1)
        )
        required_checks.extend(
            f"secret-access-{index}" for index, _ in enumerate(cp["secret_ids"], 1)
        )
        required_checks.extend(
            f"host-effective-iam-{index}"
            for index, _ in enumerate(host_identities, 1)
        )
        required_checks.extend(
            f"managed-folder-iam-{index}"
            for index, _ in enumerate(object_prefixes, 1)
        )
        if kms:
            required_checks.extend(["kms-iam", "kms-encrypt-as-runtime", "kms-decrypt-as-runtime"])
        # All permission checks must pass while the old revision is still
        # serving. Routing is deliberately the final gate in this workflow.
        evidence.require_passes(required_checks)

        if args.route_traffic:
            before_route = json.loads(
                evidence.command(
                    "service-before-route",
                    gcloud(
                        "run", "services", "describe", args.service,
                        f"--region={args.region}", f"--project={args.project}", "--format=json",
                    ),
                )
            )
            if (
                before_route.get("status", {}).get("latestCreatedRevisionName") != candidate
                or runtime_identity(before_route) != identity
            ):
                raise VerificationError("service changed during candidate verification")
            evidence.command(
                "route-candidate",
                gcloud(
                    "run",
                    "services",
                    "update-traffic",
                    args.service,
                    f"--to-revisions={candidate}=100",
                    f"--region={args.region}",
                    f"--project={args.project}",
                ),
            )
            final_service = json.loads(
                evidence.command(
                    "traffic-after-route",
                    gcloud(
                        "run",
                        "services",
                        "describe",
                        args.service,
                        f"--region={args.region}",
                        f"--project={args.project}",
                        "--format=json",
                    ),
                )
            )
            final_ready = final_service.get("status", {}).get("latestReadyRevisionName")
            final_traffic = final_service.get("status", {}).get("traffic", [])
            final_serving = sum(
                int(entry.get("percent", 0))
                for entry in final_traffic
                if entry.get("revisionName") == candidate
            )
            if final_ready != candidate or final_serving != 100:
                raise VerificationError(
                    f"latest revision {final_ready!r} has {final_serving}% traffic after routing"
                )
            latest_json = evidence.command(
                "latest-revision",
                gcloud(
                    "run",
                    "revisions",
                    "describe",
                    final_ready,
                    f"--region={args.region}",
                    f"--project={args.project}",
                    "--format=json",
                ),
            )
            latest = json.loads(latest_json)
            latest_identity = runtime_identity(latest)
            if latest_identity != identity:
                raise VerificationError(
                    f"serving revision uses {latest_identity!r}, expected {identity!r}"
                )
            (args.evidence_dir / "revision-traffic-final.json").write_text(
                json.dumps(
                    {
                        "latest_ready_revision": final_ready,
                        "runtime_service_account": latest_identity,
                        "traffic": final_traffic,
                    },
                    indent=2,
                )
                + "\n"
            )
            evidence.require_passes(["service-before-route", "route-candidate", "traffic-after-route", "latest-revision"])

        (args.evidence_dir / "legacy-grant-audit.txt").write_text(
            "Legacy identity is retained only until the old revision and shared-host dependencies are drained.\n"
            f"legacy_identity={legacy}\n"
            f"previous_revision={args.previous_revision or 'not supplied'}\n"
            f"previous_revision_identity={previous_identity or 'not observed'}\n"
            "Audit: confirm no serving revision, VMD host, restore tool, or rollback revision still uses each grant; record removed or retained-with-owner rows here before revocation.\n"
        )
        evidence.write_index("PASS")
        return 0
    except (VerificationError, OSError, json.JSONDecodeError) as exc:
        if not (args.evidence_dir / "legacy-grant-audit.txt").exists():
            (args.evidence_dir / "legacy-grant-audit.txt").write_text(
                "cleanup_status=NOT_EVALUATED\n"
                "The verifier failed before the obsolete-grant dependency audit; retain all legacy grants and investigate the failure before retrying.\n"
            )
        (args.evidence_dir / "failure.txt").write_text(f"{exc}\n")
        evidence.write_index("FAIL")
        print(f"control-plane identity verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
