#!/usr/bin/env python3
"""Return success when a Terraform plan activates or changes host logging.

The production staging-evidence gate is scoped to the persisted host-logging
assignment/revision, immutable deployment content, and serving-host
replacements that change its identity. Unrelated Terraform and control-plane
plans therefore remain deployable.
"""

import hashlib
import json
import re
import sys


_CONTENT_RESOURCES = (
    "google_os_config_os_policy_assignment.host_logging",
    "google_storage_bucket_object.ops_agent_config",
    "google_storage_bucket_object.reconcile_script",
    "google_storage_bucket_object.validate_script",
)
_ALERT_RESOURCES = (
    "google_logging_metric.host_logging_heartbeat",
    "google_monitoring_alert_policy.host_logging_export_failures",
    "google_monitoring_alert_policy.host_logging_lag",
    "google_monitoring_alert_policy.host_logging_heartbeat",
)
_DEPLOYMENT_METADATA_KEYS = {
    "bucket", "location", "member", "project", "service_account_email",
    "service_account", "zone", "name", "display_name", "instance_name",
}
_IDENTITY_LINE = re.compile(
    r"(?im)(\b(?:host_id|instance_id|incarnation|environment|region|host_logging_assignment|assignment_name)\b\s*[:=]\s*)([^,\s}\"']+)"
)
_HOST_DESCRIPTOR_LINE = re.compile(r"(?m)^# [^:\n]+: host_id=.*$\n?")
_KNOWN_ENVIRONMENTS = {"staging", "production"}
_KNOWN_REGIONS = {"us-central1", "us-west2", "us-east4"}
_HOST_RESOURCE_ADDRESS = re.compile(r'(module\.host_logging\.[^\[]+|module\.observability\.[^\[]+)\["[^"]+"\]')
_IDENTITY_KEYS = {
    "host_id", "instance_id", "instance_name", "incarnation", "self_link",
    "service_account_email",
}


def _normalize_artifact(text: str) -> str:
    """Ignore only approved deployment substitutions in rendered artifacts."""

    text = _HOST_DESCRIPTOR_LINE.sub("", text)
    return _IDENTITY_LINE.sub(r"\1<deployment-identity>", text)


def _stable(value, *, artifact=False, key=None, selector=False):
    if isinstance(value, dict):
        if key == "enrolled_hosts":
            # Host multiplicity and runtime identity are rollout metadata. The
            # source allowlist/proxy-unit behavior remains part of the digest;
            # duplicate equivalent host descriptors collapse below.
            descriptors = []
            for descriptor in value.values():
                if not isinstance(descriptor, dict):
                    continue
                descriptors.append(_stable(descriptor, key="host_descriptor"))
            return sorted({json.dumps(item, sort_keys=True) for item in descriptors})
        return {
            key: _stable(
                child,
                artifact=artifact or key in {"content", "filter", "query", "documentation"},
                key=key,
                selector=selector or key in {"instance_filter", "inclusion_labels", "labels"},
            )
            for key, child in sorted(value.items())
            if key not in _DEPLOYMENT_METADATA_KEYS | {"id", "etag", "self_link", "generation"}
        }
    if isinstance(value, list):
        stable = [_stable(child, artifact=artifact, key=key, selector=selector) for child in value]
        # for_each host resources are equivalent when their behavior is
        # equivalent; retain order for every other list because order can be
        # functional (processor/pipeline order, IAM conditions, etc.).
        if key in {"enrolled_hosts", "host_descriptor"}:
            return sorted({json.dumps(item, sort_keys=True) for item in stable})
        return stable
    if key in _IDENTITY_KEYS and not selector:
        return "<deployment-identity>"
    if key == "member" and isinstance(value, str) and value.startswith("serviceAccount:"):
        return "serviceAccount:<deployment-identity>"
    if key in {"environment", "region"} and str(value) in (_KNOWN_ENVIRONMENTS | _KNOWN_REGIONS):
        return f"<deployment-{key}>"
    if artifact and isinstance(value, str):
        return _normalize_artifact(value)
    return value


def deployment_content_digest(plan: dict) -> str:
    """Hash the effective host-logging and alert content, not its revision name.

    Bucket generations, Terraform provider IDs, and narrowly-scoped staging vs
    production identity values are excluded. Functional configuration,
    reconciliation, package/resource settings, pipeline, and alert changes
    remain part of the digest.
    """

    manifest = []
    for item in plan.get("resource_changes") or []:
        address = item.get("address", "")
        if not any(resource in address for resource in _CONTENT_RESOURCES + _ALERT_RESOURCES):
            continue
        after = (item.get("change") or {}).get("after")
        if after is not None:
            canonical_address = _HOST_RESOURCE_ADDRESS.sub(r'\1["<host>"]', address)
            canonical_after = _stable(after)
            manifest.append({"address": canonical_address, "after": canonical_after})
    # A staging plan can legitimately enumerate two equivalent serving hosts
    # while a production plan enumerates one. Deduplicate only equivalent
    # canonical resource entries; selector shape and all functional content
    # remain represented in each entry.
    manifest = sorted({json.dumps(item, sort_keys=True) for item in manifest})
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def requires_evidence(plan: dict) -> bool:
    for item in (plan.get("resource_changes") or []):
        address = item.get("address", "")
        actions = (item.get("change") or {}).get("actions", [])
        if address.startswith("module.host_logging.") and actions != ["no-op"]:
            return True
        if (address.startswith("module.observability.") and
                any(resource in address for resource in _ALERT_RESOURCES) and
                actions != ["no-op"]):
            return True
        if address.startswith("module.sandbox_host") and set(actions) & {"create", "delete"}:
            return True
    return False


def configuration_revision(plan: dict) -> str:
    for item in (plan.get("resource_changes") or []):
        if item.get("address") != "module.host_logging.google_storage_bucket_object.ops_agent_config":
            continue
        name = ((item.get("change") or {}).get("after") or {}).get("name", "")
        parts = name.split("/")
        if len(parts) >= 2 and parts[-1] == "config.yaml":
            return parts[-2]
    return ""


if __name__ == "__main__":
    revision_mode = len(sys.argv) == 3 and sys.argv[1] == "--revision"
    digest_mode = len(sys.argv) == 3 and sys.argv[1] == "--digest"
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and not (revision_mode or digest_mode)):
        raise SystemExit("usage: host_logging_plan_requires_evidence.py [--revision|--digest] PLAN_JSON")
    plan_path = sys.argv[-1]
    with open(plan_path, encoding="utf-8") as handle:
        plan = json.load(handle)
    if revision_mode:
        print(configuration_revision(plan))
        raise SystemExit(0)
    if digest_mode:
        print(deployment_content_digest(plan))
        raise SystemExit(0)
    print("host-logging staging evidence required" if requires_evidence(plan)
          else "host-logging staging evidence not required")
    raise SystemExit(0 if requires_evidence(plan) else 1)
