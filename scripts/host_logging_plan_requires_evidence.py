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
_KNOWN_ENVIRONMENTS = {"staging", "production"}
_KNOWN_REGIONS = {"us-central1", "us-west2", "us-east4"}
_HOST_RESOURCE_ADDRESS = re.compile(r'(module\.host_logging\.[^\[]+|module\.observability\.[^\[]+)\["[^"]+"\]')
def _unknown_allowed(address, path):
    """Permit provider metadata only at explicit resource-root paths."""
    resource = address.split("[")[0]
    return resource in {
        "module.host_logging.google_storage_bucket_object.ops_agent_config",
        "module.host_logging.google_storage_bucket_object.reconcile_script",
        "module.host_logging.google_storage_bucket_object.validate_script",
    } and len(path) == 1 and path[0] in {"generation", "etag"}


def _validate_after_unknown(address, after, unknown, path=()):
    """Fail closed for unresolved functional plan content.

    Terraform may omit a value from ``after`` when ``after_unknown`` marks it.
    Only the exact object-generation metadata paths above are provider-owned
    and safe to ignore; an unknown ancestor/list/value can otherwise hide a
    selector, script, policy, or IAM change.
    """
    if unknown is True:
        if not _unknown_allowed(address, path):
            raise ValueError("unresolved functional host-logging content at " + ".".join(map(str, path)))
        return
    if isinstance(unknown, dict):
        if after is not None and not isinstance(after, dict):
            raise ValueError("malformed after/after_unknown shape at " + ".".join(map(str, path)))
        after_map = after if isinstance(after, dict) else {}
        for key, pending in unknown.items():
            _validate_after_unknown(address, after_map.get(key), pending, path + (key,))
        return
    if isinstance(unknown, list):
        if after is not None and not isinstance(after, list):
            raise ValueError("malformed after/after_unknown list shape at " + ".".join(map(str, path)))
        after_list = after if isinstance(after, list) else []
        for index, pending in enumerate(unknown):
            _validate_after_unknown(address, after_list[index] if index < len(after_list) else None,
                                     pending, path + (index,))


def _stable(value, *, path=(), normalize_identity=False):
    if isinstance(value, dict):
        result = {}
        for key, child in sorted(value.items()):
            child_path = path + (key,)
            # These are the only identity substitutions used by this schema.
            # Selector maps and arbitrary script/config dictionaries retain
            # their keys and values verbatim.
            child_identity = normalize_identity and key in {
                "host_id", "instance_id", "incarnation", "instance_name",
            }
            result[key] = _stable(child, path=child_path, normalize_identity=child_identity)
        return result
    if isinstance(value, list):
        return [_stable(child, path=path + (index,), normalize_identity=normalize_identity)
                for index, child in enumerate(value)]
    if normalize_identity and isinstance(value, (str, int)):
        return "<deployment-identity>"
    return value


def _canonical_after(address, after):
    """Normalize only known deployment identity schema paths."""
    if not isinstance(after, dict):
        return after
    copied = json.loads(json.dumps(after))
    enrolled = copied.get("enrolled_hosts")
    if isinstance(enrolled, dict):
        for descriptor in enrolled.values():
            if isinstance(descriptor, dict):
                for key in ("host_id", "instance_id", "incarnation", "instance_name"):
                    if key in descriptor:
                        descriptor[key] = "<deployment-identity>"
    # Resource-level deployment operands are explicit schema fields; nested
    # selector labels and arbitrary content are intentionally untouched.
    for key in ("environment", "region", "zone"):
        if key in copied and str(copied[key]) in (_KNOWN_ENVIRONMENTS | _KNOWN_REGIONS):
            copied[key] = f"<deployment-{key}>"
    if ".google_project_iam_member.log_writer" in address:
        member = copied.get("member")
        if isinstance(member, str) and member.startswith("serviceAccount:"):
            copied["member"] = "serviceAccount:<deployment-identity>"
    if ".google_storage_bucket_object.ops_agent_config" in address:
        content = copied.get("content")
        if isinstance(content, str):
            # These lines are rendered from the module's explicit deployment
            # context. Do not generalize this to arbitrary scripts or literals.
            content = re.sub(r"(?m)^(labels\.environment:\s*).*$", r"\1<deployment-environment>", content)
            content = re.sub(r"(?m)^(labels\.region:\s*).*$", r"\1<deployment-region>", content)
            content = re.sub(r"(?m)^# [^:\n]+: host_id=\S+\s*$", "", content)
            copied["content"] = content
    if ".google_monitoring_alert_policy.host_logging_" in address:
        def normalize_filter(value, key=None):
            if key == "filter" and isinstance(value, str):
                for operand in ("instance_id", "project_id", "location", "zone"):
                    value = re.sub(
                        rf'(resource\.labels\.{operand}\s*=\s*")[^"]+("|$)',
                        rf'\1<deployment-{operand}>\2', value)
                return value
            if isinstance(value, dict):
                return {child_key: normalize_filter(child, child_key)
                        for child_key, child in value.items()}
            if isinstance(value, list):
                return [normalize_filter(child, key) for child in value]
            return value
        copied = normalize_filter(copied)
    return _stable(copied)


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
        change = item.get("change") or {}
        after = change.get("after")
        _validate_after_unknown(address, after, change.get("after_unknown") or {})
        if after is not None:
            canonical_address = _HOST_RESOURCE_ADDRESS.sub(r'\1["<host>"]', address)
            canonical_after = _canonical_after(address, after)
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
