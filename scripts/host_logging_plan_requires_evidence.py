#!/usr/bin/env python3
"""Print true when a Terraform plan activates or changes host logging.

The production staging-evidence gate is scoped to the persisted host-logging
assignment/revision, immutable deployment content, and serving-host
replacements that change its identity. Unrelated Terraform and control-plane
plans therefore remain deployable.
"""

import hashlib
import datetime
import json
import re
import sys


_CONTENT_RESOURCES = (
    "google_os_config_os_policy_assignment.host_logging",
    "google_storage_bucket_object.otel_config",
    "google_storage_bucket_object.otel_service",
    "google_storage_bucket_object.reconcile_script",
    "google_storage_bucket_object.validate_script",
    "google_project_iam_member.log_writer",
    "google_project_iam_member.telemetry_consumer",
    "google_storage_bucket_iam_member.artifact_reader",
)
_ALERT_RESOURCES = (
    "google_logging_metric.host_logging_heartbeat",
    "google_logging_metric.host_logging_delivery_lag",
    "google_monitoring_alert_policy.host_logging_export_failures",
    "google_monitoring_alert_policy.host_logging_lag",
    "google_monitoring_alert_policy.host_logging_heartbeat",
)
def _known(value, unknown, path="content"):
    if unknown is True:
        raise ValueError("unresolved functional host-logging content at " + path)
    if isinstance(unknown, dict):
        for key, child in unknown.items():
            _known((value or {}).get(key), child, path + "." + key)
    elif isinstance(unknown, list):
        for index, child in enumerate(unknown):
            _known(value[index] if isinstance(value, list) and index < len(value) else None,
                   child, path + f"[{index}]")
    return value


def _selected(change, fields):
    after, unknown = change.get("after"), change.get("after_unknown") or {}
    if not isinstance(after, dict) or unknown is True:
        raise ValueError("missing or unresolved host-logging resource")
    return {key: _known(after.get(key), unknown.get(key), key) for key in fields}


def _normalize_config(content):
    # Only operands supplied by this module's deployment context are variable.
    content = re.sub(r'(?m)^(    (?:quota_project|project): )[^\n]+$', r'\1<project>', content)
    for key in ("environment", "region"):
        content = re.sub(r'(set\(attributes\["' + key + r'"\], ")[^"]+("\))',
                         r'\1<deployment>\2', content)
    for key in ("gcp.project_id", "cloud.availability_zone"):
        content = re.sub(r'(set\(resource.attributes\["' + re.escape(key) + r'"\], ")[^"]+("\))',
                         r'\1<deployment>\2', content)
    return content


def _normalize_alert(value, key=""):
    if isinstance(value, list):
        return [_normalize_alert(child, key) for child in value]
    if isinstance(value, dict):
        return {k: _normalize_alert(v, k) for k, v in value.items()
                if k not in {"name", "display_name", "description"}}
    if key in {"filter", "query"} and isinstance(value, str):
        value = re.sub(r'(resource.labels.(?:instance_id|project_id|location|zone)|labels.incarnation)(\s*=\s*")[^"]+("|$)',
                       r'\1\2<identity>\3', value)
        value = re.sub(r'("(?:collector_host_id|incarnation)"\s*=\s*")[^"]+("|$)', r'\1<identity>\2', value)
        value = re.sub(r'(superserve_host_logging_(?:heartbeat|delivery_lag)_)[A-Za-z0-9_-]+', r'\1<host>', value)
    return value


def deployment_content_digest(plan: dict) -> str:
    """Hash explicit deployment intent from Terraform's provider-shaped plan.

    Computed resource IDs and checksums are not configuration. GCS generations
    are checked against the planned artifact before replacing that reference
    with its content identity. Every selected functional value must be known.
    """
    changes = plan.get("resource_changes") or []
    artifacts, manifest = {}, []
    for item in changes:
        address = item.get("address", "")
        if any(resource in address for resource in _CONTENT_RESOURCES[1:5]):
            change = item["change"]
            value = _selected(change, ("bucket", "name", "content"))
            if not all(isinstance(value[k], str) for k in value):
                raise ValueError("artifact names and content must be known strings")
            suffix = value["name"].split("/")[-1]
            content = _normalize_config(value["content"]) if suffix == "otel-logs.yaml" else value["content"]
            if suffix == "reconcile.sh":
                content = re.sub(r"(?m)^legacy_enabled=[01]$", "legacy_enabled=<deployment>", content)
            artifacts[(value["bucket"], value["name"])] = (suffix, change["after"].get("generation"))
            manifest.append({"artifact": suffix, "content": content})
    for item in changes:
        address, change = item.get("address", ""), item.get("change") or {}
        if "google_os_config_os_policy_assignment.host_logging" in address:
            # permissions is provider-computed, and generation is resolved to
            # the exact content-bearing artifact above. No other unknown is ignored.
            change = json.loads(json.dumps(change))
            # Migration artifacts have their own exact target/instance evidence.
            # Remove corresponding entries in both value and unknown trees.
            policies = (change.get("after") or {}).get("os_policies", [])
            for pi, policy in enumerate(policies if isinstance(policies, list) else []):
                for gi, group in enumerate(policy.get("resource_groups", [])):
                    entries = group.get("resources", [])
                    kept = [i for i, entry in enumerate(entries) if not entry.get("id", "").startswith("legacy-migration-")]
                    if len(kept) != len(entries) and legacy_target(plan) is None:
                        raise ValueError("legacy migration resources require a bound target")
                    group["resources"] = [entries[i] for i in kept]
                    unknown = change.get("after_unknown") or {}
                    try:
                        ug = unknown["os_policies"][pi]["resource_groups"][gi]
                        if isinstance(ug.get("resources"), list):
                            ug["resources"] = [ug["resources"][i] for i in kept]
                    except (KeyError, IndexError, TypeError):
                        pass
            for root in (change.get("after") or {}, change.get("after_unknown") or {}):
                if not isinstance(root, dict):
                    raise ValueError("unresolved assignment")
                for policy in root.get("os_policies", []) if isinstance(root.get("os_policies", []), list) else []:
                    for group in policy.get("resource_groups", []) if isinstance(policy, dict) else []:
                        for resource in group.get("resources", []) if isinstance(group, dict) else []:
                            for file in resource.get("file", []) if isinstance(resource, dict) else []:
                                if not isinstance(file, dict):
                                    continue
                                file.pop("permissions", None)
                                for source in file.get("file", []) if isinstance(file.get("file", []), list) else []:
                                    for gcs in source.get("gcs", []) if isinstance(source, dict) else []:
                                        if not isinstance(gcs, dict):
                                            continue
                                        if root is change.get("after"):
                                            ref = artifacts.get((gcs.get("bucket"), gcs.get("object")))
                                            if ref is None:
                                                raise ValueError("assignment references an unbound artifact")
                                            if gcs.get("generation") is not None and ref[1] is not None and str(gcs["generation"]) != str(ref[1]):
                                                raise ValueError("assignment generation differs from planned artifact")
                                            gcs["bucket"], gcs["object"] = "<artifact-bucket>", ref[0]
                                        gcs.pop("generation", None)
            value = _selected(change, ("instance_filter", "os_policies", "rollout"))
            for selector in value.get("instance_filter") or []:
                for group in selector.get("inclusion_labels", []):
                    for key in ("environment", "region"):
                        if key in group.get("labels", {}):
                            group["labels"][key] = "<deployment>"
            manifest.append({"assignment": value})
        elif any(resource in address for resource in _CONTENT_RESOURCES[5:]):
            value = _selected(change, ("role", "member", "condition"))
            if not isinstance(value["member"], str) or not value["member"].startswith("serviceAccount:"):
                raise ValueError("delivery grants must use service account principals")
            value["member"] = "serviceAccount:<runtime>"
            manifest.append({"grant": address.split("[")[0].split(".")[-1], "value": value})
        elif any(resource in address for resource in _ALERT_RESOURCES):
            change = json.loads(json.dumps(change))
            for root in (change.get("after") or {}, change.get("after_unknown") or {}):
                for condition in root.get("conditions", []) if isinstance(root, dict) and isinstance(root.get("conditions", []), list) else []:
                    if isinstance(condition, dict):
                        condition.pop("name", None)
            fields = (("filter", "metric_descriptor", "label_extractors", "value_extractor", "bucket_options", "disabled")
                      if "google_logging_metric." in address else
                      ("conditions", "combiner", "enabled", "alert_strategy", "notification_channels", "documentation"))
            value = _selected(change, fields)
            if "notification_channels" in value:
                channels = value["notification_channels"]
                if not isinstance(channels, list) or not channels:
                    raise ValueError("host log alerts require notification routing")
                value["notification_channels"] = [re.sub(r"^projects/[^/]+/", "projects/<project>/", channel) for channel in channels]
                instance = (change["after"].get("user_labels") or {}).get("instance_name")
                if instance:
                    for document in value.get("documentation") or []:
                        document["content"] = document.get("content", "").replace(instance, "<instance>")
            manifest.append({"alert": address.split("[")[0].split(".")[-1], "value": _normalize_alert(value)})
    if not artifacts or not any("assignment" in item for item in manifest):
        raise ValueError("host-logging content digest unavailable")
    # Hosts differ by environment; equivalent per-host grants/alerts share intent.
    manifest = sorted({json.dumps(item, sort_keys=True) for item in manifest})
    return hashlib.sha256(json.dumps(manifest, separators=(",", ":")).encode()).hexdigest()


def legacy_target(plan, side="after"):
    for item in plan.get("resource_changes") or []:
        if item.get("address", "").startswith("module.host_logging.terraform_data.legacy_migration"):
            change = item.get("change") or {}
            value = change.get(side)
            if value is None:
                return None
            if side == "after":
                return _selected(change, ("input",))["input"]
            return value.get("input")
    return None


def migration_content_digest(plan):
    target = legacy_target(plan)
    if target is None:
        raise ValueError("missing migration target")
    artifacts, bindings = [], {}
    for item in plan.get("resource_changes") or []:
        if "google_storage_bucket_object.legacy_migration_" in item.get("address", ""):
            artifact = _selected(item["change"], ("bucket", "name", "content"))
            bindings[(artifact["bucket"], artifact["name"])] = item["change"]["after"].get("generation")
            if artifact["name"].endswith("legacy-migration.json") and json.loads(artifact["content"]) != target:
                raise ValueError("migration artifact differs from the planned target")
            artifacts.append(artifact)
    if len(artifacts) != 2:
        raise ValueError("migration helper and target artifacts are required")
    reconcile = next((_selected(item["change"], ("content",))["content"] for item in plan["resource_changes"] if "google_storage_bucket_object.reconcile_script" in item.get("address", "")), None)
    if reconcile is None:
        raise ValueError("migration requires its reconciliation script")
    references = []
    for item in plan["resource_changes"]:
        if "google_os_config_os_policy_assignment.host_logging" not in item.get("address", ""):
            continue
        change = item["change"]
        policies = (change.get("after") or {}).get("os_policies", [])
        for pi, policy in enumerate(policies):
            for gi, group in enumerate(policy.get("resource_groups", [])):
                for ri, entry in enumerate(group.get("resources", [])):
                    if not entry.get("id", "").startswith("legacy-migration-"):
                        continue
                    entry = json.loads(json.dumps(entry))
                    try:
                        unknown = json.loads(json.dumps(change["after_unknown"]["os_policies"][pi]["resource_groups"][gi]["resources"][ri]))
                    except (KeyError, IndexError):
                        unknown = {}
                    for tree in (entry, unknown):
                        for file in tree.get("file", []) if isinstance(tree, dict) else []:
                            file.pop("permissions", None)
                            for source in file.get("file", []):
                                for gcs in source.get("gcs", []):
                                    if tree is entry:
                                        key = (gcs.get("bucket"), gcs.get("object"))
                                        if key not in bindings:
                                            raise ValueError("unbound migration artifact reference")
                                        if gcs.get("generation") is not None and bindings[key] is not None and str(gcs["generation"]) != str(bindings[key]):
                                            raise ValueError("migration generation differs from planned artifact")
                                    gcs.pop("generation", None)
                    _known(entry, unknown, "migration resource")
                    for file in entry.get("file", []):
                        for source in file.get("file", []):
                            for gcs in source.get("gcs", []):
                                if gcs.get("object") not in {a["name"] for a in artifacts}:
                                    raise ValueError("unbound migration artifact reference")
                    references.append(entry)
    if len(references) != 2:
        raise ValueError("migration policy must bind helper and target")
    manifest = {"target": target, "artifacts": artifacts, "reconcile": reconcile, "references": references}
    return hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()


def validate_migration_evidence(plan, evidence):
    target, previous = legacy_target(plan), legacy_target(plan, "before")
    if target is None:
        return
    phase = target["phase"]
    before = previous["phase"] if previous else "preserve"
    allowed = {"preserve": {"verify", "overlap"}, "verify": {"overlap", "drain"},
               "overlap": {"verify", "drain"}, "drain": {"retire"},
               "retire": set(), "rollback": {"preserve", "verify", "overlap"}}
    if phase != before and phase != "rollback" and phase not in allowed.get(before, set()):
        raise ValueError("invalid legacy migration transition")
    if phase == "preserve":
        return
    receipt = evidence.get("migration") or {}
    if (receipt.get("phase") != phase or receipt.get("legacy_policy_name") != target.get("legacy_policy_name")
            or receipt.get("deployment_content_digest") != migration_content_digest(plan)
            or sorted(receipt.get("instance_ids", [])) != sorted(target["instance_ids"])
            or receipt.get("verified_instance_ids") != target["verified_instance_ids"]
            or receipt.get("drained_instance_ids") != target["drained_instance_ids"]
            or receipt.get("otel_deployment_content_digest") != deployment_content_digest(plan)
            or receipt.get("metrics_continuity") is not True or receipt.get("rollback_verified") is not True):
        raise ValueError("matching legacy migration and metrics continuity evidence required")
    try:
        observed = datetime.datetime.fromisoformat(receipt["observed_at"].replace("Z", "+00:00"))
        age = (datetime.datetime.now(datetime.timezone.utc) - observed).total_seconds()
    except (KeyError, ValueError, TypeError):
        raise ValueError("timestamped migration evidence required")
    if not -300 <= age <= 3600:
        raise ValueError("migration evidence must be from the last hour")
    if phase in {"drain", "retire"}:
        if receipt.get("overlap_gap_count") != 0 or not isinstance(receipt.get("duplicate_count"), int) or receipt["duplicate_count"] < 0:
            raise ValueError("measured overlap gaps and duplicate counts required")
    if phase == "retire" and (receipt.get("pending_records") != 0 or receipt.get("oldest_pending_age_seconds") != 0):
        raise ValueError("legacy buffers must be drained before retirement")


def requires_evidence(plan: dict) -> bool:
    if not isinstance(plan, dict) or not isinstance(plan.get("resource_changes"), list):
        raise ValueError("plan must contain a resource_changes list")
    has_logging = any(item.get("address", "").startswith("module.host_logging.") for item in plan["resource_changes"])
    for item in (plan.get("resource_changes") or []):
        address = item.get("address", "")
        actions = (item.get("change") or {}).get("actions", [])
        if address.startswith("module.host_logging.") and actions != ["no-op"]:
            return True
        if (address.startswith("module.observability.") and
                any(resource in address for resource in _ALERT_RESOURCES) and
                actions != ["no-op"]):
            return True
        if has_logging and address.startswith("module.sandbox_host") and set(actions) & {"create", "delete"}:
            return True
    return False


def configuration_revision(plan: dict) -> str:
    for item in (plan.get("resource_changes") or []):
        address = item.get("address", "")
        if not (address == "module.host_logging.google_storage_bucket_object.otel_config" or
                address.startswith("module.host_logging.google_storage_bucket_object.otel_config[")):
            continue
        name = ((item.get("change") or {}).get("after") or {}).get("name", "")
        parts = name.split("/")
        # The module emits the OTel configuration under this exact object
        # name. Keep the revision tied to the rendered artifact rather than
        # accepting an obsolete generic config.yaml basename.
        if len(parts) >= 2 and parts[-1] == "otel-logs.yaml":
            return parts[-2]
    return ""


def migration_changed(plan):
    return legacy_target(plan) is not None and any(
        item.get("address", "").startswith("module.host_logging.") and
        (item.get("change") or {}).get("actions") != ["no-op"]
        for item in plan.get("resource_changes") or [])


def requires_staging_evidence(plan):
    target = legacy_target(plan)
    return requires_evidence(plan) and (target is None or target["phase"] not in {"preserve", "rollback"})


def check_evidence(plan, evidence):
    if migration_changed(plan):
        validate_migration_evidence(plan, evidence)
    if requires_staging_evidence(plan):
        # Cross-project channels have distinct IDs. Only an explicit reviewed
        # routing map in the accepted receipt may substitute those operands.
        staged = json.loads(json.dumps(plan))
        channel_map = evidence.get("notification_channel_map", {})
        if not isinstance(channel_map, dict) or not all(
                re.fullmatch(r"projects/[^/]+/notificationChannels/[0-9]+", value)
                for pair in channel_map.items() for value in pair):
            raise ValueError("invalid notification channel mapping")
        for item in staged.get("resource_changes") or []:
            if any(resource in item.get("address", "") for resource in _ALERT_RESOURCES):
                after = (item.get("change") or {}).get("after") or {}
                if "notification_channels" in after:
                    after["notification_channels"] = [channel_map.get(channel, channel) for channel in after["notification_channels"]]
        if (evidence.get("environment") != "staging" or evidence.get("accepted") is not True
                or evidence.get("configuration_revision") != configuration_revision(plan)
                or evidence.get("deployment_content_digest") != deployment_content_digest(staged)):
            raise ValueError("accepted staging evidence for the exact host-logging content is required")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("usage: host_logging_plan_requires_evidence.py [--revision|--digest|--migration-digest|--needs-evidence|--check] PLAN_JSON [EVIDENCE_JSON]")
    option = sys.argv[1] if sys.argv[1].startswith("--") else ""
    path = sys.argv[2] if option else sys.argv[1]
    with open(path, encoding="utf-8") as handle:
        plan = json.load(handle)
    if option == "--revision":
        print(configuration_revision(plan))
    elif option == "--digest":
        print(deployment_content_digest(plan))
    elif option == "--migration-digest":
        print(migration_content_digest(plan))
    elif option == "--check":
        with open(sys.argv[3], encoding="utf-8") as handle:
            check_evidence(plan, json.load(handle))
    elif option == "--needs-evidence":
        target = legacy_target(plan)
        previous = legacy_target(plan, "before")
        migration = migration_changed(plan) and target is not None and (target["phase"] != "preserve" or (previous is not None and previous["phase"] != "preserve"))
        print("true" if migration or requires_staging_evidence(plan) else "false")
    elif not option:
        print("true" if requires_evidence(plan) else "false")
    else:
        raise SystemExit("unsupported option")
