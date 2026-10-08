#!/usr/bin/env python3
"""Validate logging migration phases and detect changes outside identity rollouts."""

import json
import sys


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


def validate_migration_transition(plan):
    changes_host_logging(plan)  # Reject malformed plans before inspecting phases.
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


def changes_host_logging(plan: dict) -> bool:
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


if __name__ == "__main__":
    if len(sys.argv) == 2:
        option, path = "--has-changes", sys.argv[1]
    elif len(sys.argv) == 3 and sys.argv[1] == "--check":
        option, path = sys.argv[1:]
    else:
        raise SystemExit("usage: host_logging_plan.py [--check] PLAN_JSON")
    with open(path, encoding="utf-8") as handle:
        plan = json.load(handle)
    if option == "--check":
        validate_migration_transition(plan)
    else:
        print("true" if changes_host_logging(plan) else "false")
