#!/usr/bin/env python3
"""Limit initial billing-monitor rollout to its six independently owned alerts."""
import json
import sys

METRIC_KEYS = (
    "debt_unknown",
    "sampler_errors",
    "silent-east-entitlement_coverage_sample",
    "silent-east-usage_entitlement_backlog",
    "silent-west-usage_entitlement_backlog",
)
ADDRESSES = {
    f'module.billing_alerts.google_monitoring_alert_policy.entitlement_metric["{key}"]'
    for key in METRIC_KEYS
} | {"module.billing_alerts.google_monitoring_alert_policy.entitlement_recovery"}
CHANNEL = "projects/rayai-prod/notificationChannels/17044408421759047225"


def validate(plan):
    resources = plan.get("resource_changes", [])
    if len(resources) != len(ADDRESSES) or {r["address"] for r in resources} != ADDRESSES:
        raise ValueError("Plan must contain exactly the six owned billing alerts")
    for resource in resources:
        change = resource["change"]
        after = change.get("after") or {}
        if change.get("importing") or change["actions"] not in (["create"], ["no-op"]):
            raise ValueError("Initial rollout permits only creation or unchanged owned alerts")
        if (resource["type"] != "google_monitoring_alert_policy"
                or after.get("project") != "rayai-prod"
                or after.get("enabled") is not True
                or after.get("notification_channels") != [CHANNEL]):
            raise ValueError("Alert project, enabled state or billing route is outside scope")


if __name__ == "__main__":
    validate(json.load(sys.stdin))
    print("Plan contains only the six owned billing alerts; no imports, updates or deletions")
