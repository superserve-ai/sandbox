#!/usr/bin/env python3
"""Check triage mapping coverage against the reviewed alert inventory."""

import sys
from pathlib import Path

from alert_contract import POLICIES, mapping_rows, policy_inventory, reviewed_variants, variant_inventory


def check(root):
    errors = policy_inventory(root) + variant_inventory(root)
    rows = mapping_rows(root)
    expected = set()
    for name, variant, label in reviewed_variants():
        expected.add(label)
        entries = rows.get(label, [])
        if len(entries) != 1:
            errors.append(f"infra/alerts/runbook-map.md: google_monitoring_alert_policy.{name}: missing or duplicate {label} triage mapping")
            continue
        _, family, component, failure, _ = POLICIES[name]
        actual = entries[0][1:4]
        if actual[:2] != [f"`{family}`", f"`{component}`"] or any(not cell.strip("` ") for cell in actual):
            errors.append(f"infra/alerts/runbook-map.md: google_monitoring_alert_policy.{name}: incomplete {label} triage mapping")
        if failure != "variant" and actual[2] != f"`{failure}`":
            errors.append(f"infra/alerts/runbook-map.md: google_monitoring_alert_policy.{name}: mismatched {label} failure family")
        operation = entries[0][4]
        if name == "sandbox_lifecycle_latency" and operation != f"`{variant}`":
            errors.append(f"infra/alerts/runbook-map.md: google_monitoring_alert_policy.{name}: mismatched {label} operation")
        if name == "sandbox_failed" and operation != "—":
            errors.append(f"infra/alerts/runbook-map.md: google_monitoring_alert_policy.{name}: aggregate operation must be absent")
    for label in rows.keys() - expected:
        errors.append(f"infra/alerts/runbook-map.md: unreviewed policy variant {label}")
    return errors


if __name__ == "__main__":
    failures = check(Path(__file__).resolve().parents[1])
    print("\n".join(failures) if failures else "Alert triage coverage OK", file=sys.stderr if failures else sys.stdout)
    sys.exit(bool(failures))
