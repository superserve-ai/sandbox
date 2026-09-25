#!/usr/bin/env python3
"""Check runbook coverage against the reviewed alert inventory."""

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
        logical = "vmd_launch" if variant == "launcher_not_ready" else "vmd_network" if name == "launch_path" else POLICIES[name][0]
        if name.startswith("ids_"):
            logical = "Cloud IDS investigation"
        if len(entries) != 1 or entries[0][0] != f"`{logical}`" and entries[0][0] != logical:
            errors.append(f"infra/alerts/runbook-map.md: google_monitoring_alert_policy.{name}: missing or mismatched {label} runbook input")
    for label in rows.keys() - expected:
        errors.append(f"infra/alerts/runbook-map.md: unreviewed policy variant {label}")
    return errors


if __name__ == "__main__":
    failures = check(Path(__file__).resolve().parents[1])
    print("\n".join(failures) if failures else "Alert runbook coverage OK", file=sys.stderr if failures else sys.stdout)
    sys.exit(bool(failures))
