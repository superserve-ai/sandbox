#!/usr/bin/env python3
"""Keep Host 2 maintenance out of routine Terraform rollout workflows."""

import json
import sys


def main():
    plan = json.load(sys.stdin)
    if not isinstance(plan, dict) or "format_version" not in plan:
        raise ValueError("Expected Terraform plan JSON")

    # The guarded host is the cell's identity-bound one: the second host in
    # every cell but us-east4, whose second host was retired and whose third
    # host carries the identity.
    suffix = plan.get("variables", {}).get("resource_suffix", {}).get("value")
    guarded = "module.sandbox_host_c." if suffix == "use4" else "module.sandbox_host_b."

    blocked = []
    for resource in plan.get("resource_changes", []):
        address = resource["address"]
        host = (
            address.startswith(guarded)
            and resource["type"] == "google_compute_instance"
        )
        # The adapter can restart the VM even when the Compute plan is a no-op.
        identity = (
            address.startswith("module.peer_identity.")
            and resource["type"] == "terraform_data"
            and resource["name"] == "managed_identity"
        )
        if (host or identity) and resource["change"]["actions"] != ["no-op"]:
            blocked.append(address)

    if blocked:
        print("Host 2 maintenance requires an operator-applied plan after the "
              "prechecks in deploy/host2-identity-runbook.md:", file=sys.stderr)
        for address in blocked:
            print(f"  {address}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
