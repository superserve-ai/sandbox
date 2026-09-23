#!/usr/bin/env python3
"""Keep Host 2 maintenance out of routine Terraform rollout workflows.

The guarded host module is the root's identity-bound host: module.sandbox_host_b
unless the workflow names another with --guarded, which the east root does for
module.sandbox_host_c. Identity-only rollouts use --all-hosts to also protect
legacy hosts and persistent disks from unrelated maintenance.
"""

import argparse
import json
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--guarded", default="module.sandbox_host_b")
    parser.add_argument("--all-hosts", action="store_true")
    args = parser.parse_args()
    guarded = args.guarded.rstrip(".") + "."

    plan = json.load(sys.stdin)
    if not isinstance(plan, dict) or "format_version" not in plan:
        raise ValueError("Expected Terraform plan JSON")

    blocked = []
    for resource in plan.get("resource_changes", []):
        address = resource["address"]
        host = (
            resource["type"] == "google_compute_instance"
            and (args.all_hosts or address.startswith(guarded))
        )
        disk = args.all_hosts and resource["type"] in {
            "google_compute_disk", "google_compute_attached_disk",
        }
        # The adapter can restart the VM even when the Compute plan is a no-op.
        identity = (
            address.startswith("module.peer_identity.")
            and resource["type"] == "terraform_data"
            and resource["name"] == "managed_identity"
        )
        if (host or disk or identity) and resource["change"]["actions"] != ["no-op"]:
            blocked.append(address)

    if blocked:
        print("Host maintenance requires an operator-applied plan after the "
              "prechecks in deploy/host2-identity-runbook.md:", file=sys.stderr)
        for address in blocked:
            print(f"  {address}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
