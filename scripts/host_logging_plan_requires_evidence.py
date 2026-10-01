#!/usr/bin/env python3
"""Return success when a Terraform plan activates or changes host logging.

The production staging-evidence gate is scoped to the persisted host-logging
assignment/revision and to serving-host replacements that change its identity.
Unrelated Terraform and control-plane plans therefore remain deployable.
"""

import json
import sys


def requires_evidence(plan: dict) -> bool:
    for item in (plan.get("resource_changes") or []):
        address = item.get("address", "")
        actions = (item.get("change") or {}).get("actions", [])
        if address.startswith("module.host_logging.") and actions != ["no-op"]:
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
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and not revision_mode):
        raise SystemExit("usage: host_logging_plan_requires_evidence.py [--revision] PLAN_JSON")
    plan_path = sys.argv[-1]
    with open(plan_path, encoding="utf-8") as handle:
        plan = json.load(handle)
    if revision_mode:
        print(configuration_revision(plan))
        raise SystemExit(0)
    print("host-logging staging evidence required" if requires_evidence(plan)
          else "host-logging staging evidence not required")
    raise SystemExit(0 if requires_evidence(plan) else 1)
