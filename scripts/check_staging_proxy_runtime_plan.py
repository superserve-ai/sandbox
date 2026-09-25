#!/usr/bin/env python3
"""Allow only the staging NEG binding's explicit project-wide exception."""

import json
import sys


PREFIX = 'module.proxy_generations["staging"].'
BINDING = PREFIX + 'google_project_iam_member.generation[0]'
ROLE = PREFIX + 'google_project_iam_custom_role.generation[0]'
IDENTITY = {
    "project": "rayai-dev",
    "role": "projects/rayai-dev/roles/proxy_staging_proxy_endpoints",
    "member": "serviceAccount:vmd-runtime-staging-usc1@rayai-dev.iam.gserviceaccount.com",
}
CONDITION = [{
    "title": "Cell-owned proxy generation NEGs",
    "description": "Restrict NEG membership operations to this cell's generation NEGs.",
    "expression": "resource.type == 'compute.googleapis.com/NetworkEndpointGroup' && resource.name.startsWith('projects/rayai-dev/zones/us-central1-a/networkEndpointGroups/proxy-staging-')",
}]
PERMISSIONS = {
    "compute.networkEndpointGroups.get",
    "compute.networkEndpointGroups.attachNetworkEndpoints",
    "compute.networkEndpointGroups.detachNetworkEndpoints",
}


def validate(plan):
    changes = plan.get("resource_changes", [])
    if {item["address"] for item in changes} != {BINDING, ROLE} or len(changes) != 2:
        raise ValueError("Plan must contain exactly the staging endpoint role and binding")
    for item in changes:
        change = item["change"]
        before, after = change.get("before") or {}, change.get("after") or {}
        if change.get("importing") or item.get("previous_address"):
            raise ValueError("Imports and state moves are not part of the runtime grant")
        if item["address"] == ROLE:
            if (change["actions"] != ["no-op"] or after.get("project") != IDENTITY["project"]
                    or after.get("name") != IDENTITY["role"]
                    or set(after.get("permissions", [])) != PERMISSIONS):
                raise ValueError("Runtime role must retain exactly the three NEG permissions")
        else:
            create = change["actions"] == ["create"] and change.get("before") is None
            for value in (after,) if create else (before, after):
                if any(value.get(key) != expected for key, expected in IDENTITY.items()):
                    raise ValueError("Unexpected runtime principal, role, or project")
            if after.get("condition") != []:
                raise ValueError("Expected the explicit unconditional staging binding")
            actions = change["actions"]
            if not (create or (actions == ["delete", "create"] and before.get("condition") == CONDITION)
                    or (actions == ["no-op"] and before.get("condition") == [])):
                raise ValueError("Only the exact new grant or known conditional replacement is allowed")


if __name__ == "__main__":
    try:
        validate(json.load(sys.stdin))
    except (ValueError, KeyError, TypeError) as error:
        sys.exit(str(error))
    print("Validated staging runtime endpoint grant; no other resource changes.")
