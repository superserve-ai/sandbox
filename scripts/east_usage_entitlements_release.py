#!/usr/bin/env python3
"""Recognize the narrow source landing and validate its separately approved plan."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


FLAG = "BILLING_USAGE_ENTITLEMENTS_ENABLED"
ROOT_FILE = "infra/envs/production/us-east4/main.tf"
API = "module.api.google_cloud_run_v2_service.this"
ACCOMMODATION_FILES = {
    ".github/workflows/terraform-cd.yml",
    "scripts/east_usage_entitlements_release.py",
    ".github/workflows/scripts/test_east_usage_entitlements_release.py",
}


def source_landing(before, after, changed_files):
    """Fail closed on a mixed enablement push instead of falling back to broad CD."""
    if before == after:
        return False
    if FLAG in before or FLAG not in after:
        return False
    api_start = before.index('module "api" {')
    env_start = before.index("  env = {\n", api_start) + len("  env = {\n")
    expected = before[:env_start] + f'    {FLAG} = "true"\n\n' + before[env_start:]
    if after != expected or set(changed_files) - ({ROOT_FILE} | ACCOMMODATION_FILES):
        raise ValueError("Enablement is mixed with other changes; automatic rollout is blocked")
    return True


def has_unknown(value):
    if isinstance(value, dict):
        return any(has_unknown(v) for v in value.values())
    if isinstance(value, list):
        return any(has_unknown(v) for v in value)
    return value is True


def validate_plan(plan, project, service):
    """Reject dependency mutations and every API delta except the literal flag."""
    if plan.get("errored") or plan.get("applyable") is False:
        raise ValueError("Plan is not applicable")
    if plan.get("deferred_changes"):
        raise ValueError("Deferred changes are not permitted")
    mutations = []
    for resource in plan.get("resource_changes", []):
        if resource.get("previous_address") or resource["change"].get("importing"):
            raise ValueError("State moves and imports require separate review")
        actions = resource["change"]["actions"]
        if actions == ["no-op"]:
            continue
        if resource.get("mode") == "data" and actions == ["read"]:
            continue
        mutations.append(resource)
    if len(mutations) != 1 or mutations[0].get("address") != API:
        raise ValueError("Plan must change only the East API service")
    resource = mutations[0]
    change = resource["change"]
    if resource.get("type") != "google_cloud_run_v2_service" or resource.get("provider_name") != "registry.terraform.io/hashicorp/google":
        raise ValueError("Unexpected API provider or resource type")
    if resource.get("mode") != "managed" or change["actions"] != ["update"]:
        raise ValueError("Only an in-place API update is permitted")
    if change.get("importing") or change.get("replace_paths") or has_unknown(change.get("after_unknown")):
        raise ValueError("Import, replacement or unknown API values require new review")
    before, after = copy.deepcopy(change["before"]), copy.deepcopy(change["after"])
    identity = {
        "project": project,
        "location": "us-east4",
        "name": service,
        "id": f"projects/{project}/locations/us-east4/services/{service}",
    }
    if not project or not service or any(before.get(k) != v or after.get(k) != v for k, v in identity.items()):
        raise ValueError("Plan does not match the reviewed East service identity")
    old_containers = before["template"][0]["containers"]
    new_containers = after["template"][0]["containers"]
    if len(old_containers) != 1 or len(new_containers) != 1:
        raise ValueError("Expected exactly one API container")
    old_env = old_containers[0].get("env", [])
    new_env = new_containers[0].get("env", [])
    old_flag = [e for e in old_env if e.get("name") == FLAG]
    new_flag = [e for e in new_env if e.get("name") == FLAG]
    if old_flag:
        raise ValueError("Flag already exists; obtain a fresh release assessment")
    if len(new_flag) != 1:
        raise ValueError("Expected exactly one new flag")
    flag = new_flag[0]
    if flag.get("value") != "true" or flag.get("value_source") or set(flag) - {"name", "value", "value_source"}:
        raise ValueError("Flag must be the literal true value")
    new_containers[0]["env"] = [e for e in new_env if e.get("name") != FLAG]
    if before != after:
        raise ValueError("Plan changes another API field, environment value, image or traffic")
    for output in plan.get("output_changes", {}).values():
        if output.get("actions") != ["no-op"]:
            raise ValueError("Output changes require separate review")
    return {"resource": API, "flag": FLAG, "value": "true", "other_mutations": 0}


def git(*args):
    return subprocess.check_output(
        ["git", *args], text=True, cwd=Path(__file__).resolve().parents[1], stderr=subprocess.PIPE,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    landing = sub.add_parser("landing")
    landing.add_argument("--before", required=True)
    landing.add_argument("--after", required=True)
    check = sub.add_parser("check-plan")
    check.add_argument("saved_plan", help="Private binary plan produced by Terraform, not JSON")
    check.add_argument("--project", required=True)
    check.add_argument("--service", required=True)
    args = parser.parse_args()
    try:
        if args.command == "landing":
            if not all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in (args.before, args.after)):
                raise ValueError("Expected exact commit IDs")
            files = git("diff", "--name-only", args.before, args.after).splitlines()
            before = git("show", f"{args.before}:{ROOT_FILE}")
            after = git("show", f"{args.after}:{ROOT_FILE}")
            narrow = source_landing(before, after, files)
            print(f"east_usage_only={str(narrow).lower()}")
        else:
            plan_path = Path(args.saved_plan).resolve(strict=True)
            digest = hashlib.sha256(plan_path.read_bytes()).hexdigest()
            root = Path(__file__).resolve().parents[1]
            data = subprocess.check_output(
                ["terraform", f"-chdir={root / 'infra/envs/production/us-east4'}", "show", "-json", str(plan_path)],
                stderr=subprocess.PIPE,
            )
            result = validate_plan(json.loads(data), args.project, args.service)
            if digest != hashlib.sha256(plan_path.read_bytes()).hexdigest():
                raise ValueError("Plan changed during validation")
            result["saved_plan_sha256"] = digest
            result["source_revision"] = git("rev-parse", "HEAD").strip()
            print(json.dumps(result))
    except (ValueError, KeyError, IndexError, TypeError, OSError, subprocess.CalledProcessError) as exc:
        # Provider values can contain secrets; never include the rejected value.
        print(f"Release check failed ({type(exc).__name__}); no apply is authorized", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
