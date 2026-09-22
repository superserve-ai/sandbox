#!/usr/bin/env python3
"""Reject control-plane identity changes from the automatic Terraform CD path."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any


API_RESOURCE = "module.api.google_cloud_run_v2_service.this"


def _first(value: Any) -> Any:
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _service_account(values: Any) -> str | None:
    if not isinstance(values, dict):
        return None
    template = _first(values.get("template"))
    if not isinstance(template, dict):
        return None
    account = template.get("service_account")
    return account if isinstance(account, str) and account else None


def changed_identity(plan: dict[str, Any]) -> tuple[str, str | None, str | None] | None:
    """Return the API resource's identity transition, if the plan contains one."""
    for resource in plan.get("resource_changes", []):
        if not isinstance(resource, dict) or resource.get("address") != API_RESOURCE:
            continue
        change = resource.get("change")
        if not isinstance(change, dict):
            return (API_RESOURCE, None, None)
        actions = change.get("actions")
        if actions == ["no-op"]:
            continue
        before = _service_account(change.get("before"))
        after = _service_account(change.get("after"))
        # A create/delete or an incomplete plan cannot be safely handed to the
        # automatic image deploy: it has no captured rollback identity.
        if "create" in (actions or []) or "delete" in (actions or []):
            return (API_RESOURCE, before, after)
        if before is None or after is None or before != after:
            return (API_RESOURCE, before, after)
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cell", required=True)
    args = parser.parse_args()
    try:
        plan = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"cannot inspect Terraform plan for {args.cell}: {exc}", file=sys.stderr)
        return 2
    if not isinstance(plan, dict):
        print(f"cannot inspect Terraform plan for {args.cell}: expected an object", file=sys.stderr)
        return 2

    transition = changed_identity(plan)
    if transition is None:
        return 0
    address, before, after = transition
    print(
        "Automatic Terraform CD refuses a control-plane service-account "
        f"transition in {args.cell} ({address}: {before!r} -> {after!r}). "
        "Run the staged control-plane identity rollout before retrying automatic CD.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
