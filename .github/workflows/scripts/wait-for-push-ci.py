#!/usr/bin/env python3
"""Require successful push CI for the exact automatic deployment revision."""

import json
import os
import re
import subprocess
import time


RECOVERY_PATHS = {
    "scripts/migrate_database.py",
    ".github/workflows/cd.yml",
    ".github/workflows/deploy-api.yml",
    ".github/workflows/deploy-proxy.yml",
    ".github/workflows/terraform-cd.yml",
    ".github/workflows/scripts/wait-for-push-ci.py",
}


def recovery_hold(before, revision, event, *, run=subprocess.run):
    if event != "push":
        return False
    if (not re.fullmatch(r"[0-9a-f]{40}", before or "") or before == "0" * 40
            or not re.fullmatch(r"[0-9a-f]{40}", revision or "")):
        return True
    try:
        result = run(["git", "fetch", "--quiet", "--no-tags", "--depth=1", "origin", before],
                     capture_output=True, text=True, timeout=30)
        if result.returncode:
            return True
        result = run(["git", "diff", "--name-only", "-z", "--no-renames", before, revision, "--"],
                     capture_output=True, text=True, timeout=30)
        if result.returncode:
            return True
        return any(path in RECOVERY_PATHS or path.startswith(
            ("supabase/shared-auth-history/", "supabase/shared-auth-migrations/"))
            for path in result.stdout.split("\0"))
    except (OSError, subprocess.TimeoutExpired):
        return True


def wait_for_ci(repository, revision, event, *, attempts=60, interval=20,
                run=subprocess.run, sleep=time.sleep):
    if event != "push":
        print("Manual dispatch: operator owns CI verification.")
        return True
    for attempt in range(attempts):
        try:
            result = run(
                ["gh", "api", f"repos/{repository}/actions/workflows/ci.yml/runs"
                 f"?head_sha={revision}&event=push&per_page=100"],
                capture_output=True, text=True, timeout=30)
            if result.returncode:
                return False
            runs = json.loads(result.stdout)["workflow_runs"]
            matching = [r for r in runs if r.get("head_sha") == revision and r.get("event") == "push"]
            current = matching[0] if matching else None
            if current and current.get("status") == "completed":
                return current.get("conclusion") == "success"
        except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError):
            return False
        print(f"Waiting for successful same-revision push CI ({attempt + 1}/{attempts}).")
        if attempt + 1 < attempts:
            sleep(interval)
    return False


if __name__ == "__main__":
    if recovery_hold(os.environ.get("PUSH_BEFORE", ""), os.environ["GITHUB_SHA"],
                     os.environ["GITHUB_EVENT_NAME"]):
        raise SystemExit("Intentional rollout hold: migration composition or deployment controls changed, "
                         "or the complete push diff could not be verified. CI and migrations may proceed; "
                         "target deployment requires a coordinated manual release.")
    if not wait_for_ci(os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_SHA"],
                       os.environ["GITHUB_EVENT_NAME"]):
        raise SystemExit("Required same-revision push CI did not succeed; refusing deployment.")
