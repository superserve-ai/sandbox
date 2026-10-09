#!/usr/bin/env python3
"""Require successful push CI for the exact automatic deployment revision."""

import json
import os
import subprocess
import time


class CILookupError(Exception):
    pass


def wait_for_ci(repository, revision, event, *, attempts=60, interval=20, tolerance=3,
                run=subprocess.run, sleep=time.sleep):
    """Wait for the same-revision push CI verdict.

    A lookup that cannot be completed is not a verdict. Tolerate up to
    `tolerance` consecutive lookup failures inside the attempt budget, then
    fail closed as before: an unverifiable revision never deploys.
    """
    if event != "push":
        print("Manual dispatch: operator owns CI verification.")
        return True
    failures = 0
    for attempt in range(attempts):
        try:
            result = run(
                ["gh", "api", f"repos/{repository}/actions/workflows/ci.yml/runs"
                 f"?head_sha={revision}&event=push&per_page=100"],
                capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise CILookupError("CI run lookup failed")
            runs = json.loads(result.stdout)["workflow_runs"]
            matching = [r for r in runs if r.get("head_sha") == revision and r.get("event") == "push"]
            current = matching[0] if matching else None
            if current and current.get("status") == "completed":
                return current.get("conclusion") == "success"
            failures = 0
            print(f"Waiting for successful same-revision push CI ({attempt + 1}/{attempts}).")
        except (CILookupError, OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError):
            failures += 1
            print(f"CI run lookup did not complete ({failures}/{tolerance}).")
            if failures >= tolerance:
                return False
        if attempt + 1 < attempts:
            sleep(interval)
    return False


if __name__ == "__main__":
    if not wait_for_ci(os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_SHA"],
                       os.environ["GITHUB_EVENT_NAME"]):
        raise SystemExit("Required same-revision push CI did not succeed; refusing deployment.")
