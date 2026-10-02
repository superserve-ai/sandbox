#!/usr/bin/env python3
"""Select an explicit migration action only after revision and CI checks."""

import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess


spec = importlib.util.spec_from_file_location("push_ci", Path(__file__).with_name("wait-for-push-ci.py"))
push_ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(push_ci)
push_ci.RECOVERY_PATHS.update({
    ".github/workflows/ci.yml",
    ".github/workflows/scripts/migration_gate.py",
    ".github/workflows/scripts/test_migration_gate.py",
    "scripts/test_migration_cli.py",
    "scripts/test_migration_overlay.py",
    "scripts/test_migration_execution.py",
})


class GateError(Exception):
    pass


def api(repository, path):
    result = subprocess.run(["gh", "api", f"repos/{repository}/{path}"],
                            capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise GateError("Could not verify migration release prerequisites")
    return json.loads(result.stdout)


def select_action(env):
    revision, repository = env["GITHUB_SHA"], env["GITHUB_REPOSITORY"]
    if not re.fullmatch(r"[0-9a-f]{40}", revision) or env.get("GITHUB_REF") != "refs/heads/main":
        raise GateError("Migration execution requires an exact main revision")
    event = env["GITHUB_EVENT_NAME"]
    if event == "push":
        if push_ci.recovery_hold(env.get("PUSH_BEFORE", ""), revision, event):
            raise GateError("Intentional migration hold: runner or controls changed, or push diff is unverified")
        action, production = "push", True
    elif event == "workflow_dispatch":
        if env.get("APPROVED_REVISION") != revision:
            raise GateError("Approved revision must match this workflow revision exactly")
        if api(repository, "git/ref/heads/main")["object"]["sha"] != revision:
            raise GateError("Main advanced; migration release must be re-evaluated")
        requested = env.get("MIGRATION_ACTION")
        if requested not in ("preflight", "migrate") or env.get("MIGRATION_ENVIRONMENT") not in ("staging", "production"):
            raise GateError("Select an explicit supported migration action and environment")
        action = "preflight" if requested == "preflight" else "push"
        production = env["MIGRATION_ENVIRONMENT"] == "production"
        if action == "push":
            run_id = env.get("PREFLIGHT_RUN_ID", "")
            if not re.fullmatch(r"[1-9][0-9]*", run_id):
                raise GateError("Migration requires a successful same-revision preflight run")
            run = api(repository, f"actions/runs/{run_id}")
            if (run.get("head_sha") != revision or run.get("head_branch") != "main"
                    or run.get("event") != "workflow_dispatch" or run.get("status") != "completed"
                    or run.get("conclusion") != "success" or run.get("path") != ".github/workflows/cd.yml"):
                raise GateError("Preflight run does not establish this revision's prerequisites")
            jobs = api(repository, f"actions/runs/{run_id}/jobs?filter=latest&per_page=100")
            required = {"Preflight Staging", "Preflight Production"} if production else {"Preflight Staging"}
            successful = {job.get("name") for job in jobs["jobs"] if job.get("conclusion") == "success"}
            if not required <= successful:
                raise GateError("Preflight did not verify every requested environment")
    else:
        raise GateError("Unsupported migration workflow event")
    # Explicitly request the push-CI check even for manual dispatch.
    if not push_ci.wait_for_ci(repository, revision, "push"):
        raise GateError("Successful same-revision push CI is required")
    if api(repository, "git/ref/heads/main")["object"]["sha"] != revision:
        raise GateError("Main advanced while waiting; migration release must be re-evaluated")
    return action, production


def main():
    try:
        action, production = select_action(os.environ)
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            output.write(f"action={action}\nproduction={str(production).lower()}\n")
    except (GateError, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        print(str(error) if isinstance(error, GateError) else "Migration release verification failed")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
