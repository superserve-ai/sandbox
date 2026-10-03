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


class MigrationProofError(Exception):
    pass


def wait_for_migration_baseline(repository, revision, event, *, attempts=60, interval=20,
                                run=subprocess.run, sleep=time.sleep):
    """Require full regional migration success covering inherited migration inputs."""
    if event != "push":
        return True
    if not re.fullmatch(r"[0-9a-f]{40}", revision or ""):
        return False

    def command(args):
        result = run(args, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise MigrationProofError("Migration proof lookup failed")
        return result.stdout

    def api(path):
        return json.loads(command(["gh", "api", f"repos/{repository}/{path}"]))

    def inventory():
        collected = []
        for page in range(1, 11):
            response = api(f"actions/workflows/cd.yml/runs?branch=main&per_page=100&page={page}")
            batch, total = response["workflow_runs"], response["total_count"]
            if not isinstance(batch, list) or not isinstance(total, int) or total > 1000:
                raise MigrationProofError("Migration run inventory exceeds verification bound")
            collected.extend(batch)
            if len(collected) == total:
                if len({item["id"] for item in collected}) != total:
                    raise MigrationProofError("Migration run inventory changed")
                return collected
            if not batch or len(collected) > total:
                raise MigrationProofError("Incomplete migration run inventory")
        raise MigrationProofError("Incomplete migration run inventory")

    def signature(runs):
        return sorted((item["id"], item["run_attempt"], item["status"], item["conclusion"],
                       item["head_sha"], item["updated_at"]) for item in runs)

    try:
        for attempt in range(attempts):
            if api("git/ref/heads/main")["object"]["sha"] != revision:
                return False
            runs = inventory()
            # Older runs can be rerun after newer ones. Never select only successes
            # or rely on creation order while a later attempt may mutate a region.
            if any(item["status"] != "completed" for item in runs):
                pending = True
            else:
                pending = False
                baseline = None
                for item in sorted(runs, key=lambda item: item["updated_at"], reverse=True):
                    if (item.get("path") != ".github/workflows/cd.yml"
                            or item.get("head_branch") != "main"
                            or item.get("event") not in ("push", "workflow_dispatch")
                            or not re.fullmatch(r"[0-9a-f]{40}", item.get("head_sha", ""))
                            or not isinstance(item.get("run_attempt"), int) or item["run_attempt"] < 1):
                        return False
                    jobs = api(f"actions/runs/{item['id']}/attempts/{item['run_attempt']}/jobs?per_page=100")
                    if jobs["total_count"] != len(jobs["jobs"]) or not jobs["jobs"]:
                        return False
                    names = {job["name"] for job in jobs["jobs"]}
                    success = {job["name"] for job in jobs["jobs"] if job["conclusion"] == "success"}
                    # A named read-only preflight cannot establish or invalidate
                    # a migration baseline. Everything ambiguous holds deployment.
                    if (names <= {"Verify migration release", "Preflight Staging", "Preflight Production"}
                            and "Preflight Staging" in names):
                        continue
                    if (item["conclusion"] != "success"
                            or not {"Migrate Staging", "Migrate Production"} <= success):
                        return False
                    baseline = item["head_sha"]
                    break
                if baseline is None:
                    return False
                command(["git", "fetch", "--quiet", "--no-tags", "--depth=1000", "origin", revision, baseline])
                command(["git", "merge-base", "--is-ancestor", baseline, revision])
                protected = sorted(RECOVERY_PATHS | {
                    "supabase/migrations", "supabase/shared-auth-history", "supabase/shared-auth-migrations",
                    "supabase/recovery", ".github/workflows/scripts/migration_gate.py",
                })
                # History, not just endpoint trees: a change followed by a revert
                # still needs a newer successful migration run.
                changed = command(["git", "log", "--full-history", "--format=%H",
                                   f"{baseline}..{revision}", "--", *protected])
                if changed.strip():
                    return False
                if (signature(inventory()) != signature(runs)
                        or api("git/ref/heads/main")["object"]["sha"] != revision):
                    return False
                return True
            if pending and attempt + 1 < attempts:
                print(f"Waiting for migration attempts to finish ({attempt + 1}/{attempts}).")
                sleep(interval)
    except (MigrationProofError, OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError):
        return False
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

    if not wait_for_migration_baseline(os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_SHA"],
                                       os.environ["GITHUB_EVENT_NAME"]):
        raise SystemExit("No completed regional migration covers this revision's inherited inputs; "
                         "refusing deployment. Re-evaluate migrations at the current main revision.")
