#!/usr/bin/env python3
"""Require successful push CI for the exact automatic deployment revision."""

import json
import os
import re
import subprocess
import time


RECOVERY_PATHS = {
    "scripts/migrate_database.py",
    "scripts/retained_storage_recovery.py",
    "scripts/recovery_evidence.py",
    "scripts/collect_recovery_evidence.py",
    "scripts/recovery_database_binding.py",
    "scripts/recovery_guest_probe.py",
    "scripts/recovery_retired_receivers.json",
    "scripts/test_collect_recovery_evidence.py",
    "scripts/test_recovery_database_binding.py",
    "scripts/test_recovery_guest_probe.py",
    "scripts/migration-requirements.txt",
    "scripts/test_migration_recovery.py",
    "scripts/test_recovery_evidence.py",
    ".github/workflows/recovery-evidence.yml",
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
            ("supabase/shared-auth-history/", "supabase/shared-auth-migrations/", "supabase/recovery/"))
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
            def job_sets(item):
                if (item.get("path") != ".github/workflows/cd.yml"
                        or item.get("head_branch") != "main"
                        or item.get("event") not in ("push", "workflow_dispatch")
                        or not re.fullmatch(r"[0-9a-f]{40}", item.get("head_sha", ""))
                        or not isinstance(item.get("run_attempt"), int) or item["run_attempt"] < 1):
                    raise MigrationProofError("Unverified migration attempt")
                jobs = api(f"actions/runs/{item['id']}/attempts/{item['run_attempt']}/jobs?per_page=100")
                if jobs["total_count"] != len(jobs["jobs"]) or not jobs["jobs"]:
                    raise MigrationProofError("Incomplete migration job inventory")
                return ({job["name"] for job in jobs["jobs"]},
                        {job["name"] for job in jobs["jobs"] if job["conclusion"] == "success"})

            def read_only(names):
                return any(names <= pair | {"Verify migration release"}
                           and any(name.endswith("Staging") for name in names & pair)
                           for pair in (
                               {"Preflight Staging", "Preflight Production"},
                               {"Recovery Preflight Staging", "Recovery Preflight Production"},
                           ))

            # Older runs can be rerun after newer ones. Classify named read-only
            # preflights before waiting on potentially mutating attempts.
            pending = False
            for item in runs:
                if item["status"] != "completed" and not read_only(job_sets(item)[0]):
                    pending = True
                    break
            if not pending:
                baseline = None
                for item in sorted(runs, key=lambda item: item["updated_at"], reverse=True):
                    names, success = job_sets(item)
                    if read_only(names):
                        continue
                    if (item["conclusion"] != "success" or not any(pair <= success for pair in (
                            {"Migrate Staging", "Migrate Production"},
                            {"Recover Staging", "Recover Production"}))):
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
