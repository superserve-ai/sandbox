#!/usr/bin/env python3
"""Validate the exact migration source before a deployment prerequisite runs."""

import argparse
import os
import re
import subprocess

from migration_gate import GateError, api, push_ci


# Branch staging may reuse main's migration bundle, never execute branch SQL.
MIGRATION_INPUTS = (
    "supabase/migrations", "supabase/shared-auth-history", "supabase/shared-auth-migrations",
    "supabase/recovery", "scripts/migrate_database.py", "scripts/retained_storage_recovery.py",
    "scripts/recovery_evidence.py", "scripts/migration-requirements.txt",
)


def verify_revision(env):
    revision = env.get("DEPLOYMENT_REVISION", "")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise GateError("Deployment migrations require an exact revision")
    repository = env["GITHUB_REPOSITORY"]
    resume = env.get("RESUME_RUN_ID", "")
    if env.get("GITHUB_REF") != "refs/heads/main":
        if (env.get("ALLOW_BRANCH_STAGING") != "true" or env.get("DEPLOYMENT_PRODUCTION") != "false"
                or env.get("GITHUB_EVENT_NAME") != "workflow_dispatch" or resume
                or revision != env["GITHUB_SHA"]):
            raise GateError("Only explicit compatible branch staging is supported")
        main = api(repository, "git/ref/heads/main")["object"]["sha"]
        if not re.fullmatch(r"[0-9a-f]{40}", main):
            raise GateError("Could not verify main's migration revision")
        subprocess.run(["git", "fetch", "--quiet", "--no-tags", "--depth=1", "origin", main],
                       check=True, capture_output=True, timeout=30)
        comparison = subprocess.run(["git", "diff", "--quiet", main, revision, "--", *MIGRATION_INPUTS],
                                    capture_output=True, timeout=30)
        if comparison.returncode:
            raise GateError("Branch migration inputs differ from main; refusing branch migrations")
        return main
    if resume:
        if not re.fullmatch(r"[1-9][0-9]*", resume) or env.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
            raise GateError("Only an explicit proxy resume may use an earlier revision")
        run = api(repository, f"actions/runs/{resume}")
        if (run.get("head_sha") != revision or run.get("head_branch") != "main"
                or run.get("path") != ".github/workflows/deploy-proxy.yml"
                or run.get("event") not in ("push", "workflow_dispatch")):
            raise GateError("Resume does not identify the original proxy revision")
        comparison = api(repository, f"compare/{revision}...main")
        if comparison.get("status") not in ("ahead", "identical"):
            raise GateError("Resume revision is not an ancestor of current main")
    elif (revision != env["GITHUB_SHA"]
          or api(repository, "git/ref/heads/main")["object"]["sha"] != revision):
        raise GateError("Main advanced; deployment must be re-evaluated")
    return revision


def require_ci(env):
    revision = verify_revision(env)
    if not push_ci.wait_for_ci(env["GITHUB_REPOSITORY"], revision, "push"):
        raise GateError("Successful same-revision push CI is required")
    if verify_revision(env) != revision:
        raise GateError("Migration revision changed while waiting for CI")
    return revision


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-revision", action="store_true")
    args = parser.parse_args()
    try:
        if args.verify_revision:
            revision = verify_revision(os.environ)
            if revision != os.environ.get("MIGRATION_REVISION"):
                raise GateError("Migration revision changed after the prerequisite gate")
            checkout = subprocess.check_output(
                ["git", "-C", "migration-source", "rev-parse", "HEAD"], text=True).strip()
            if checkout != revision:
                raise GateError("Migration source does not match the deployment revision")
        else:
            revision = require_ci(os.environ)
            with open(os.environ["GITHUB_OUTPUT"], "a") as output:
                output.write(f"migration_revision={revision}\n")
    except (GateError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(str(error) if isinstance(error, GateError) else "Deployment migration verification failed")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
