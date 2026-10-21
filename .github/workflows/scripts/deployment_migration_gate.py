#!/usr/bin/env python3
"""Validate the exact migration source before a deployment prerequisite runs."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from migration_gate import GateError, api, push_ci


# Branch staging may reuse main's migration bundle, never execute branch SQL.
MIGRATION_INPUTS = (
    "supabase/migrations", "supabase/shared-auth-history", "supabase/shared-auth-migrations",
    "supabase/recovery", "scripts/migrate_database.py", "scripts/retained_storage_recovery.py",
    "scripts/recovery_evidence.py", "scripts/migration-requirements.txt",
    "scripts/snapshot_reference_index.py", "scripts/migrate_shared_auth.py",
    ".github/workflows/deployment-migrations.yml",
    ".github/workflows/deploy-api.yml", ".github/workflows/terraform-cd.yml",
    ".github/workflows/scripts/deployment_migration_gate.py",
    ".github/workflows/scripts/migration_gate.py", ".github/workflows/scripts/wait-for-push-ci.py",
)

# Runtime routing is established by the release contract, not secret labels.
SHARED_TARGETS = {"staging": "rifhalqzxgskwajjgipj", "use4": "xompkvadqplatcchfqjq"}
# Accepted-offer consumers require explicit target preparation; see
# deploy/shared-auth-preparation.md. Unrelated deployments retain this baseline.
SHARED_MIGRATIONS = {"authority": "20261016070000", "claims": "20261016174553",
                     "approvals": "20261020224623"}


def check_shared_requirement(env):
    if "SHARED_AUTH_REQUIRED" not in env:
        return  # The standalone inspection workflow has its own selected action.
    caller = env.get("GITHUB_WORKFLOW_REF", "").split("@", 1)[0]
    proxy = env.get("GITHUB_REPOSITORY", "") + "/.github/workflows/deploy-proxy.yml"
    if env["SHARED_AUTH_REQUIRED"] != "true" and caller != proxy:
        raise GateError("Only the proxy deployment may omit shared Auth migrations")


def bundle_identity(root):
    objects = subprocess.check_output(
        ["git", "-C", str(root), "ls-tree", "-r", "-z", "HEAD", "--", *MIGRATION_INPUTS])
    return hashlib.sha256(objects).hexdigest()


def verification_identity(env, target, root):
    if target not in SHARED_TARGETS:
        raise GateError("Unsupported shared Auth target")
    for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        if not re.fullmatch(r"[1-9][0-9]*", env.get(name, "")):
            raise GateError("Missing workflow execution identity")
    for name in ("GITHUB_SHA", "MIGRATION_REVISION"):
        if not re.fullmatch(r"[a-f0-9]{40}", env.get(name, "")):
            raise GateError("Missing exact migration execution revision")
    return dict(run_id=env["GITHUB_RUN_ID"], attempt=env["GITHUB_RUN_ATTEMPT"],
                deployment_revision=env["GITHUB_SHA"], migration_revision=env["MIGRATION_REVISION"],
                target=target, project=SHARED_TARGETS[target], bundle=bundle_identity(root),
                shared_versions=list(SHARED_MIGRATIONS.values()))


def verify_checkout(env, root=Path("migration-source")):
    revision = verify_revision(env)
    checkout = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    if revision != env.get("MIGRATION_REVISION") or checkout != revision:
        raise GateError("Migration source does not match the prerequisite revision")


def apply_shared(env, target, root=Path("migration-source")):
    if env.get("SHARED_AUTH_REQUIRED") != "true":
        raise GateError("Shared Auth prerequisite was not requested")
    verify_checkout(env, root)
    identity = verification_identity(env, target, root)
    for migration, version in SHARED_MIGRATIONS.items():
        result = subprocess.run(
            [sys.executable, str(root / "scripts/migrate_shared_auth.py"), target, "apply",
             "--migration", migration, "--revision", env["MIGRATION_REVISION"],
             "--runtime-project", SHARED_TARGETS[target]],
            capture_output=True, text=True, check=False)
        # The executor reports sanitized categories; never relay driver output.
        if result.returncode:
            raise GateError("Shared Auth migration failed; inspect before retrying")
        evidence = json.loads(result.stdout)
        if evidence != dict(target=target, version=version, state="applied", regional_history_unchanged=True):
            raise GateError("Shared Auth executor did not verify the required migration")
    return identity


def record_receipt(env, target, root=Path("migration-source")):
    identity = verification_identity(env, target, root)
    if json.loads(env.get("SHARED_VERIFICATION", "null")) != identity:
        raise GateError("Shared verification is missing or belongs to another execution")
    return dict(identity, regional_targets=["staging"] if target == "staging" else ["use4", "usw2"])


def verify_receipt(env, target, root=Path(".")):
    expected = dict(verification_identity(env, target, root),
                    regional_targets=["staging"] if target == "staging" else ["use4", "usw2"])
    if json.loads(env.get("MIGRATION_RECEIPT", "null")) != expected:
        raise GateError("Migration receipt is missing, stale or mismatched; re-run all jobs")


def output(name, value):
    with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
        stream.write(f"{name}={json.dumps(value, separators=(',', ':'))}\n")


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
    elif revision != env["GITHUB_SHA"]:
        raise GateError("Deployment revision must match the workflow revision")
    comparison = api(repository, f"compare/{revision}...main")
    if comparison.get("status") not in ("ahead", "identical"):
        raise GateError("Deployment revision is not an ancestor of current main")
    return revision


def require_ci(env):
    check_shared_requirement(env)
    revision = verify_revision(env)
    if not push_ci.wait_for_ci(env["GITHUB_REPOSITORY"], revision, "push"):
        raise GateError("Successful same-revision push CI is required")
    if verify_revision(env) != revision:
        raise GateError("Migration revision changed while waiting for CI")
    return revision


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--verify-revision", action="store_true")
    modes.add_argument("--apply-shared", action="store_true")
    modes.add_argument("--record-receipt", action="store_true")
    modes.add_argument("--verify-receipt", action="store_true")
    parser.add_argument("--target", choices=SHARED_TARGETS)
    args = parser.parse_args()
    try:
        if args.verify_revision:
            verify_checkout(os.environ)
        elif args.apply_shared:
            output("verification", apply_shared(os.environ, args.target))
        elif args.record_receipt:
            output("receipt", record_receipt(os.environ, args.target))
        elif args.verify_receipt:
            verify_receipt(os.environ, args.target)
        else:
            revision = require_ci(os.environ)
            with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
                stream.write(f"migration_revision={revision}\n")
    except (GateError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(str(error) if isinstance(error, GateError) else "Deployment migration verification failed")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
