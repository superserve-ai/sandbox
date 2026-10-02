"""Verify an authenticated read-only observation before retained recovery.

The collector is a separate operational prerequisite. This verifier never
registers SSH keys, provisions access, or treats a sampling flag as exclusion.
"""

import datetime
import hashlib
import io
import json
import re
import subprocess
import time
import zipfile

from migrate_database import MigrationError

COLLECTOR_WORKFLOW = ".github/workflows/recovery-evidence.yml"
MAX_AGE_SECONDS = 120
MAX_BYTES = 2_000_000
# This source has neither the retained API receiver nor the retained publisher
# field. Adding an admitted build requires source and persisted-replay review.
AUDITED_SOURCE = "7bfa1da7f8b18ccf7bc25feaf3fc8640ae2cc690"
PROJECT = "rayai-prod"
REGION = "us-west2"
SERVICE = "superserve-api-usw2"


def require(condition, message):
    if not condition:
        raise MigrationError(message)


def sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def command(args, deadline, *, binary=False):
    remaining = deadline - time.monotonic()
    require(remaining > 0, "Recovery evidence deadline exceeded")
    result = subprocess.run(args, capture_output=True, timeout=min(remaining, 15), text=not binary)
    require(result.returncode == 0, "Authenticated read-only observation failed; no output logged")
    return result.stdout


def timestamp(value):
    dt = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(dt.tzinfo is not None, "Evidence timestamps must include a timezone")
    return dt.timestamp()


def inventory(deadline):
    # Inspect every revision, including tagged, draining and zero-traffic ones.
    # The conservative admission below requires every observed revision to be
    # an audited incapable build, rather than inferring absence from traffic.
    service = json.loads(command(["gcloud", "run", "services", "describe", SERVICE,
                                  "--project", PROJECT, "--region", REGION, "--format=json"], deadline))
    revisions = json.loads(command(["gcloud", "run", "revisions", "list", "--service", SERVICE,
                                    "--project", PROJECT, "--region", REGION, "--format=json"], deadline))
    hosts = json.loads(command(["gcloud", "compute", "instances", "list", "--project", PROJECT,
                               "--format=json"], deadline))
    require(isinstance(service, dict) and isinstance(revisions, list) and revisions and isinstance(hosts, list),
            "Cloud observation is incomplete")
    # Use the complete project instance inventory so an unlabelled/standby host
    # cannot disappear through a deployment script's narrower label filter.
    return {"service": service, "revisions": revisions, "instances": hosts}


def validate(document, *, revision, plan_hash, database_project, current, now):
    require(document.get("schema") == 1 and document.get("target") == "usw2"
            and document.get("recovery_revision") == revision and document.get("plan_hash") == plan_hash
            and document.get("database_project") == database_project,
            "Evidence does not identify this recovery revision, plan and database")
    start, end = timestamp(document["started_at"]), timestamp(document["completed_at"])
    require(now - MAX_AGE_SECONDS <= start <= end <= now, "Deployment evidence is stale or future dated")
    require(document.get("collector_revision") == revision, "Collector revision mismatch")
    require(document.get("inventory_before") == document.get("inventory_after") == sha(current),
            "Deployment inventory changed or evidence coverage is incomplete")
    require(document.get("project") == PROJECT and document.get("region") == REGION
            and document.get("service") == SERVICE, "Evidence cloud target mismatch")
    revisions = document.get("revisions", [])
    observed = {r["metadata"]["name"] for r in current["revisions"]}
    require({r.get("name") for r in revisions} == observed and len(revisions) == len(observed),
            "Evidence must cover every revision, including background and tagged revisions")
    for item in revisions:
        require(item.get("source_commit") == AUDITED_SOURCE
                and re.fullmatch(r"sha256:[a-f0-9]{64}", item.get("image_digest", ""))
                and item.get("build_provenance_verified") is True,
                "Revision is not an authenticated audited incapable build")
        actual = next(r for r in current["revisions"] if r["metadata"]["name"] == item["name"])
        actual_image = actual.get("status", {}).get("imageDigest", "")
        require(actual_image.rsplit("@", 1)[-1] == item["image_digest"], "Revision image changed")
        containers = actual.get("spec", {}).get("containers", [])
        require(len(containers) == 1 and not containers[0].get("command") and not containers[0].get("args"),
                "Unaudited sidecars or command overrides prevent writer exclusion")
    lifecycle = document.get("revision_lifecycle_audit", {})
    require(timestamp(lifecycle["started_at"]) <= start - 600
            and timestamp(lifecycle["completed_at"]) >= end
            and lifecycle.get("complete") is True and lifecycle.get("deleted_revisions") == [],
            "Recent revision deletion or incomplete drain coverage prevents recovery")
    hosts = document.get("hosts", [])
    instances = {str(item["id"]): item for item in current["instances"]}
    require({str(h.get("instance_id")) for h in hosts} == set(instances) and len(hosts) == len(instances),
            "Host evidence must cover the full instance inventory")
    for host in hosts:
        instance = instances[str(host["instance_id"])]
        require(host.get("instance_name") == instance["name"] and host.get("zone") == instance["zone"],
                "Host identity changed")
        require(host.get("authenticated_read_route") and host.get("key_or_metadata_mutation") is False
                and host.get("complete_process_inventory") is True,
                "Host observation requires established non-mutating authenticated access")
        services = host.get("report_services")
        require(isinstance(services, list), "Restart-capable report services were not inventoried")
        by_service = {s["service_id"]: s for s in services}
        require(len(by_service) == len(services), "Ambiguous report service inventory")
        for service in services:
            require(service.get("source_commit") == AUDITED_SOURCE
                    and service.get("build_provenance_verified") is True
                    and service.get("automatic_downloads") is False and service.get("in_progress_rollout") is False
                    and all(re.fullmatch(r"[a-f0-9]{64}", service.get(key, ""))
                            for key in ("executable_sha256", "unit_sha256", "configuration_sha256")),
                    "A restart source may introduce a retained-capable writer")
        processes = host.get("report_processes")
        require(isinstance(processes, list), "Running report process inventory is missing")
        for process in processes:
            require(process.get("source_commit") == AUDITED_SOURCE
                    and re.fullmatch(r"[a-f0-9]{64}", process.get("executable_sha256", ""))
                    and process.get("build_provenance_verified") is True
                    and process.get("start_time") and process.get("incarnation_id")
                    and process.get("destination_database") == database_project
                    and process.get("service_id") in by_service
                    and process.get("executable_sha256") == by_service[process["service_id"]]["executable_sha256"],
                    "A host process may produce or replay retained reports")
        require(set(host.get("spools", {})) == {".storage-report-queue", ".storage-report-queue.v2", ".storage-report-queue.migrating/state.json"}
                and all(s.get("retained_payloads") == 0 and s.get("complete_scan") is True
                        for s in host["spools"].values()),
                "Retained spool coverage is missing or contains retained payloads")
    require(document.get("alternate_producers") == [] and document.get("complete_writer_inventory") is True,
            "Alternate or unobserved writers prevent recovery")
    require(document.get("deployment_and_toggle_hold", {}).get("revision") == revision
            and document["deployment_and_toggle_hold"].get("active") is True,
            "The separately coordinated deployment and configuration hold is missing")


class Observation:
    def __init__(self, *, repository, revision, run_id, plan_hash, database_project, deadline):
        require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository or "")
                and re.fullmatch(r"[a-f0-9]{40}", revision or "")
                and re.fullmatch(r"[1-9][0-9]*", run_id or ""),
                "Recovery is blocked: supply a successful authenticated read-only evidence collection run")
        self.repository, self.revision, self.run_id = repository, revision, run_id
        self.plan_hash, self.database_project, self.deadline = plan_hash, database_project, deadline
        self.artifact_digest = None
        self.state_digest = None
        self.valid_until = None

    def api(self, path, binary=False):
        return command(["gh", "api", f"repos/{self.repository}/{path}"], self.deadline, binary=binary)

    def verify(self):
        run = json.loads(self.api(f"actions/runs/{self.run_id}"))
        require(run.get("head_sha") == self.revision and run.get("head_branch") == "main"
                and run.get("path") == COLLECTOR_WORKFLOW and run.get("event") == "workflow_dispatch"
                and run.get("status") == "completed" and run.get("conclusion") == "success"
                and run.get("repository", {}).get("full_name") == self.repository,
                "Evidence must come from the reviewed same-revision read-only collection workflow")
        artifacts = json.loads(self.api(f"actions/runs/{self.run_id}/artifacts?per_page=100"))
        matching = [a for a in artifacts["artifacts"] if a.get("name") == "retained-recovery-evidence-usw2"]
        require(len(matching) == 1, "A unique recovery evidence artifact is required")
        artifact = matching[0]
        require(not artifact.get("expired") and 0 < artifact.get("size_in_bytes", 0) <= MAX_BYTES,
                "Recovery evidence artifact is unavailable or oversized")
        data = self.api(f"actions/artifacts/{int(artifact['id'])}/zip", binary=True)
        require(len(data) <= MAX_BYTES, "Recovery evidence download is oversized")
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        require(digest == artifact.get("digest") and (self.artifact_digest is None or digest == self.artifact_digest),
                "Recovery evidence artifact integrity changed")
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            require(archive.namelist() == ["evidence.json"] and archive.getinfo("evidence.json").file_size <= MAX_BYTES,
                    "Recovery evidence archive shape is invalid")
            document = json.loads(archive.read("evidence.json"))
        current = inventory(self.deadline)
        validate(document, revision=self.revision, plan_hash=self.plan_hash, database_project=self.database_project,
                 current=current, now=time.time())
        state_digest = sha({key: document[key] for key in (
            "inventory_after", "revisions", "hosts", "alternate_producers", "deployment_and_toggle_hold")})
        require(self.state_digest is None or self.state_digest == state_digest,
                "Observed writer state changed during recovery")
        self.valid_until = timestamp(document["started_at"]) + MAX_AGE_SECONDS
        self.state_digest = state_digest
        self.artifact_digest = digest
