#!/usr/bin/env python3
"""Temporary read-only staging inventory for the template-build smoke test."""
import json
import os
import subprocess
from urllib.parse import urlsplit
from urllib.error import HTTPError
from urllib.request import Request, urlopen


PROJECT = "rayai-dev"
ZONE = "us-central1-a"
INSTANCES = ("superserve-vmd-staging", "superserve-vmd-staging-2")
PERMISSIONS = ("compute.instances.get", "compute.instances.stop", "compute.instances.start")

SQL = """SELECT json_build_object(
 'latest_migration', (SELECT max(version) FROM supabase_migrations.schema_migrations),
 'execution_schema', to_regclass('public.template_build_execution') IS NOT NULL,
 'active_builds', (SELECT count(*) FROM template_build WHERE status IN ('pending','building','snapshotting')),
 'hosts', (SELECT coalesce(json_agg(row_to_json(x)), '[]') FROM (
   SELECT h.id,h.status,h.region,h.vmd_addr,h.identity_bound,
     h.incarnation_id IS NOT NULL AS has_incarnation,
     coalesce(h.last_heartbeat_at > now()-interval '2 minutes',false) AS heartbeat_fresh,
     EXISTS(SELECT 1 FROM host_capability c WHERE c.host_id=h.id
       AND c.capability='template_build_v1' AND c.heartbeat_at=h.last_heartbeat_at) AS build_capable,
     coalesce(p.reported_at > now()-interval '90 seconds',false) AS pressure_fresh,
     p.running_sandboxes,p.provisioning_sandboxes,p.paused_sandboxes,p.unknown_allocation_vms,
     (SELECT count(*) FROM sandbox s WHERE s.host_id=h.id AND s.destroyed_at IS NULL) AS retained_sandboxes,
     (SELECT json_object_agg(status,n) FROM (
       SELECT s.status,count(*) AS n FROM sandbox s WHERE s.host_id=h.id AND s.destroyed_at IS NULL
       GROUP BY s.status) counts) AS sandboxes_by_status
   FROM host h LEFT JOIN host_pressure p ON p.host_id=h.id ORDER BY h.id
 ) x))"""


def capture(command, env=None):
    try:
        result = subprocess.run(command, env=env, text=True, capture_output=True, timeout=45)
    except (subprocess.TimeoutExpired, OSError):
        raise RuntimeError(f"{command[0]} preflight command did not complete") from None
    if result.returncode:
        # A failed connection can include credentials in diagnostic output.
        for diagnostic in ("unsupported startup parameter", "Tenant or user not found",
                           "password authentication failed", "Network is unreachable",
                           "could not translate host name", "Connection refused",
                           "connection timed out", "invalid URI query parameter"):
            if diagnostic.lower() in result.stderr.lower():
                raise RuntimeError(f"{command[0]} preflight: {diagnostic}")
        raise RuntimeError(f"{command[0]} preflight command failed (exit {result.returncode})")
    return json.loads(result.stdout)


def require_staging(env):
    if env.get("DEPLOY_ENVIRONMENT") != "staging" or env.get("GCP_PROJECT") != PROJECT:
        raise RuntimeError("preflight requires the staging environment and project")
    if not env.get("DATABASE_URL"):
        raise RuntimeError("staging database secret is not configured")


def cloud(*args):
    return capture(["gcloud", *args, f"--project={PROJECT}", "--format=json", "--quiet"])


def instance_permissions(name):
    token = subprocess.run(["gcloud", "auth", "print-access-token"], capture_output=True,
                           text=True, timeout=30)
    if token.returncode:
        raise RuntimeError("could not authenticate staging permission check")
    request = Request(
        f"https://compute.googleapis.com/compute/v1/projects/{PROJECT}/zones/{ZONE}/instances/{name}/testIamPermissions",
        data=json.dumps({"permissions": PERMISSIONS}).encode(),
        headers={"Authorization": "Bearer " + token.stdout.strip(), "Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=30) as response:
            granted = json.load(response).get("permissions", [])
    except HTTPError as error:
        raise RuntimeError(f"instance permission check failed (HTTP {error.code})") from None
    return {permission: permission in granted for permission in PERMISSIONS}


def main():
    require_staging(os.environ)
    snapshot = capture(["psql", "--dbname", os.environ["DATABASE_URL"], "-XqAt", "-v", "ON_ERROR_STOP=1", "-c",
                        "BEGIN READ ONLY; SET LOCAL statement_timeout='10s'; " + SQL + "; COMMIT;"], env=dict(
        os.environ, PGCONNECT_TIMEOUT="10",
        PGOPTIONS=""))
    instances = []
    addresses = {}
    for name in INSTANCES:
        instance = cloud("compute", "instances", "describe", name, f"--zone={ZONE}")
        for interface in instance.get("networkInterfaces", []):
            addresses[interface["networkIP"]] = name
        instances.append({"name": name, "status": instance["status"],
                          "component": instance.get("labels", {}).get("component"),
                          "permissions": instance_permissions(name)})
    for host in snapshot["hosts"]:
        address = urlsplit("//" + host.pop("vmd_addr")).hostname
        host["instance"] = addresses.get(address)
    service = cloud("run", "services", "describe", "superserve-api", "--region=us-central1")
    container = service["spec"]["template"]["spec"]["containers"][0]
    settings = {item["name"]: item.get("value", "<secret reference>")
                for item in container.get("env", [])
                if item["name"] in ("TEMPLATE_BUILD_REGION", "BACKUP_BUCKET")}
    snapshot.update(instances=instances, build_settings=settings,
                    api_revision=service["status"].get("latestReadyRevisionName"),
                    api_image=container["image"])
    print(json.dumps(snapshot, indent=2))


if __name__ == "__main__":
    main()
