#!/usr/bin/env python3
"""Bounded Actions entry point for the one-time staging proxy migration."""

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

from check_staging_proxy_frontend_plan import BASE, ROUTES, has_unknown, validate


ROOT = Path(__file__).resolve().parents[1]
TF = ROOT / "infra/envs/staging/us-central1"


def command(*args, capture=False, cwd=None):
    return subprocess.run(args, cwd=cwd, check=True, text=True,
                          stdout=subprocess.PIPE if capture else None).stdout


def host(mode, legacy_frontends_verified=False):
    source = (ROOT / "scripts/staging_proxy_credential_hold.py").read_text()
    result = command("gcloud", "compute", "ssh", "superserve-vmd-staging-2",
                     "--zone=us-central1-a", "--project=rayai-dev", "--tunnel-through-iap", "--quiet",
                     "--command", "sudo python3 -c " + shlex.quote(source) + " " + shlex.quote(mode)
                     + (" --legacy-frontends-verified" if legacy_frontends_verified else ""),
                     capture=True)
    # A fresh Actions runner's gcloud SSH key creation also writes to stdout.
    prefix = "STAGING_PROXY_MIGRATION_STATUS="
    records = [line[len(prefix):] for line in result.splitlines() if line.startswith(prefix)]
    if len(records) != 1:
        raise RuntimeError("Expected exactly one staging migration host status")
    status = json.loads(records[0])
    if not isinstance(status, dict) or status.get("mode") != mode:
        raise RuntimeError("Unexpected staging migration host status")
    print(json.dumps(status), flush=True)
    return status


def legacy_frontends():
    for kind, name, field, legacy in (
        ("url-maps", "sandbox-proxy-url-map", "defaultService", "sandbox-proxy-backend-https"),
        ("target-ssl-proxies", "sandbox-proxy-ssl", "service", "sandbox-proxy-backend"),
        ("target-tcp-proxies", "sandbox-proxy-tcp", "service", "sandbox-proxy-redirect-backend"),
    ):
        resource = json.loads(command("gcloud", "compute", kind, "describe", name,
                                      *([] if kind == "target-ssl-proxies" else ["--global"]),
                                      "--project=rayai-dev", "--format=json", capture=True))
        if resource.get(field) != BASE + legacy:
            raise RuntimeError("Restore all three live frontend references before abort: " + name)


def registered_legacy_endpoints():
    # Unreferenced replacement backends may not be health checked until the
    # first frontend switch. Bootstrap resume requires LB health afterward.
    for _, _, backend in ROUTES.values():
        entries = json.loads(command("gcloud", "compute", "network-endpoint-groups", "list-network-endpoints", backend,
                                     "--zone=us-central1-a", "--project=rayai-dev", "--format=json", capture=True))
        port = 5008 if backend == "proxy-staging-redirect-generations" else 5007
        if len(entries) != 1:
            raise RuntimeError("Expected only the adopted legacy endpoint: " + backend)
        endpoint = entries[0].get("networkEndpoint", {})
        if (endpoint.get("ipAddress") != "10.0.0.3" or endpoint.get("port") != port
                or endpoint.get("instance", "").rsplit("/", 1)[-1] != "superserve-vmd-staging-2"):
            raise RuntimeError("Unexpected adopted endpoint: " + backend)


def validate_drain_plan(plan):
    expected = {f'module.proxy_generations["staging"].google_compute_backend_service.generation["{route}"]': backend
                for route, backend in (("public-http", "proxy-staging-public-http-generations"),
                                       ("public-tcp", "proxy-staging-public-tcp-generations"),
                                       ("redirect", "proxy-staging-redirect-generations"))}
    seen = set()
    for item in plan.get("resource_changes", []):
        if item.get("mode") == "data":
            continue
        change = item["change"]
        if item.get("previous_address") or change.get("importing"):
            raise ValueError("Drain cleanup cannot import or move resources")
        if item["address"] not in expected:
            if change["actions"] != ["no-op"]:
                raise ValueError("Drain cleanup cannot change other resources")
            continue
        seen.add(item["address"])
        before, after = change.get("before") or {}, change.get("after") or {}
        name = expected[item["address"]]
        if (change["actions"] not in (["no-op"], ["update"])
                or has_unknown(change.get("after_unknown", {}))
                or before.get("project") != "rayai-dev" or before.get("name") != name
                or before.get("id") != "projects/rayai-dev/global/backendServices/" + name
                or before.get("connection_draining_timeout_sec") not in (0, 1, 3600)
                or after != dict(before, connection_draining_timeout_sec=1)):
            raise ValueError("Only the three unused staging backend drain timeouts may change")
    if seen != set(expected):
        raise ValueError("Expected all three staging backend drain timeouts")


def expedite_abort():
    # This changes only unused backend settings, never host/controller state.
    # The existing abort retains its lock and still waits for Google's DONE.
    source = '''import json, pathlib, subprocess
root = pathlib.Path('/var/lib/proxy-rollout')
state = json.loads((root / 'state.json').read_text())
receipt = json.loads(pathlib.Path('/run/proxy-generation-migration-receipt.json').read_text())
assert pathlib.Path('/run/proxy-generation-migration-hold').exists()
assert state['phase'] == 'rollback_withdrawing' and not state.get('bootstrap')
assert not state['old']['id'] and state['old']['unit'] == 'proxy.service'
candidate = state['candidate']
assert candidate['id'] and candidate['unit'] == 'proxy-' + candidate['id'] + '.service'
assert candidate['ports'] in ({'public':5100,'redirect':5101,'peer':5102,'local':5103},
                            {'public':5110,'redirect':5111,'peer':5112,'local':5113})
for unit, key in [('superserve-vmd.service','vmd'),('proxy.service','proxy')]:
    actual = subprocess.check_output(['systemctl','show','-p','InvocationID','--value',unit],text=True).strip()
    assert actual == receipt[key]
    subprocess.run(['systemctl','is-active','--quiet',unit],check=True)
connections = subprocess.check_output(['ss','-Htn','state','established'],text=True)
for line in connections.splitlines():
    fields = line.split()
    assert len(fields) >= 4
    assert fields[2].rsplit(':',1)[-1] not in {str(p) for p in candidate['ports'].values()}
print('Failed staging candidate has no established connections; retained services unchanged.')
'''
    def preflight():
        legacy_frontends()
        command("gcloud", "compute", "ssh", "superserve-vmd-staging-2", "--zone=us-central1-a",
                "--project=rayai-dev", "--tunnel-through-iap", "--quiet",
                "--command", "sudo python3 -c " + shlex.quote(source))
    preflight()
    path = ROOT / "infra/modules/proxy-lb/generations.tf"
    text = path.read_text()
    setting = "connection_draining_timeout_sec = 3600"
    if text.count(setting) != 1:
        raise RuntimeError("Unexpected configured generation drain timeout")
    # The provider omits a zero timeout from its update request.
    path.write_text(text.replace(setting, "connection_draining_timeout_sec = 1"))
    command("terraform", "init", "-input=false", cwd=TF)
    command("terraform", "plan", "-input=false", "-lock-timeout=5m", "-out=drain-plan",
            '-target=module.proxy_generations["staging"].google_compute_backend_service.generation', cwd=TF)
    plan = json.loads(command("terraform", "show", "-json", "drain-plan", capture=True, cwd=TF))
    validate_drain_plan(plan)
    preflight()
    command("terraform", "apply", "-input=false", "-lock-timeout=5m", "drain-plan", cwd=TF)
    verify_shortened_drains()
    print("Verified one-second drains on unused staging backends; existing abort still verifies completion.")


def verify_shortened_drains():
    for _, _, backend in ROUTES.values():
        resource = json.loads(command("gcloud", "compute", "backend-services", "describe", backend,
                                      "--global", "--project=rayai-dev", "--format=json", capture=True))
        if resource.get("connectionDraining", {}).get("drainingTimeoutSec") != 1:
            raise RuntimeError("Backend drain timeout did not change: " + backend)


def main(mode):
    if mode == "expedite-abort":
        expedite_abort()
        return
    if mode in ("hold", "release", "abort"):
        if mode in ("hold", "abort"):
            legacy_frontends()
        host(mode, legacy_frontends_verified=mode in ("hold", "abort"))
        return
    if mode not in ("cutover", "rollback"):
        raise ValueError("Unknown staging migration action")
    status = host("check")
    if not status["legacy_running"] or status.get("active_generation"):
        raise RuntimeError("Frontend migration requires the retained legacy proxy")
    if mode == "cutover":
        if status["phase"] != "bootstrap_ready" or not status["legacy_ready"]:
            raise RuntimeError("Bootstrap must register legacy endpoints before the traffic switch")
        registered_legacy_endpoints()
    command("terraform", "init", "-input=false", cwd=TF)
    command("terraform", "validate", cwd=TF)
    targets = ["module.proxy_generations", "google_compute_url_map.proxy", "google_compute_target_https_proxy.proxy",
               "google_compute_target_ssl_proxy.proxy", "google_compute_target_tcp_proxy.redirect",
               "google_compute_global_forwarding_rule.proxy"]
    command("terraform", "plan", "-input=false", "-lock-timeout=5m", "-out=frontend-plan",
            "-var=proxy_generation_frontends_enabled=" + str(mode == "cutover").lower(),
            *("-target=" + target for target in targets), cwd=TF)
    plan = json.loads(command("terraform", "show", "-json", "frontend-plan", capture=True, cwd=TF))
    validate(plan, mode)
    # Recheck the host and prepared health immediately before applying the saved plan.
    if host("check") != status:
        raise RuntimeError("Host state changed while planning")
    if mode == "cutover":
        registered_legacy_endpoints()
    command("terraform", "apply", "-input=false", "-lock-timeout=5m", "frontend-plan", cwd=TF)
    manifests = json.loads(command("terraform", "output", "-json", "proxy_generation_rollout", capture=True, cwd=TF))
    if (set(manifests) != {"staging"} or manifests["staging"]["project"] != "rayai-dev"
            or manifests["staging"]["migration_complete"] != (mode == "cutover")):
        raise RuntimeError("Applied frontend manifest does not match the requested migration")
    host("check")
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
        summary.write(f"Staging frontend {mode} applied; VMD invocation unchanged.\n")


if __name__ == "__main__":
    main(sys.argv[1])
