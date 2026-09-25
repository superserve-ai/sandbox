#!/usr/bin/env python3
"""Deploy the proxy binary to every compute instance tagged with the
configured label, in parallel.

Env vars:
  GCP_PROJECT                required — project containing vmd hosts
  GCP_REGION                 required — restrict discovery to this region
  EXPECTED_STANDBY_HOST      optional — exact identity from select-deploy-target.sh
  VMD_LABEL                  required — gcloud instances list label filter
  SHA                        required — immutable revision identity
  PROXY_ROLLOUT_ID           stable retry identity; overrides the CI run ID
  PROXY_ROLLOUT_MANIFESTS    required — Terraform proxy_generation_rollout JSON output
  PROXY_OPERATION            optional — deploy (default) or bootstrap before frontend migration
  PROXY_TARGET               optional — serving (default) or non-serving standby
  PROXY_DRAIN_GRACE          optional — defaults to 30s, maximum 10m
  PROXY_DOMAIN               required — host suffix the proxy serves (e.g. sandbox.superserve.ai)
  PROXY_DOMAINS              optional — comma-separated host suffixes; overrides
                             PROXY_DOMAIN on the proxy when set (DNS transitions)
  SANDBOX_ACCESS_TOKEN_SEED  optional — hex, >=32 bytes (>=64 hex chars)
  PROXY_DATABASE_URL        required when routing is enabled — dedicated read-only connection
  PROXY_ALLOWED_ORIGINS      optional — comma-separated origin patterns
  REQUIRE_DATA_PLANE         optional — "", "0", or "1"
  PEER_PROXY_TARGET_ADDR     optional — loopback address for peer ingress
  SENTRY_DSN                 optional — Sentry DSN URL for error reporting
  PEER_IDENTITY_HOSTS        optional — comma-separated hosts requiring identity bootstrap
  EXPECTED_STANDBY_HOST      optional — require exactly this deployment host
  PEER_PROXY_LISTEN_ADDR     optional — private mTLS listener (auto or private IP:port)
  PEER_PROXY_TARGET_ADDR     optional — loopback target; defaults to 127.0.0.1:5010
  Peer identity and certificate paths are supplied by host bootstrap.
"""

import json
import tempfile
import uuid
import os
import re
import shlex
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed


def verify_frontend_references(config):
    """Verify the bounded, applied frontend inventory from Terraform.

    The migration acknowledgement is not evidence that a frontend switched.
    Compare every declared route with the backend references read from the
    applied frontend resources before authorizing a recurring rollout.
    """
    routes = config.get("routes")
    references = config.get("frontend_backend_references")
    if not isinstance(routes, list) or not isinstance(references, dict):
        raise ValueError("Terraform migration output must include frontend_backend_references")
    if not 1 <= len(routes) <= 8 or len(references) > 8:
        raise ValueError("Terraform migration output exceeds the route bound")

    expected = {}
    for route in routes:
        if not isinstance(route, dict):
            raise ValueError("Terraform migration output contains an invalid route")
        name = route.get("name") or route.get("backend")
        backend = route.get("backend_self_link") or route.get("backend")
        if not isinstance(name, str) or not name or not isinstance(backend, str) or not backend:
            raise ValueError("Terraform migration output route is missing its backend identity")
        if name in expected:
            raise ValueError(f"duplicate frontend route {name}")
        expected[name] = backend

    frontend_resources = config.get("frontend_resources")
    if frontend_resources is not None:
        if (not isinstance(frontend_resources, dict)
                or set(frontend_resources) != set(expected)):
            raise ValueError("frontend resource inventory must cover every declared route")
        for name, resources in frontend_resources.items():
            if (not isinstance(resources, list) or not 1 <= len(resources) <= 16
                    or any(not isinstance(resource, str) or not resource for resource in resources)):
                raise ValueError(f"frontend route {name} is missing its adopted resource inventory")

    if set(references) != set(expected):
        missing = sorted(set(expected) - set(references))
        extra = sorted(set(references) - set(expected))
        raise ValueError(f"frontend references do not cover declared routes (missing={missing}, extra={extra})")

    for name, backend in expected.items():
        applied = references[name]
        if isinstance(applied, str):
            applied = [applied]
        if (not isinstance(applied, list) or len(applied) > 16 or not applied
                or any(reference != backend for reference in applied)):
            raise ValueError(f"frontend route {name} does not reference replacement backend {backend}")


def main() -> int:
    mode = os.environ.get("PROXY_DEPLOYMENT_MODE", "generation")
    if mode == "legacy":
        if os.environ.get("PROXY_OPERATION", "deploy") != "deploy":
            raise ValueError("legacy deployments cannot bootstrap generations")
        import runpy
        from pathlib import Path
        return runpy.run_path(str(Path(__file__).with_name("deploy-proxy-legacy.py")))["main"]()
    if mode != "generation":
        raise ValueError("unknown proxy deployment mode")
    project = os.environ["GCP_PROJECT"]
    region = os.environ.get("GCP_REGION", "")
    if not region.strip():
        print("ERROR: GCP_REGION is required; refusing unscoped deployment", file=sys.stderr)
        return 1
    expected_standby = os.environ.get("EXPECTED_STANDBY_HOST", "")
    label = os.environ.get("VMD_LABEL", "component=vmd")
    sha = os.environ["SHA"][:8]

    proxy_domain = os.environ.get("PROXY_DOMAIN", "")
    if not proxy_domain:
        print("ERROR: PROXY_DOMAIN is required", file=sys.stderr)
        return 1
    if not re.fullmatch(r"[A-Za-z0-9.\-]+", proxy_domain):
        print("ERROR: PROXY_DOMAIN contains disallowed characters", file=sys.stderr)
        return 1
    # Optional multi-domain set for DNS/hostname transitions; the proxy
    # prefers PROXY_DOMAINS over PROXY_DOMAIN when both are present.
    # Validated per-entry (not as one blob) so a space-separated list
    # fails loudly here instead of deploying a domain string that can
    # never match a Host — the proxy only splits on commas.
    proxy_domains = os.environ.get("PROXY_DOMAINS", "")
    for entry in filter(None, (s.strip() for s in proxy_domains.split(","))):
        if not re.fullmatch(r"[A-Za-z0-9.\-]+", entry):
            print("ERROR: PROXY_DOMAINS contains an invalid domain", file=sys.stderr)
            return 1
    access_seed = os.environ.get("SANDBOX_ACCESS_TOKEN_SEED", "")
    if access_seed and not re.fullmatch(r"[0-9a-fA-F]{64,}", access_seed):
        print("ERROR: SANDBOX_ACCESS_TOKEN_SEED must be hex-encoded, >= 32 bytes (64 hex chars)", file=sys.stderr)
        return 1
    peer_routing = os.environ.get("PEER_ROUTING_ENABLED", "") or "0"
    if peer_routing not in ("0", "1"):
        print("ERROR: PEER_ROUTING_ENABLED must be 0 or 1", file=sys.stderr)
        return 1
    database_url = os.environ.get("PROXY_DATABASE_URL", "")
    if peer_routing == "1" and not database_url:
        print("ERROR: PROXY_DATABASE_URL is required for cross-host routing", file=sys.stderr)
        return 1
    terminal_origins = os.environ.get("PROXY_ALLOWED_ORIGINS", "")
    if terminal_origins and not re.fullmatch(r"[A-Za-z0-9.,:/*\-]+", terminal_origins):
        print("ERROR: PROXY_ALLOWED_ORIGINS contains disallowed characters", file=sys.stderr)
        return 1
    require_data_plane = os.environ.get("REQUIRE_DATA_PLANE", "")
    if require_data_plane not in ("", "0", "1"):
        print('ERROR: REQUIRE_DATA_PLANE must be empty, "0", or "1"', file=sys.stderr)
        return 1
    sentry_dsn = os.environ.get("SENTRY_DSN", "")
    peer_identity_hosts = set(filter(None, (host.strip() for host in
        os.environ.get("PEER_IDENTITY_HOSTS", "").split(","))))
    peer_env = {
        key: os.environ.get(key, "") for key in (
            "PEER_PROXY_LISTEN_ADDR", "PEER_PROXY_TARGET_ADDR",
            "PEER_PROXY_CERT_FILE", "PEER_PROXY_KEY_FILE",
            "PEER_PROXY_CA_FILE",
        )
    }
    peer_env["PEER_PROXY_TARGET_ADDR"] = peer_env["PEER_PROXY_TARGET_ADDR"] or "127.0.0.1:5010"
    peer_listen = peer_env["PEER_PROXY_LISTEN_ADDR"]
    peer_transport = peer_routing == "1" or bool(peer_listen)
    for key, default in (
        ("PEER_PROXY_CERT_FILE", "/etc/superserve/peer/tls.crt"),
        ("PEER_PROXY_KEY_FILE", "/etc/superserve/peer/tls.key"),
        ("PEER_PROXY_CA_FILE", "/etc/superserve/peer/ca.crt"),
    ):
        if peer_transport:
            peer_env[key] = peer_env[key] or default
        else:
            # A host without peer ingress or outbound routing must not require
            # identity files just to prepare an otherwise independent proxy.
            peer_env[key] = ""
    if peer_listen not in ("", "auto") and not peer_listen.endswith(":5009"):
        print("ERROR: PEER_PROXY_LISTEN_ADDR must use port 5009", file=sys.stderr)
        return 1
    peer_max_streams = os.environ.get("PEER_PROXY_MAX_STREAMS", "") or "128"
    if not peer_max_streams.isascii() or not peer_max_streams.isdecimal() or not 1 <= int(peer_max_streams) <= 2147483647:
        print("ERROR: PEER_PROXY_MAX_STREAMS must be a positive 32-bit integer", file=sys.stderr)
        return 1
    # Empty = skip: enabling the proxy's OTLP exporter is a per-environment
    # opt-in, matching the vmd deploy's OTEL_ENVIRONMENT convention.
    otel_environment = os.environ.get("OTEL_ENVIRONMENT", "")
    if sentry_dsn and not re.fullmatch(r"https://[A-Za-z0-9@./:_\-]+", sentry_dsn):
        print("ERROR: SENTRY_DSN must be a https:// URL or empty", file=sys.stderr)
        return 1

    result = subprocess.run(
        [
            "gcloud", "compute", "instances", "list",
            f"--project={project}",
            f"--filter=labels.{label}" + ("" if expected_standby else " AND status=RUNNING"),
            "--format=csv[no-heading](name,zone,status,networkInterfaces[0].networkIP)" if expected_standby else "--format=csv[no-heading](name,zone)",
        ],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"ERROR: gcloud instance discovery failed (exit {result.returncode})", file=sys.stderr)
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="" if result.stderr.endswith("\n") else "\n")
        return 1

    instances = [
        {"name": r[0], "zone": r[1], "status": r[2] if len(r) > 2 else "",
         "ip": r[3] if len(r) > 3 else ""}
        for line in result.stdout.strip().splitlines()
        if line.strip()
        for r in [line.strip().split(",")]
    ]

    # A misplaced standby must not become an optional staging absence.
    if expected_standby and any(
        inst["name"] == expected_standby
        and not inst["zone"].split("/")[-1].startswith(f"{region}-")
        for inst in instances
    ):
        print(f"ERROR: standby {expected_standby} found outside expected region {region}", file=sys.stderr)
        return 1

    # Region scoping happens here rather than in the gcloud filter: matching
    # on the zone basename is unambiguous, while gcloud filter matching
    # against zone URIs is easy to get subtly wrong. Zero matches is a hard
    # failure either way — a deploy that silently skips a host is exactly
    # the drift this script exists to prevent.
    instances = [
        inst for inst in instances
        if inst["zone"].split("/")[-1].startswith(f"{region}-")
    ]

    if expected_standby:
        if (not instances and os.environ.get("DEPLOY_EVENT") == "workflow_dispatch"
                and os.environ.get("DEPLOY_ENVIRONMENT") == "production"
                and os.environ.get("DEPLOY_TARGET") == "standby"
                and os.environ.get("DEPLOY_CELL") == "staging"):
            print("No staging standby found; continuing to the selected production standby.")
            return 0
        if (len(instances) != 1 or instances[0]["name"] != expected_standby
                or instances[0]["status"] != "RUNNING"):
            print(f"ERROR: expected exactly one running standby {expected_standby} in {region}", file=sys.stderr)
            return 1

    where = f"{project} ({region})"
    if not instances:
        print(f"No instances with label {label} found in {where}", file=sys.stderr)
        return 1

    operation = os.environ.get("PROXY_OPERATION", "deploy")
    target = (os.environ.get("PROXY_TARGET") or os.environ.get("DEPLOY_TARGET", "serving")) or "serving"
    try:
        if operation not in ("deploy", "bootstrap"):
            raise ValueError("PROXY_OPERATION must be deploy or bootstrap")
        if target not in ("serving", "standby"):
            raise ValueError("PROXY_TARGET must be serving or standby")
        if target == "standby" and operation == "bootstrap":
            raise ValueError("standby deployments cannot run the serving bootstrap operation")
        with open(os.environ["PROXY_ROLLOUT_MANIFESTS"]) as source:
            manifests = json.load(source)
        for inst in instances:
            matches = [manifest for manifest in manifests.values()
                       if manifest["project"] == project and manifest["instance"] == inst["name"]
                       and manifest["zone"] == inst["zone"].split("/")[-1]]
            if not matches and target == "standby":
                # Terraform owns the cell's serving identity and generation
                # routes.  A role-swapped standby is intentionally outside
                # that static host inventory, so reuse the one serving-cell
                # manifest and replace only the host identity for this run.
                candidates = [manifest for manifest in manifests.values()
                              if manifest.get("project") == project
                              and (manifest.get("serving_host", manifest).get("zone")
                                   == inst["zone"].split("/")[-1])]
                if len(candidates) == 1:
                    if not inst.get("ip"):
                        described = subprocess.run(
                            ["gcloud", "compute", "instances", "describe", inst["name"],
                             f"--zone={inst['zone']}", f"--project={project}", "--quiet",
                             "--format=value(networkInterfaces[0].networkIP)"],
                            capture_output=True, text=True,
                        )
                        if described.returncode != 0 or not described.stdout.strip():
                            raise ValueError(f"could not resolve standby IP for {inst['name']}")
                        inst["ip"] = described.stdout.strip().splitlines()[-1]
                    serving = candidates[0]
                    matches = [dict(serving, instance=inst["name"], zone=inst["zone"].split("/")[-1],
                                    ip=inst["ip"])]
            if len(matches) != 1:
                raise ValueError(f"expected exactly one Terraform manifest for {inst['name']}")
            inst["manifest"] = matches[0]
            if operation == "deploy" and target == "serving":
                verify_frontend_references(matches[0])
    except (KeyError, ValueError, OSError, TypeError, AttributeError) as error:
        print(f"ERROR: rollout manifest: {error}", file=sys.stderr)
        return 1

    print(f"Deploying proxy to {len(instances)} instance(s) in {where}")

    # gcloud generates the runner's SSH key on first use. With per-host deploys
    # running in parallel, two hosts can both find it missing and both run
    # ssh-keygen; the loser fails with "already exists". Create it up front,
    # locally, so no single host's reachability gates the others.
    key = os.path.expanduser("~/.ssh/google_compute_engine")
    if not os.path.exists(key):
        os.makedirs(os.path.dirname(key), mode=0o700, exist_ok=True)
        subprocess.run(["ssh-keygen", "-q", "-t", "rsa", "-N", "", "-f", key], check=True)

    def deploy(inst):
        name, zone = inst["name"], inst["zone"]
        host_region = zone.rsplit("/", 1)[-1].rsplit("-", 1)[0]
        tag = f"{name}/{zone}"

        rollout = os.environ.get("PROXY_ROLLOUT_ID") or os.environ.get("GITHUB_RUN_ID")
        if not rollout:
            raise RuntimeError("PROXY_ROLLOUT_ID is required outside CI; reuse it to resume")
        upload = "/tmp/proxy-upload-" + uuid.uuid4().hex
        request = {
            "rollout": rollout, "revision": os.environ["SHA"], "target": target,
            "require_identity": name in peer_identity_hosts,
            "env": {
                "PROXY_DOMAIN": proxy_domain, "PROXY_DOMAINS": proxy_domains,
                "SANDBOX_ACCESS_TOKEN_SEED": access_seed, "PROXY_ALLOWED_ORIGINS": terminal_origins,
                "REQUIRE_DATA_PLANE": require_data_plane, "SENTRY_DSN": sentry_dsn,
                "PEER_ROUTING_ENABLED": peer_routing, "PEER_PROXY_MAX_STREAMS": peer_max_streams,
                "PROXY_DATABASE_URL": database_url if peer_routing == "1" else "", "HOST_REGION": host_region,
                "OTEL_ENVIRONMENT": otel_environment,
                "OTEL_METRICS_ENABLED": "true" if otel_environment else "false",
                "PROXY_DRAIN_GRACE": os.environ.get("PROXY_DRAIN_GRACE", "30s"),
                **peer_env,
            },
        }
        ssh = ["gcloud", "compute", "ssh", name, f"--zone={zone}", f"--project={project}",
               "--quiet", "--tunnel-through-iap"]
        subprocess.run(ssh + ["--command", "install -d -m 0700 " + shlex.quote(upload)], check=True, capture_output=True)
        with tempfile.TemporaryDirectory() as local:
            request_file = os.path.join(local, "request.json")
            with open(request_file, "w") as output:
                json.dump(request, output)
            os.chmod(request_file, 0o600)
            manifest_file = os.path.join(local, "manifest.json")
            with open(manifest_file, "w") as output:
                json.dump(inst["manifest"], output)
            os.chmod(manifest_file, 0o600)
            for src, dst in [
                ("bin/proxy", "proxy"),
                ("deploy/proxy-generation.service", "proxy.service"),
                (".github/workflows/scripts/proxy_rollout.py", "controller.py"),
                ("deploy/refresh-peer-credentials.py", "refresh-peer-credentials.py"),
                (request_file, "request.json"),
                (manifest_file, "manifest.json"),
            ]:
                subprocess.run(["gcloud", "compute", "scp", src, f"{name}:{upload}/{dst}",
                                f"--zone={zone}", f"--project={project}", "--quiet", "--tunnel-through-iap"],
                               check=True, capture_output=True)
        deploy_script = ("set -eu; trap " + shlex.quote("rm -rf " + shlex.quote(upload)) + " EXIT; "
                         + "sudo python3 " + shlex.quote(upload + "/controller.py")
                         + " --manifest " + shlex.quote(upload + "/manifest.json")
                         + (" --bootstrap" if operation == "bootstrap" else "")
                         + " --request " + shlex.quote(upload + "/request.json"))
        r = subprocess.run(
            [
                "gcloud", "compute", "ssh", name,
                f"--zone={zone}", f"--project={project}",
                "--quiet", "--tunnel-through-iap",
                "--command", deploy_script,
            ],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            raise RuntimeError(
                f"proxy not healthy\n"
                f"--- stdout ---\n{r.stdout}\n"
                f"--- stderr ---\n{r.stderr}"
            )
        if operation == "bootstrap":
            result = "bootstrap phase saved; resume the same rollout after Terraform frontend migration"
        elif target == "standby":
            result = "standby generation prepared; serving membership and cutover suppressed"
        else:
            result = "proxy cutover externally verified"
        print(f"[{tag}] {result}")

    failed = []
    with ThreadPoolExecutor(max_workers=len(instances)) as ex:
        futures = {ex.submit(deploy, inst): inst for inst in instances}
        for f in as_completed(futures):
            inst = futures[f]
            try:
                f.result()
            except Exception as e:
                tag = f"{inst['name']}/{inst['zone']}"
                print(f"[{tag}] FAILED: {e}", file=sys.stderr)
                failed.append(tag)

    if failed:
        print(f'Deploy failed on: {", ".join(failed)}', file=sys.stderr)
        return 1

    print(f"Deployed proxy to {len(instances)} instance(s). sha={sha}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
