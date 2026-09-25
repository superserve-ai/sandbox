#!/usr/bin/env python3
"""Deploy the proxy binary to every compute instance tagged with the
configured label, in parallel.

Env vars:
  GCP_PROJECT                required — project containing vmd hosts
  GCP_REGION                 required — restrict discovery to this region
  EXPECTED_STANDBY_HOST      optional — exact identity from select-deploy-target.sh
  VMD_LABEL                  required — gcloud instances list label filter
  VMD_INSTALL_DIR            required — bin install dir on the host
  SHA                        required — commit SHA (only first 8 chars used)

This compatibility path retains socket-activated legacy listeners and never changes VMD.
  PROXY_DOMAIN               required — host suffix the proxy serves (e.g. sandbox.superserve.ai)
  PROXY_DOMAINS              optional — comma-separated host suffixes; overrides
                             PROXY_DOMAIN on the proxy when set (DNS transitions)
  SANDBOX_ACCESS_TOKEN_SEED  optional — hex, >=32 bytes (>=64 hex chars)
  PROXY_DATABASE_URL        required when routing is enabled — dedicated read-only connection
  PROXY_ALLOWED_ORIGINS      optional — comma-separated origin patterns
  REQUIRE_DATA_PLANE         optional — "", "0", or "1"
  PEER_PROXY_TARGET_ADDR     optional — loopback address for peer ingress
  PEER_PROXY_SPIFFE_URI      required — authorized peer certificate URI
  SENTRY_DSN                 optional — Sentry DSN URL for error reporting
  PEER_IDENTITY_HOSTS        optional — comma-separated hosts requiring identity bootstrap
  EXPECTED_STANDBY_HOST      optional — require exactly this deployment host
  PEER_PROXY_LISTEN_ADDR     optional — private mTLS listener (auto or private IP:port)
  PEER_PROXY_TARGET_ADDR     optional — loopback target; defaults to 127.0.0.1:5010
  Peer identity and certificate paths are supplied by host bootstrap.
"""

import os
import re
import shlex
import subprocess
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor, as_completed


def main() -> int:
    project = os.environ["GCP_PROJECT"]
    region = os.environ.get("GCP_REGION", "")
    if not region.strip():
        print("ERROR: GCP_REGION is required; refusing unscoped deployment", file=sys.stderr)
        return 1
    expected_standby = os.environ.get("EXPECTED_STANDBY_HOST", "")
    label = os.environ.get("VMD_LABEL", "component=vmd")
    # The installed unit is superserve-vmd.service; retain an override for
    # environments that use a deliberately different unit name.
    service = os.environ.get("VMD_SERVICE", "superserve-vmd")
    install_dir = os.environ.get("VMD_INSTALL_DIR", "/usr/local/bin")
    sha = os.environ["SHA"][:8]
    if not re.fullmatch(r"[a-zA-Z0-9_/-]+", install_dir) or not install_dir.startswith("/"):
        raise ValueError("invalid proxy install directory")
    if not re.fullmatch(r"[a-zA-Z0-9_.@-]+", service):
        raise ValueError("invalid VMD unit")
    if not re.fullmatch(r"[0-9a-f]{8}", sha):
        raise ValueError("invalid revision")

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
    database_env_line = ('PROXY_DATABASE_URL="' + database_url.replace('\\', '\\\\').replace('"', '\\"') + '"') if peer_routing == "1" else ""
    database_env_command = ("printf '%s\\n' " + shlex.quote(database_env_line) + " | sudo tee -a /etc/sandbox/proxy.env > /dev/null") if database_env_line else ":"
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
    for key, default in (
        ("PEER_PROXY_CERT_FILE", "/etc/superserve/peer/tls.crt"),
        ("PEER_PROXY_KEY_FILE", "/etc/superserve/peer/tls.key"),
        ("PEER_PROXY_CA_FILE", "/etc/superserve/peer/ca.crt"),
    ):
        peer_env[key] = default
    peer_listen = peer_env["PEER_PROXY_LISTEN_ADDR"]
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
    otel_env_lines = ""
    if otel_environment:
        otel_env_lines = (
            "\n            OTEL_METRICS_ENABLED=true"
            f"\n            OTEL_ENVIRONMENT={otel_environment}"
        )
    if sentry_dsn and not re.fullmatch(r"https://[A-Za-z0-9@./:_\-]+", sentry_dsn):
        print("ERROR: SENTRY_DSN must be a https:// URL or empty", file=sys.stderr)
        return 1

    result = subprocess.run(
        [
            "gcloud", "compute", "instances", "list",
            f"--project={project}",
            f"--filter=labels.{label}" + ("" if expected_standby else " AND status=RUNNING"),
            "--format=csv[no-heading](name,zone,status)" if expected_standby else "--format=csv[no-heading](name,zone)",
        ],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"ERROR: gcloud instance discovery failed (exit {result.returncode})", file=sys.stderr)
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="" if result.stderr.endswith("\n") else "\n")
        return 1

    instances = [
        {"name": r[0], "zone": r[1], "status": r[2] if len(r) > 2 else ""}
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

        for src, dst in [
            ("bin/proxy", f"/tmp/proxy-{sha}"),
            (".github/workflows/scripts/legacy_proxy_preflight.py", f"/tmp/legacy-proxy-preflight-{sha}.py"),
            ("deploy/proxy.service", "/tmp/proxy.service"),
            ("deploy/proxy.socket", "/tmp/proxy.socket"),
        ]:
            subprocess.run(
                [
                    "gcloud", "compute", "scp", src, f"{name}:{dst}",
                    f"--zone={zone}", f"--project={project}",
                    "--quiet", "--tunnel-through-iap",
                ],
                check=True, capture_output=True,
            )
        print(f"[{tag}] proxy uploaded")

        deploy_script = textwrap.dedent(f"""
            set -euo pipefail

            # Match VMD's environment precedence. Only legacy hosts without an
            # installed identity may fall back to vmd.env or the instance name.
            if sudo test -e /etc/sandbox/host-identity.env; then
                host_id=$(sudo sed -n 's/^HOST_ID=//p' /etc/sandbox/host-identity.env)
                if ! [[ "$host_id" =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]{{0,255}}$ ]]; then
                    echo 'ERROR: invalid installed host identity environment' >&2
                    exit 1
                fi
            else
                host_id=$(sudo sed -n 's/^HOST_ID=//p' /etc/sandbox/vmd.env 2>/dev/null | tail -n1 || true)
            fi

            peer_identity=""
            if sudo test -f /etc/superserve/peer/identity.json; then
                # Shared with the refresh worker through systemd credential load.
                exec 9< /run/lock/vmd-peer-credentials.lock
                flock -s 9
                peer_identity=$(sudo python3 -c 'import json; print(json.load(open("/etc/superserve/peer/identity.json"))["spiffe_uri"])')
                if ! [[ "$peer_identity" =~ ^spiffe://[A-Za-z0-9._:/-]+$ ]]; then
                    echo 'ERROR: invalid infrastructure peer identity' >&2
                    exit 1
                fi
                sudo /usr/local/sbin/refresh-peer-credentials --check
            elif [ "{int(name in peer_identity_hosts)}" -eq 1 ]; then
                echo 'ERROR: host requires infrastructure identity bootstrap' >&2
                exit 1
            elif ! sudo test -s /etc/sandbox/proxy.env; then
                # Legacy peer identity lives in proxy.env. A rebuilt host must
                # restore it or bootstrap before deployment can preserve mTLS.
                echo 'ERROR: restore the legacy proxy.env or bootstrap host identity before deployment' >&2
                exit 1
            fi

            peer_listen_addr=$(sudo python3 /tmp/legacy-proxy-preflight-{sha}.py {shlex.quote(peer_listen)} {shlex.quote(service)})
            vmd_invocation=$(systemctl show -p InvocationID --value {service})
            sudo mkdir -p /etc/sandbox
            rollback_dir=$(sudo mktemp -d /etc/sandbox/proxy-rollback.XXXXXX)
            for config in {install_dir}/proxy /etc/systemd/system/proxy.service /etc/systemd/system/proxy.socket /etc/sandbox/proxy.env /etc/systemd/system/proxy.service.d/peer-credentials.conf; do
                if sudo test -f "$config"; then
                    sudo cp -p "$config" "$rollback_dir/$(basename "$config")"
                fi
            done

            rollback_proxy() {{
                # Restore the executable and configuration together; an older
                # binary may not accept the new environment.
                for config in {install_dir}/proxy /etc/systemd/system/proxy.service /etc/systemd/system/proxy.socket /etc/sandbox/proxy.env /etc/systemd/system/proxy.service.d/peer-credentials.conf; do
                    if sudo test -f "$rollback_dir/$(basename "$config")"; then
                        # Rename avoids overwriting a running executable in place.
                        sudo cp -p "$rollback_dir/$(basename "$config")" "$config.restore-{sha}" || return 1
                        sudo mv "$config.restore-{sha}" "$config" || return 1
                    else
                        sudo rm -f "$config" || return 1
                    fi
                done
                sudo systemctl daemon-reload || return 1
                # The restored unit must be the one bound: a build that binds
                # the ports itself needs the socket gone, and a restored unit
                # file only takes effect through a restart of the socket.
                if ! sudo test -f "$rollback_dir/proxy.socket"; then
                    sudo systemctl disable --now proxy.socket 2>/dev/null || true
                else
                    sudo systemctl stop proxy proxy.socket 2>/dev/null || true
                    sudo systemctl start proxy.socket || return 1
                fi
                if ! sudo test -f "$rollback_dir/proxy" || ! sudo test -f "$rollback_dir/proxy.service"; then
                    sudo systemctl stop proxy || return 1
                elif ! sudo systemctl restart proxy || ! sudo systemctl is-active --quiet proxy; then
                    echo "ERROR: proxy restart failed during rollback" >&2
                    sudo journalctl -u proxy --no-pager -n 40 >&2 || true
                    return 1
                fi
            }}
            deployment_mutated=0
            finish_deployment() {{
                result=$?
                trap - EXIT
                if [ "$result" -ne 0 ] && [ "$deployment_mutated" -eq 1 ]; then
                    if ! rollback_proxy; then
                        echo "ERROR: rollback failed; snapshots retained at $rollback_dir" >&2
                        exit "$result"
                    fi
                fi
                sudo rm -rf "$rollback_dir"
                rm -f /tmp/legacy-proxy-preflight-{sha}.py
                exit "$result"
            }}
            trap finish_deployment EXIT

            # Both outbound clients and inbound ingress use the host identity.
            # Legacy hosts retain their existing peer configuration.
            if [ -n "$peer_identity" ]; then
                sudo install -d -m 0750 /etc/superserve/peer
                for credential in \
                    "{peer_env['PEER_PROXY_CERT_FILE']}" \
                    "{peer_env['PEER_PROXY_KEY_FILE']}" \
                    "{peer_env['PEER_PROXY_CA_FILE']}"; do
                    # The SSH deployment account cannot traverse the
                    # root-owned credential directory; validate with the
                    # same privileges used to install and load the files.
                    if ! sudo test -s "$credential"; then
                        echo "ERROR: peer credential missing: $credential" >&2
                        exit 1
                    fi
                done
                # DynamicUser cannot traverse the root-owned bootstrap
                # directory. Let systemd copy credentials into its private
                # runtime credential directory and point the proxy there.
                sudo install -d -m 0755 /etc/systemd/system/proxy.service.d
                deployment_mutated=1
                sudo tee /etc/systemd/system/proxy.service.d/peer-credentials.conf > /dev/null <<CREDENTIALS
                [Service]
                LoadCredential=peer-cert:{peer_env['PEER_PROXY_CERT_FILE']}
                LoadCredential=peer-key:{peer_env['PEER_PROXY_KEY_FILE']}
                LoadCredential=peer-ca:{peer_env['PEER_PROXY_CA_FILE']}
                Environment=PEER_PROXY_CERT_FILE=%d/peer-cert
                Environment=PEER_PROXY_KEY_FILE=%d/peer-key
                Environment=PEER_PROXY_CA_FILE=%d/peer-ca
                CREDENTIALS
            fi

            deployment_mutated=1
            sudo mv /tmp/proxy-{sha} {install_dir}/proxy
            sudo chmod +x {install_dir}/proxy

            sudo mv /tmp/proxy.service /etc/systemd/system/proxy.service
            # An open socket keeps the options it was bound with; a changed
            # unit means it must be bound again.
            socket_changed=0
            if ! sudo cmp -s /tmp/proxy.socket /etc/systemd/system/proxy.socket; then
                socket_changed=1
            fi
            sudo mv /tmp/proxy.socket /etc/systemd/system/proxy.socket
            sudo systemctl daemon-reload
            sudo systemctl enable proxy proxy.socket

            peer_cert_file={peer_env['PEER_PROXY_CERT_FILE']!r}
            peer_key_file={peer_env['PEER_PROXY_KEY_FILE']!r}
            peer_ca_file={peer_env['PEER_PROXY_CA_FILE']!r}
            if [ -n "$peer_identity" ]; then
                peer_cert_file=/run/credentials/proxy.service/peer-cert
                peer_key_file=/run/credentials/proxy.service/peer-key
                peer_ca_file=/run/credentials/proxy.service/peer-ca
            fi
            deployment_mutated=1
            sudo tee /etc/sandbox/proxy.env > /dev/null <<PROXYENV
            PROXY_DOMAIN={proxy_domain}
            PROXY_DOMAINS={proxy_domains}
            SANDBOX_ACCESS_TOKEN_SEED={access_seed}
            PROXY_ALLOWED_ORIGINS={terminal_origins}
            REQUIRE_DATA_PLANE={require_data_plane}
            SENTRY_DSN={sentry_dsn}
            PEER_PROXY_LISTEN_ADDR=$peer_listen_addr
            PEER_PROXY_TARGET_ADDR={peer_env['PEER_PROXY_TARGET_ADDR']}
            PEER_PROXY_CERT_FILE=$peer_cert_file
            PEER_PROXY_KEY_FILE=$peer_key_file
            PEER_PROXY_CA_FILE=$peer_ca_file
            PEER_PROXY_SPIFFE_URI=$peer_identity
            PEER_PROXY_MAX_STREAMS={peer_max_streams}
            PEER_ROUTING_ENABLED={peer_routing}
            HOST_ID=${{host_id:-{name}}}
            HOST_REGION={host_region}{otel_env_lines}
            PROXYENV
            if [ -z "$peer_identity" ]; then
                sudo sed -i '/^PEER_PROXY_/d' /etc/sandbox/proxy.env
                if sudo test -f "$rollback_dir/proxy.env"; then
                    sudo awk '/^PEER_PROXY_/' "$rollback_dir/proxy.env" | sudo tee -a /etc/sandbox/proxy.env > /dev/null
                fi
            fi
            {database_env_command}
            sudo chmod 0600 /etc/sandbox/proxy.env

            # Binding the socket needs the ports free: a proxy that still binds
            # them itself, or a socket bound with an older unit, stops first.
            # One gap, only on those rollouts.
            if [ "$socket_changed" -eq 1 ] || ! sudo systemctl is-active --quiet proxy.socket; then
                sudo systemctl stop proxy proxy.socket 2>/dev/null || true
                if ! sudo systemctl start proxy.socket; then
                    echo "ERROR: proxy.socket failed to bind the public ports" >&2
                    sudo systemctl status --no-pager proxy.socket >&2 || true
                    exit 1
                fi
            fi
            if ! sudo systemctl restart proxy; then
                echo "ERROR: proxy restart failed" >&2
                sudo systemctl status --no-pager proxy >&2 || true
                sudo journalctl -u proxy --no-pager -n 40 >&2 || true
                exit 1
            fi
            sleep 3
            if ! sudo systemctl is-active --quiet proxy; then
                echo "ERROR: proxy failed to become active after restart" >&2
                sudo systemctl status --no-pager proxy >&2 || true
                sudo journalctl -u proxy --no-pager -n 40 >&2 || true
                exit 1
            fi
            curl --fail --silent --show-error --max-time 10 http://127.0.0.1:5007/health > /dev/null
            [ "$(systemctl show -p InvocationID --value {service})" = "$vmd_invocation" ]
        """)
        # Heredoc terminators must begin at column zero in the generated shell.
        deploy_script = deploy_script.replace("    CREDENTIALS\n", "CREDENTIALS\n")
        # Share the generation controller's host lock, including legacy credential reloads.
        deploy_script = ("sudo install -d -m 0755 /var/lib/proxy-rollout && "
                         "sudo flock -n /var/lib/proxy-rollout/lock bash -c " + shlex.quote(deploy_script))

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
        print(f"[{tag}] proxy active")

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
