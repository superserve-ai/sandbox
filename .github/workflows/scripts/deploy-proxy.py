#!/usr/bin/env python3
"""Deploy the proxy binary to every compute instance tagged with the
configured label, in parallel.

Env vars:
  GCP_PROJECT                required — project containing vmd hosts
  GCP_REGION                 optional — only deploy to instances whose zone is
                             in this region (e.g. us-central1). The prod
                             project holds hosts for more than one cell, and
                             the workflow deploys them sequentially, so an
                             unscoped label filter would fold the cell host
                             into the primary fan-out. Empty = no scoping.
  VMD_LABEL                  required — gcloud instances list label filter
  VMD_INSTALL_DIR            required — bin install dir on the host
  SHA                        required — commit SHA (only first 8 chars used)
  PROXY_DOMAIN               required — host suffix the proxy serves (e.g. sandbox.superserve.ai)
  PROXY_DOMAINS              optional — comma-separated host suffixes; overrides
                             PROXY_DOMAIN on the proxy when set (DNS transitions)
  SANDBOX_ACCESS_TOKEN_SEED  optional — hex, >=32 bytes (>=64 hex chars)
  PROXY_ALLOWED_ORIGINS      optional — comma-separated origin patterns
  REQUIRE_DATA_PLANE         optional — "", "0", or "1"
  SENTRY_DSN                 optional — Sentry DSN URL for error reporting
  PEER_PROXY_*               optional — private mTLS peer ingress settings
"""

import os
import re
import subprocess
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor, as_completed


def main() -> int:
    project = os.environ["GCP_PROJECT"]
    region = os.environ.get("GCP_REGION", "")
    label = os.environ.get("VMD_LABEL", "component=vmd")
    # The installed unit is superserve-vmd.service; retain an override for
    # environments that use a deliberately different unit name.
    service = os.environ.get("VMD_SERVICE", "superserve-vmd")
    install_dir = os.environ.get("VMD_INSTALL_DIR", "/usr/local/bin")
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
    terminal_origins = os.environ.get("PROXY_ALLOWED_ORIGINS", "")
    if terminal_origins and not re.fullmatch(r"[A-Za-z0-9.,:/*\-]+", terminal_origins):
        print("ERROR: PROXY_ALLOWED_ORIGINS contains disallowed characters", file=sys.stderr)
        return 1
    require_data_plane = os.environ.get("REQUIRE_DATA_PLANE", "")
    if require_data_plane not in ("", "0", "1"):
        print('ERROR: REQUIRE_DATA_PLANE must be empty, "0", or "1"', file=sys.stderr)
        return 1
    sentry_dsn = os.environ.get("SENTRY_DSN", "")
    peer_env = {
        key: os.environ.get(key, "") for key in (
            "PEER_PROXY_LISTEN_ADDR", "PEER_PROXY_TARGET_ADDR",
            "PEER_PROXY_CERT_FILE", "PEER_PROXY_KEY_FILE",
            "PEER_PROXY_CA_FILE", "PEER_PROXY_SPIFFE_URI",
        )
    }
    peer_env["PEER_PROXY_TARGET_ADDR"] = peer_env["PEER_PROXY_TARGET_ADDR"] or "127.0.0.1:5010"
    for key, default in (
        ("PEER_PROXY_CERT_FILE", "/etc/superserve/peer/tls.crt"),
        ("PEER_PROXY_KEY_FILE", "/etc/superserve/peer/tls.key"),
        ("PEER_PROXY_CA_FILE", "/etc/superserve/peer/ca.crt"),
    ):
        peer_env[key] = peer_env[key] or default
    peer_identity = peer_env["PEER_PROXY_SPIFFE_URI"]
    if peer_env["PEER_PROXY_LISTEN_ADDR"] and not peer_identity:
        print("ERROR: peer ingress requires PEER_PROXY_SPIFFE_URI", file=sys.stderr)
        return 1
    if peer_identity and not re.fullmatch(r"spiffe://[A-Za-z0-9._:/-]+", peer_identity):
        print("ERROR: PEER_PROXY_SPIFFE_URI must be a SPIFFE URI", file=sys.stderr)
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
            f"--filter=labels.{label} AND status=RUNNING",
            "--format=csv[no-heading](name,zone)",
        ],
        capture_output=True, text=True, check=True,
    )

    instances = [
        {"name": r[0], "zone": r[1]}
        for line in result.stdout.strip().splitlines()
        if line.strip()
        for r in [line.strip().split(",")]
    ]

    # Region scoping happens here rather than in the gcloud filter: matching
    # on the zone basename is unambiguous, while gcloud filter matching
    # against zone URIs is easy to get subtly wrong. Zero matches is a hard
    # failure either way — a deploy that silently skips a host is exactly
    # the drift this script exists to prevent.
    if region:
        instances = [
            inst for inst in instances
            if inst["zone"].split("/")[-1].startswith(f"{region}-")
        ]

    where = f"{project} ({region})" if region else project
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
        tag = f"{name}/{zone}"

        for src, dst in [
            ("bin/proxy", f"/tmp/proxy-{sha}"),
            ("deploy/proxy.service", "/tmp/proxy.service"),
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

            sudo mv /tmp/proxy-{sha} {install_dir}/proxy
            sudo chmod +x {install_dir}/proxy

            sudo mv /tmp/proxy.service /etc/systemd/system/proxy.service
            sudo systemctl daemon-reload
            sudo systemctl enable proxy

            sudo mkdir -p /etc/sandbox
            rollback_dir=$(sudo mktemp -d /etc/sandbox/proxy-rollback.XXXXXX)
            for config in /etc/sandbox/proxy.env /etc/sandbox/vmd.env /etc/systemd/system/proxy.service.d/peer-credentials.conf; do
                if sudo test -f "$config"; then
                    sudo cp -p "$config" "$rollback_dir/$(basename "$config")"
                fi
            done

            peer_listen_addr=""
            peer_endpoint_changed=0
            existing_peer_listen_addr=""
            wait_for_vmd_ready() {{
                # Type=simple becomes active before VMD can serve requests.
                # Readiness and endpoint acknowledgement must belong to the
                # still-current invocation before old routing can be retired.
                for attempt in $(seq 1 90); do
                    invocation=$(systemctl show -p InvocationID --value {service} 2>/dev/null || true)
                    if [ -n "$invocation" ] \
                       && sudo journalctl "_SYSTEMD_INVOCATION_ID=$invocation" --quiet -g 'gRPC serving requests' --no-pager >/dev/null 2>&1 \
                       && sudo journalctl "_SYSTEMD_INVOCATION_ID=$invocation" --quiet -g 'host endpoint heartbeat accepted' --no-pager >/dev/null 2>&1 \
                       && [ "$(systemctl show -p InvocationID --value {service} 2>/dev/null || true)" = "$invocation" ] \
                       && sudo systemctl is-active --quiet {service}; then
                        return 0
                    fi
                    sleep 1
                done
                echo "ERROR: {service} did not reach application readiness and endpoint acknowledgement within 90s" >&2
                return 1
            }}
            rollback_peer_advertisement() {{
                # Restore the listener configuration before restoring what VMD
                # advertises. The failed deployment may already have restarted
                # the proxy with a different port or credential drop-in.
                for config in /etc/sandbox/proxy.env /etc/sandbox/vmd.env /etc/systemd/system/proxy.service.d/peer-credentials.conf; do
                    if sudo test -f "$rollback_dir/$(basename "$config")"; then
                        sudo cp -p "$rollback_dir/$(basename "$config")" "$config" || return 1
                    else
                        sudo rm -f "$config" || return 1
                    fi
                done
                sudo systemctl daemon-reload || return 1
                if ! sudo systemctl restart proxy || ! sudo systemctl is-active --quiet proxy; then
                    echo "ERROR: proxy restart failed during rollback" >&2
                    sudo journalctl -u proxy --no-pager -n 40 >&2 || true
                    return 1
                fi
                if [ "$peer_endpoint_changed" -eq 1 ]; then
                    # VMD reads its environment only at process startup; restart
                    # it so the running process matches the restored env file.
                    if ! sudo systemctl restart {service} || ! wait_for_vmd_ready; then
                        echo "ERROR: {service} restart failed while rolling back peer advertisement" >&2
                        sudo systemctl status --no-pager {service} >&2 || true
                        sudo journalctl -u {service} --no-pager -n 40 >&2 || true
                        return 1
                    fi
                fi
            }}
            deployment_mutated=0
            finish_deployment() {{
                result=$?
                trap - EXIT
                if [ "$result" -ne 0 ] && [ "$deployment_mutated" -eq 1 ]; then
                    if ! rollback_peer_advertisement; then
                        echo "ERROR: rollback failed; snapshots retained at $rollback_dir" >&2
                        exit "$result"
                    fi
                fi
                sudo rm -rf "$rollback_dir"
                exit "$result"
            }}
            trap finish_deployment EXIT

            # Both outbound clients and inbound ingress use the host identity.
            # Configure it only after bootstrap has provisioned all target hosts.
            if [ -n "{peer_identity}" ]; then
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
            else
                deployment_mutated=1
                sudo rm -f /etc/systemd/system/proxy.service.d/peer-credentials.conf
            fi

            sudo systemctl daemon-reload

            peer_cert_file={peer_env['PEER_PROXY_CERT_FILE']!r}
            peer_key_file={peer_env['PEER_PROXY_KEY_FILE']!r}
            peer_ca_file={peer_env['PEER_PROXY_CA_FILE']!r}
            if [ -n "{peer_identity}" ]; then
                peer_cert_file=/run/credentials/proxy.service/peer-cert
                peer_key_file=/run/credentials/proxy.service/peer-key
                peer_ca_file=/run/credentials/proxy.service/peer-ca
            fi
            if [ -n "{peer_env['PEER_PROXY_LISTEN_ADDR']}" ]; then
                sudo mkdir -p /etc/sandbox
                peer_listen_addr={peer_env['PEER_PROXY_LISTEN_ADDR']}
                if [ "$peer_listen_addr" = "auto" ]; then
                    peer_ip=$(curl -fsS -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/ip)
                    # 5008 is reserved for the wildcard HTTP redirect listener.
                    # Keep peer ingress on its own private port so the two binds
                    # cannot collide when the staging shortcut is enabled.
                    peer_listen_addr="$peer_ip:5009"
                elif [[ "$peer_listen_addr" == *:5008 ]]; then
                    # Explicit addresses must obey the same reservation as auto;
                    # otherwise a private-IP override still collides with the
                    # wildcard redirect listener on 5008.
                    peer_listen_addr="${{peer_listen_addr%:5008}}:5009"
                fi
                # vmd owns host.proxy_addr advertisement. Keep its environment in
                # lockstep with the proxy listener so the heartbeat publishes the
                # private peer endpoint when ingress is enabled.
                sudo touch /etc/sandbox/vmd.env
                existing_peer_listen_addr=$(sudo sed -n 's/^PEER_PROXY_LISTEN_ADDR=//p' /etc/sandbox/vmd.env | tail -n1 || true)
                peer_endpoint_changed=1
                if [ "$existing_peer_listen_addr" = "$peer_listen_addr" ]; then
                    peer_endpoint_changed=0
                else
                    sudo sed -i '/^PEER_PROXY_LISTEN_ADDR=/d' /etc/sandbox/vmd.env
                    printf 'PEER_PROXY_LISTEN_ADDR=%s\\n' "$peer_listen_addr" | sudo tee -a /etc/sandbox/vmd.env > /dev/null
                fi
            else
                # Remove the prior advertisement when peer ingress is disabled
                # (including rollback). VMD only reads this environment at
                # startup, so restart it only when a stale advertisement
                # actually exists; ordinary deployments must not interrupt it.
                if sudo grep -q '^PEER_PROXY_LISTEN_ADDR=' /etc/sandbox/vmd.env 2>/dev/null; then
                    existing_peer_listen_addr=$(sudo sed -n 's/^PEER_PROXY_LISTEN_ADDR=//p' /etc/sandbox/vmd.env | tail -n1 || true)
                    peer_endpoint_changed=1
                    sudo sed -i '/^PEER_PROXY_LISTEN_ADDR=/d' /etc/sandbox/vmd.env
                    if ! sudo systemctl restart {service}; then
                        echo "ERROR: {service} restart failed" >&2
                        sudo systemctl status --no-pager {service} >&2 || true
                        sudo journalctl -u {service} --no-pager -n 40 >&2 || true
                        exit 1
                    fi
                    if ! wait_for_vmd_ready; then
                        echo "ERROR: {service} failed to become active after restart" >&2
                        sudo systemctl status --no-pager {service} >&2 || true
                        sudo journalctl -u {service} --no-pager -n 40 >&2 || true
                        exit 1
                    fi
                fi
            fi
            # HOST_ID must match vmd's: it is the host's logical identity and
            # is deliberately preserved across deploys (a replacement host
            # keeps its predecessor's row ID), so copy vmd's value and fall
            # back to the instance name only when no vmd env exists yet.
            host_id=$(sudo sed -n 's/^HOST_ID=//p' /etc/sandbox/vmd.env 2>/dev/null | head -n1 || true)
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
            PEER_PROXY_SPIFFE_URI={peer_identity}
            PEER_PROXY_MAX_STREAMS={peer_max_streams}
            HOST_ID=${{host_id:-{name}}}{otel_env_lines}
            PROXYENV
            sudo chmod 0600 /etc/sandbox/proxy.env

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
            # Start and verify peer ingress before VMD advertises its endpoint.
            # This prevents heartbeat routing from switching to a closed port if
            # proxy configuration or credentials are invalid.
            if [ -n "$peer_listen_addr" ] && [ "$peer_endpoint_changed" -eq 1 ]; then
                if ! sudo systemctl restart {service}; then
                    echo "ERROR: {service} restart failed" >&2
                    sudo systemctl status --no-pager {service} >&2 || true
                    sudo journalctl -u {service} --no-pager -n 40 >&2 || true
                    exit 1
                fi
                if ! wait_for_vmd_ready; then
                    echo "ERROR: {service} failed to become active after restart" >&2
                    sudo systemctl status --no-pager {service} >&2 || true
                    sudo journalctl -u {service} --no-pager -n 40 >&2 || true
                    exit 1
                fi
            fi
        """)
        # Heredoc terminators must begin at column zero in the generated shell.
        deploy_script = deploy_script.replace("    CREDENTIALS\n", "CREDENTIALS\n")

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
