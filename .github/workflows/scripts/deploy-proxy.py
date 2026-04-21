#!/usr/bin/env python3
"""Deploy the proxy binary to every compute instance tagged with the
configured label, in parallel.

Env vars:
  GCP_PROJECT                required — project containing vmd hosts
  VMD_LABEL                  required — gcloud instances list label filter
  VMD_INSTALL_DIR            required — bin install dir on the host
  SHA                        required — commit SHA (only first 8 chars used)
  SANDBOX_ACCESS_TOKEN_SEED  optional — hex, >=32 bytes (>=64 hex chars)
  PROXY_ALLOWED_ORIGINS      optional — comma-separated origin patterns
  REQUIRE_DATA_PLANE         optional — "", "0", or "1"
"""

import os
import re
import subprocess
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor, as_completed


def main() -> int:
    project = os.environ["GCP_PROJECT"]
    label = os.environ.get("VMD_LABEL", "component=vmd")
    install_dir = os.environ.get("VMD_INSTALL_DIR", "/usr/local/bin")
    sha = os.environ["SHA"][:8]

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

    if not instances:
        print(f"No instances with label {label} found in {project}", file=sys.stderr)
        return 1

    print(f"Deploying proxy to {len(instances)} instance(s)")

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
            if [ -n "{access_seed}" ]; then
                sudo tee /etc/sandbox/proxy.env > /dev/null <<PROXYENV
            SANDBOX_ACCESS_TOKEN_SEED={access_seed}
            PROXY_ALLOWED_ORIGINS={terminal_origins}
            REQUIRE_DATA_PLANE={require_data_plane}
            PROXYENV
                sudo chmod 0600 /etc/sandbox/proxy.env
            fi

            sudo systemctl restart proxy
            sleep 3
            sudo systemctl is-active --quiet proxy || (
                echo "ERROR: proxy failed to become active after restart" >&2
                sudo systemctl status --no-pager proxy >&2 || true
                sudo journalctl -u proxy --no-pager -n 40 >&2 || true
                exit 1
            )
        """)

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
