#!/usr/bin/env python3
"""Deploy the OTEL Collector config and systemd unit to VMD hosts."""

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
    collector_project = os.environ.get("OTEL_COLLECTOR_PROJECT", project)

    if not re.fullmatch(r"[A-Za-z0-9._:-]+", collector_project):
        print("ERROR: OTEL_COLLECTOR_PROJECT contains disallowed characters", file=sys.stderr)
        return 1

    result = subprocess.run(
        [
            "gcloud", "compute", "instances", "list",
            f"--project={project}",
            f"--filter=labels.{label} AND status=RUNNING",
            "--format=csv[no-heading](name,zone)",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    instances = [
        {"name": r[0], "zone": r[1]}
        for line in result.stdout.strip().splitlines()
        if line.strip()
        for r in [line.strip().split(",")]
    ]

    if region:
        instances = [
            inst for inst in instances
            if inst["zone"].split("/")[-1].startswith(f"{region}-")
        ]

    where = f"{project} ({region})" if region else project
    if not instances:
        print(f"No instances with label {label} found in {where}", file=sys.stderr)
        return 1

    print(f"Deploying OTEL Collector to {len(instances)} instance(s) in {where}")

    def deploy(inst):
        name, zone = inst["name"], inst["zone"]
        tag = f"{name}/{zone}"

        uploads = [
            ("deploy/otel/collector-gmp.yaml", "/tmp/collector-gmp.yaml"),
            ("deploy/superserve-otel-collector.service", "/tmp/superserve-otel-collector.service"),
        ]

        for src, dst in uploads:
            subprocess.run(
                [
                    "gcloud", "compute", "scp", src, f"{name}:{dst}",
                    f"--zone={zone}", f"--project={project}",
                    "--quiet", "--tunnel-through-iap",
                ],
                check=True,
                capture_output=True,
            )

        print(f"[{tag}] collector files uploaded")

        deploy_script = textwrap.dedent(f"""
            set -euo pipefail

            sudo install -D -m 0644 /tmp/collector-gmp.yaml /etc/sandbox/otel/collector-gmp.yaml
            sudo install -D -m 0644 /tmp/superserve-otel-collector.service /etc/systemd/system/superserve-otel-collector.service

            sudo mkdir -p /etc/sandbox/otel
            sudo tee /etc/sandbox/otel/collector.env >/dev/null <<'OTELENV'
            GCP_PROJECT={collector_project}
            OTELENV
            sudo chmod 0644 /etc/sandbox/otel/collector.env

            sudo systemctl daemon-reload
            sudo systemctl enable superserve-otel-collector
            sudo systemctl restart superserve-otel-collector

            sleep 5

            sudo systemctl is-active --quiet superserve-otel-collector || (
                echo "ERROR: superserve-otel-collector failed to become active after restart" >&2
                sudo systemctl status --no-pager superserve-otel-collector >&2 || true
                sudo journalctl -u superserve-otel-collector --no-pager -n 80 >&2 || true
                exit 1
            )

            curl -sf http://127.0.0.1:13133/ >/dev/null
            curl -sf http://127.0.0.1:8888/metrics | grep -q '^otelcol_'
        """)

        r = subprocess.run(
            [
                "gcloud", "compute", "ssh", name,
                f"--zone={zone}", f"--project={project}",
                "--quiet", "--tunnel-through-iap",
                "--command", deploy_script,
            ],
            capture_output=True,
            text=True,
        )

        if r.returncode != 0:
            raise RuntimeError(
                f"collector not healthy\n"
                f"--- stdout ---\n{r.stdout}\n"
                f"--- stderr ---\n{r.stderr}"
            )

        print(f"[{tag}] collector active")

    failed = []
    with ThreadPoolExecutor(max_workers=len(instances)) as ex:
        futures = {ex.submit(deploy, inst): inst for inst in instances}
        for future in as_completed(futures):
            inst = futures[future]
            try:
                future.result()
            except Exception as exc:
                tag = f"{inst['name']}/{inst['zone']}"
                print(f"[{tag}] FAILED: {exc}", file=sys.stderr)
                failed.append(tag)

    if failed:
        print(f'Deploy failed on: {", ".join(failed)}', file=sys.stderr)
        return 1

    print(f"Deployed OTEL Collector to {len(instances)} instance(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
