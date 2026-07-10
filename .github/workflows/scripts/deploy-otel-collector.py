#!/usr/bin/env python3
"""Deploy the OTEL Collector binary, config, and systemd unit to VMD hosts."""

import os
import re
import subprocess
import sys
import textwrap
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


OTEL_COLLECTOR_VERSION = "0.104.0"
OTEL_ARCHITECTURES = {
    "amd64": "x86_64",
    "arm64": "aarch64",
}


def prepare_collector_binaries() -> dict[str, str]:
    tmp_dir = tempfile.mkdtemp(prefix="otel-collector-")
    binaries: dict[str, str] = {}

    for otel_arch in OTEL_ARCHITECTURES:
        archive_path = Path(tmp_dir) / f"otelcol-contrib_{otel_arch}.tar.gz"
        extract_dir = Path(tmp_dir) / f"extract_{otel_arch}"
        extract_dir.mkdir(parents=True, exist_ok=True)
        download_url = (
            "https://github.com/open-telemetry/opentelemetry-collector-releases/"
            f"releases/download/v{OTEL_COLLECTOR_VERSION}/"
            f"otelcol-contrib_{OTEL_COLLECTOR_VERSION}_linux_{otel_arch}.tar.gz"
        )

        subprocess.run(
            [
                "curl",
                "--fail",
                "--location",
                "--silent",
                "--show-error",
                download_url,
                "--output",
                str(archive_path),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            ["tar", "-xzf", str(archive_path), "-C", str(extract_dir)],
            check=True,
            capture_output=True,
            text=True,
        )

        binary_path = extract_dir / "otelcol-contrib"
        if not binary_path.is_file():
            raise RuntimeError(
                f"downloaded archive for {otel_arch} did not contain otelcol-contrib"
            )
        binary_path.chmod(0o755)
        binaries[otel_arch] = str(binary_path)

    return binaries


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
        {"name": row[0], "zone": row[1]}
        for line in result.stdout.strip().splitlines()
        if line.strip()
        for row in [line.strip().split(",")]
    ]

    if region:
        instances = [
            instance
            for instance in instances
            if instance["zone"].split("/")[-1].startswith(f"{region}-")
        ]

    where = f"{project} ({region})" if region else project
    if not instances:
        print(f"No instances with label {label} found in {where}", file=sys.stderr)
        return 1

    collector_binaries = prepare_collector_binaries()
    print(f"Deploying OTEL Collector to {len(instances)} instance(s) in {where}")

    def deploy(instance: dict[str, str]) -> None:
        name = instance["name"]
        zone = instance["zone"]
        zone_name = zone.split("/")[-1]
        tag = f"{name}/{zone}"

        host_arch_result = subprocess.run(
            [
                "gcloud", "compute", "ssh", name,
                f"--zone={zone}", f"--project={project}",
                "--quiet", "--tunnel-through-iap",
                "--command", "uname -m",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        host_uname = host_arch_result.stdout.strip()

        selected_arch = None
        for otel_arch, uname_arch in OTEL_ARCHITECTURES.items():
            if host_uname == uname_arch:
                selected_arch = otel_arch
                break
        if selected_arch is None:
            raise RuntimeError(f"unsupported host architecture: {host_uname}")

        uploads = [
            ("deploy/otel/collector-gmp.yaml", "/tmp/collector-gmp.yaml"),
            (
                "deploy/superserve-otel-collector.service",
                "/tmp/superserve-otel-collector.service",
            ),
            (collector_binaries[selected_arch], "/tmp/otelcol-contrib"),
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
                text=True,
            )

        print(f"[{tag}] collector files uploaded")

        deploy_script = textwrap.dedent(
            f"""
            set -euo pipefail

            OTEL_VERSION="{OTEL_COLLECTOR_VERSION}"
            OTEL_BINARY="/usr/local/bin/otelcol-contrib"

            if [ ! -x "$OTEL_BINARY" ] || \
               ! "$OTEL_BINARY" --version 2>/dev/null | grep -Fq "$OTEL_VERSION"; then
              echo "Installing otelcol-contrib v$OTEL_VERSION from uploaded artifact"
              sudo install -m 0755 /tmp/otelcol-contrib "$OTEL_BINARY"
            else
              echo "otelcol-contrib v$OTEL_VERSION is already installed"
            fi

            sudo install -D -m 0644 \
              /tmp/collector-gmp.yaml \
              /etc/sandbox/otel/collector-gmp.yaml

            sudo install -D -m 0644 \
              /tmp/superserve-otel-collector.service \
              /etc/systemd/system/superserve-otel-collector.service

            sudo mkdir -p /etc/sandbox/otel
            sudo tee /etc/sandbox/otel/collector.env >/dev/null <<'OTELENV'
            GCP_PROJECT={collector_project}
            GCP_ZONE={zone_name}
            OTELENV
            sudo chmod 0644 /etc/sandbox/otel/collector.env

            sudo systemctl daemon-reload
            sudo systemctl enable superserve-otel-collector
            sudo systemctl restart superserve-otel-collector

            sleep 5

            sudo systemctl is-active --quiet superserve-otel-collector || (
              echo "ERROR: superserve-otel-collector failed to become active after restart" >&2
              sudo systemctl status --no-pager --full superserve-otel-collector >&2 || true
              sudo journalctl -u superserve-otel-collector --no-pager -n 80 >&2 || true
              exit 1
            )

            curl -sf http://127.0.0.1:13133/ >/dev/null
            curl -sf http://127.0.0.1:8888/metrics | grep -q '^otelcol_'
            """
        )

        result = subprocess.run(
            [
                "gcloud", "compute", "ssh", name,
                f"--zone={zone}", f"--project={project}",
                "--quiet", "--tunnel-through-iap",
                "--command", deploy_script,
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise RuntimeError(
                "collector not healthy\n"
                f"--- stdout ---\n{result.stdout}\n"
                f"--- stderr ---\n{result.stderr}"
            )

        print(f"[{tag}] collector active")

    failed: list[str] = []
    with ThreadPoolExecutor(max_workers=len(instances)) as executor:
        futures = {
            executor.submit(deploy, instance): instance
            for instance in instances
        }
        for future in as_completed(futures):
            instance = futures[future]
            try:
                future.result()
            except Exception as exc:
                tag = f"{instance['name']}/{instance['zone']}"
                print(f"[{tag}] FAILED: {exc}", file=sys.stderr)
                failed.append(tag)

    if failed:
        print(f'Deploy failed on: {", ".join(failed)}', file=sys.stderr)
        return 1

    print(f"Deployed OTEL Collector to {len(instances)} instance(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
