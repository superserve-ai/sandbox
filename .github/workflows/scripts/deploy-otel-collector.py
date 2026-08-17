#!/usr/bin/env python3
"""Deploy the OTEL Collector binary, config, and systemd unit to VMD hosts.

The default host selection still uses the `component=vmd` label; production
can supply a full gcloud filter to scope the fan-out to a specific cell.
"""

import os
import re
import shlex
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


def _command_failure(action: str, command: list[str], exc: subprocess.CalledProcessError) -> RuntimeError:
    return RuntimeError(
        f"{action} failed (exit {exc.returncode}): {' '.join(command)}\n"
        f"--- stdout ---\n{exc.stdout or ''}\n"
        f"--- stderr ---\n{exc.stderr or ''}"
    )


def _parse_remote_probe(stdout: str, stderr: str) -> tuple[str, str]:
    host_uname = next(
        (line.removeprefix("__OTEL_ARCH__=").strip()
         for line in stdout.splitlines() if line.startswith("__OTEL_ARCH__=")),
        None,
    )
    if not host_uname:
        raise RuntimeError(
            "could not determine host architecture\n"
            f"--- stdout ---\n{stdout}\n"
            f"--- stderr ---\n{stderr}"
        )

    staging_dir = next(
        (line.removeprefix("__OTEL_STAGING__=").strip()
         for line in stdout.splitlines() if line.startswith("__OTEL_STAGING__=")),
        None,
    )
    if not staging_dir or not re.fullmatch(r"/tmp/otel-collector\.[A-Za-z0-9_-]+", staging_dir):
        raise RuntimeError(
            "could not determine safe remote staging directory\n"
            f"--- stdout ---\n{stdout}\n"
            f"--- stderr ---\n{stderr}"
        )
    return host_uname, staging_dir


def _health_check_script() -> str:
    return textwrap.dedent(
        """
        if ! systemd_status=$(sudo systemctl is-active superserve-otel-collector 2>&1); then
          echo "ERROR: systemd active check failed: $systemd_status" >&2
          sudo systemctl status --no-pager --full superserve-otel-collector >&2 || true
          sudo journalctl -u superserve-otel-collector --no-pager -n 80 >&2 || true
          exit 1
        fi

        if ! health_response=$(curl -sSf http://127.0.0.1:13133/ 2>&1); then
          echo "ERROR: collector health endpoint (13133) failed: $health_response" >&2
          exit 1
        fi

        if ! metrics_response=$(curl -sSf http://127.0.0.1:8888/metrics 2>&1); then
          echo "ERROR: collector self-metrics endpoint (8888) failed: $metrics_response" >&2
          exit 1
        fi
        if ! grep '^otelcol_' >/dev/null <<<"$metrics_response"; then
          echo "ERROR: collector self-metrics assertion (8888) failed" >&2
          exit 1
        fi
        """).strip()


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
    host_filter = os.environ.get("VMD_FILTER", "")
    label = os.environ.get("VMD_LABEL") or "component=vmd"
    collector_project = os.environ.get("OTEL_COLLECTOR_PROJECT", project)

    if not re.fullmatch(r"[A-Za-z0-9._:-]+", collector_project):
        print("ERROR: OTEL_COLLECTOR_PROJECT contains disallowed characters", file=sys.stderr)
        return 1

    if host_filter:
        instance_filter = host_filter
    else:
        instance_filter = f"labels.{label}"

    result = subprocess.run(
        [
            "gcloud", "compute", "instances", "list",
            f"--project={project}",
            f"--filter={instance_filter} AND status=RUNNING",
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
        print(f"No instances matching {instance_filter} found in {where}", file=sys.stderr)
        return 1

    collector_binaries = prepare_collector_binaries()
    print(f"Deploying OTEL Collector to {len(instances)} instance(s) in {where}")

    def deploy(instance: dict[str, str]) -> None:
        name = instance["name"]
        zone = instance["zone"]
        zone_name = zone.split("/")[-1]
        tag = f"{name}/{zone}"

        probe_command = [
            "gcloud", "compute", "ssh", name,
            f"--zone={zone}", f"--project={project}",
            "--quiet", "--tunnel-through-iap", "--command",
            'staging_dir="$(mktemp -d /tmp/otel-collector.XXXXXX)" && '
            'printf "__OTEL_ARCH__=%s\\n__OTEL_STAGING__=%s\\n" "$(uname -m)" "$staging_dir"',
        ]
        try:
            host_arch_result = subprocess.run(
                probe_command,
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            raise _command_failure(f"[{tag}] architecture/staging SSH probe", probe_command, exc) from exc
        host_uname, staging_dir = _parse_remote_probe(
            host_arch_result.stdout, host_arch_result.stderr
        )

        def cleanup_staging() -> None:
            cleanup_command = [
                "gcloud", "compute", "ssh", name,
                f"--zone={zone}", f"--project={project}",
                "--quiet", "--tunnel-through-iap",
                "--command", f"rm -rf -- {shlex.quote(staging_dir)}",
            ]
            cleanup_result = subprocess.run(cleanup_command, capture_output=True, text=True)
            if cleanup_result.returncode != 0:
                print(
                    _command_failure(
                        f"[{tag}] staging cleanup", cleanup_command,
                        subprocess.CalledProcessError(
                            cleanup_result.returncode, cleanup_command,
                            output=cleanup_result.stdout, stderr=cleanup_result.stderr,
                        ),
                    ), file=sys.stderr,
                )

        selected_arch = None
        for otel_arch, uname_arch in OTEL_ARCHITECTURES.items():
            if host_uname == uname_arch:
                selected_arch = otel_arch
                break
        if selected_arch is None:
            cleanup_staging()
            raise RuntimeError(f"unsupported host architecture: {host_uname}")

        uploads = [
            ("deploy/otel/collector-gmp.yaml", f"{staging_dir}/collector-gmp.yaml"),
            (
                "deploy/superserve-otel-collector.service",
                f"{staging_dir}/superserve-otel-collector.service",
            ),
            (collector_binaries[selected_arch], f"{staging_dir}/otelcol-contrib"),
        ]

        for src, dst in uploads:
            upload_command = [
                    "gcloud", "compute", "scp", src, f"{name}:{dst}",
                    f"--zone={zone}", f"--project={project}",
                    "--quiet", "--tunnel-through-iap",
                ]
            try:
                subprocess.run(upload_command, check=True, capture_output=True, text=True)
            except subprocess.CalledProcessError as exc:
                cleanup_staging()
                raise _command_failure(f"[{tag}] upload {src}", upload_command, exc) from exc

        print(f"[{tag}] collector files uploaded")

        deploy_script = textwrap.dedent(
            f"""
            set -euo pipefail

            OTEL_VERSION="{OTEL_COLLECTOR_VERSION}"
            OTEL_BINARY="/usr/local/bin/otelcol-contrib"
            STAGING_DIR={shlex.quote(staging_dir)}
            trap 'rm -rf -- "$STAGING_DIR"' EXIT

            if [ ! -x "$OTEL_BINARY" ] || \
               ! "$OTEL_BINARY" --version 2>/dev/null | grep -Fq "$OTEL_VERSION"; then
              echo "Installing otelcol-contrib v$OTEL_VERSION from uploaded artifact"
              sudo install -m 0755 "$STAGING_DIR/otelcol-contrib" "$OTEL_BINARY"
            else
              echo "otelcol-contrib v$OTEL_VERSION is already installed"
            fi

            sudo install -D -m 0644 \
              "$STAGING_DIR/collector-gmp.yaml" \
              /etc/sandbox/otel/collector-gmp.yaml

            sudo install -D -m 0644 \
              "$STAGING_DIR/superserve-otel-collector.service" \
              /etc/systemd/system/superserve-otel-collector.service

            sudo mkdir -p /etc/sandbox/otel
            sudo tee /etc/sandbox/otel/collector.env >/dev/null <<'OTELENV'
            GCP_PROJECT={collector_project}
            GCP_ZONE={zone_name}
            HOST_ID={name}
            OTELENV
            sudo chmod 0644 /etc/sandbox/otel/collector.env

            sudo systemctl daemon-reload
            sudo systemctl enable superserve-otel-collector
            sudo systemctl restart superserve-otel-collector

            sleep 5

            {_health_check_script()}
            """
        )

        deploy_command = [
                "gcloud", "compute", "ssh", name,
                f"--zone={zone}", f"--project={project}",
                "--quiet", "--tunnel-through-iap",
                "--command", deploy_script,
            ]
        result = subprocess.run(
            deploy_command,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            cleanup_staging()
            raise RuntimeError(
                f"[{tag}] collector deployment/health checks failed (exit {result.returncode})\n"
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
