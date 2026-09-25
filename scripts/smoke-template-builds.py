#!/usr/bin/env python3
"""Opt-in staging producer smoke; requires psql, seed-templates and a host-loss helper."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed-binary", default="seed-templates")
    parser.add_argument("--failure-helper", required=True,
                        help="executable invoked with the recorded host ID; stops that staging owner")
    args = parser.parse_args()
    if not os.environ.get("DATABASE_URL") or not os.environ.get("SYSTEM_TEAM_ID"):
        parser.error("DATABASE_URL and SYSTEM_TEAM_ID must name the staging cell")
    env = dict(os.environ, PGCONNECT_TIMEOUT="10")

    def query(sql):
        try:
            result = subprocess.run(["psql", "--dbname", os.environ["DATABASE_URL"],
                                     "-XAt", "-v", "ON_ERROR_STOP=1", "-c", sql],
                                    env=env, capture_output=True, text=True, timeout=30)
        except (subprocess.TimeoutExpired, OSError):
            raise RuntimeError("smoke database query did not complete") from None
        if result.returncode:
            raise RuntimeError(f"smoke database query failed (exit {result.returncode})")
        return json.loads(result.stdout.strip() or "[]")

    prefix = "producer-smoke-" + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="template-smoke-") as directory:
        for cpu in (1, 2, 8):
            spec = {"name": f"{prefix}-{cpu}", "vcpu": cpu, "memory_mib": cpu * 1024,
                    "disk_mib": 4096,
                    "build_spec": {"from": "debian:12-slim", "steps": [{"run": "sleep 180"}]}}
            Path(directory, f"{cpu}.json").write_text(json.dumps(spec))
        command = [args.seed_binary, "--dir", directory, "--no-wait"]
        subprocess.run(command, check=True)
        builds = query(f"""SELECT coalesce(json_agg(b.id),'[]') FROM template_build b
            JOIN template t ON t.id=b.template_id WHERE t.name LIKE '{prefix}-%'""")
        if len(builds) != 3:
            raise RuntimeError("expected three logical builds")
        selected = None
        deadline = time.monotonic() + 35 * 60
        while time.monotonic() < deadline:
            rows = query(f"""SELECT coalesce(json_agg(row_to_json(x)),'[]') FROM (
                SELECT b.id,b.status,e.reason,a.host_id,a.id AS attempt_id,a.state,
                  (SELECT count(*) FROM template_build_attempt x WHERE x.build_id=b.id
                    AND x.state<>'rejected') AS attempts,
                  EXISTS(SELECT 1 FROM template_build_publication p WHERE p.build_id=b.id
                    AND p.accepted_at IS NOT NULL) AS published
                FROM template_build b JOIN template t ON t.id=b.template_id
                JOIN template_build_execution e ON e.build_id=b.id
                LEFT JOIN template_build_attempt a ON a.id=e.current_attempt
                WHERE t.name LIKE '{prefix}-%') x""")
            print(json.dumps(rows), flush=True)
            if {row["id"] for row in rows} != set(builds):
                raise RuntimeError("logical identity changed")
            if selected is None:
                owner = next((r for r in rows if r["state"] == "admitted"), None)
                if owner:
                    selected = dict(owner)
                    subprocess.run([args.failure_helper, selected["host_id"]], check=True, timeout=120)
            if any(r["status"] in ("failed", "cancelled") for r in rows):
                raise RuntimeError("build failed; inspect printed attempt ownership")
            if rows and all(r["status"] == "ready" and r["published"] for r in rows):
                if not selected or not any(r["id"] == selected["id"] and r["attempts"] > 1
                                          and r["host_id"] != selected["host_id"]
                                          and r["attempt_id"] != selected["attempt_id"] for r in rows):
                    raise RuntimeError("interrupted build did not retry on an alternate host")
                subprocess.run(command, check=True)
                after = query(f"""SELECT coalesce(json_agg(b.id),'[]') FROM template_build b
                    JOIN template t ON t.id=b.template_id WHERE t.name LIKE '{prefix}-%'""")
                if set(after) != set(builds):
                    raise RuntimeError("unchanged seed created new logical builds")
                print("Producer smoke passed; retained templates: " + prefix)
                return
            time.sleep(2)
        raise RuntimeError("staging smoke exceeded queue/execution headroom")


if __name__ == "__main__":
    main()
