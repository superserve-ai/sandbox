#!/usr/bin/env python3
"""Create a public-safe summary from a control-plane rollout evidence tree.

The verifier's full evidence is useful for operators but contains production
principals, resource names, IAM policies, and command output.  This helper is
the boundary before a GitHub artifact upload: it emits only aggregate check
results and never copies files from the private evidence directory.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cell", required=True)
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser.parse_args()


def load_summary(input_dir: Path, cell: str) -> dict[str, object]:
    evidence_path = input_dir / "evidence.json"
    if not evidence_path.is_file():
        return {
            "format": "control-plane-identity-public-summary-v1",
            "cell": cell,
            "status": "INCOMPLETE",
            "checks": [],
            "reason": "private verifier evidence was not produced",
        }

    try:
        evidence = json.loads(evidence_path.read_text())
    except (OSError, json.JSONDecodeError):
        return {
            "format": "control-plane-identity-public-summary-v1",
            "cell": cell,
            "status": "INCOMPLETE",
            "checks": [],
            "reason": "private verifier evidence was unreadable",
        }

    raw_checks = evidence.get("checks") if isinstance(evidence, dict) else None
    checks: list[dict[str, object]] = []
    if isinstance(raw_checks, list):
        for index, raw in enumerate(raw_checks, 1):
            if not isinstance(raw, dict):
                continue
            name = raw.get("name")
            status = raw.get("status")
            if isinstance(name, str):
                # Keep only the check label and verdict.  In particular, do
                # not retain argv, principals, resources, access decisions,
                # or command output from the private evidence index.
                safe_name = name if re.fullmatch(r"[a-z0-9-]+", name) else f"check-{index}"
                checks.append({"name": safe_name, "status": "PASS" if status == "PASS" else "FAIL"})

    status = evidence.get("status") if isinstance(evidence, dict) else None
    status = "PASS" if status == "PASS" else "FAIL" if status == "FAIL" else "INCOMPLETE"
    if status == "PASS" and any(check["status"] != "PASS" for check in checks):
        status = "FAIL"

    return {
        "format": "control-plane-identity-public-summary-v1",
        "cell": cell,
        "status": status,
        "checks": checks,
        "check_count": len(checks),
        "passed_count": sum(check["status"] == "PASS" for check in checks),
    }


def write_summary(input_dir: Path, output_dir: Path, cell: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = load_summary(input_dir, cell)
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (output_dir / "summary.txt").write_text(
        "control-plane identity rollout summary\n"
        f"cell={cell}\n"
        f"status={summary['status']}\n"
        f"check_count={summary.get('check_count', 0)}\n"
        f"passed_count={summary.get('passed_count', 0)}\n"
    )


def main() -> int:
    args = parse_args()
    write_summary(args.input_dir, args.output_dir, args.cell)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
