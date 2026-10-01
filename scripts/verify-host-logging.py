#!/usr/bin/env python3
"""Static contract checks for Terraform-managed host logging."""

from pathlib import Path
import sys


REQUIRED_FILES = (
    "infra/modules/host-logging/main.tf",
    "infra/modules/host-logging/variables.tf",
    "infra/modules/host-logging/templates/ops-agent.yaml.tftpl",
    "infra/modules/host-logging/templates/reconcile.sh.tftpl",
    "infra/modules/host-logging/templates/validate.sh.tftpl",
    "infra/modules/observability/host-logging-alerts.tf",
)


def verify(root: Path) -> list[str]:
    errors = []
    for relative in REQUIRED_FILES:
        if not (root / relative).is_file():
            errors.append(f"missing required host-logging file: {relative}")

    config = (root / REQUIRED_FILES[2]).read_text() if (root / REQUIRED_FILES[2]).exists() else ""
    module = (root / REQUIRED_FILES[0]).read_text() if (root / REQUIRED_FILES[0]).exists() else ""
    reconcile = (root / REQUIRED_FILES[3]).read_text() if (root / REQUIRED_FILES[3]).exists() else ""
    alerts = (root / REQUIRED_FILES[5]).read_text() if (root / REQUIRED_FILES[5]).exists() else ""
    if "systemd_journald" not in config:
        errors.append("Ops Agent config must use systemd_journald")
    if "syslog" in config and "syslog-file" in config:
        errors.append("default syslog-file ingestion must not overlap journald")
    for required in ("parse_json", "exclude_logs", "redact_sensitive_fields", "hostmetrics"):
        if required not in config:
            errors.append(f"Ops Agent config missing {required} contract")
    for required in ("google_os_config_os_policy_assignment", "roles/logging.logWriter", "SystemMaxUse", "SystemKeepFree"):
        if required not in module and required not in (root / REQUIRED_FILES[3]).read_text():
            errors.append(f"Terraform host logging module missing {required}")
    if 'id = "ops-agent-package"' in module:
        errors.append("Ops Agent package must not mutate before staged validation")
    if "timeout \"${package_operation_timeout_seconds}s\"" not in reconcile:
        errors.append("package diagnosis/install operations must have an explicit timeout")
    if "activation_committed=1" not in reconcile or "trap on_exit EXIT" not in reconcile:
        errors.append("activation must retain rollback state until commit")
    if ("EXTRACT(labels.instance_name)" in alerts or
            "EXTRACT(resource.labels.instance_id)" not in alerts):
        errors.append("heartbeat metric must extract the numeric resource instance identity")
    if "allowlisted_application_fields" not in config or "drop_unallowlisted_payload" not in config:
        errors.append("Ops Agent config must remove unallowlisted structured payload fields")
    if 'log_id("ops_agent_self_log_files")' not in alerts or "jsonPayload.message" not in alerts:
        errors.append("export failure alert must match the explicit self-log receiver payload")
    return errors


if __name__ == "__main__":
    failures = verify(Path(__file__).resolve().parents[1])
    print("\n".join(failures) if failures else "Host logging contract OK", file=sys.stderr if failures else sys.stdout)
    raise SystemExit(bool(failures))
