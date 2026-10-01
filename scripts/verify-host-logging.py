#!/usr/bin/env python3
"""Static contract checks for Terraform-managed OTel host logging."""

from pathlib import Path
import re
import sys


REQUIRED_FILES = (
    "infra/modules/host-logging/main.tf",
    "infra/modules/host-logging/variables.tf",
    "infra/modules/host-logging/templates/otel-logs.yaml.tftpl",
    "infra/modules/host-logging/templates/otel-logs.service.tftpl",
    "infra/modules/host-logging/templates/reconcile.sh.tftpl",
    "infra/modules/host-logging/templates/validate.sh.tftpl",
    "infra/modules/observability/host-logging-alerts.tf",
)

EXPORT_FAILURE_MESSAGE_PATTERN = re.compile(
    r"(?i)(?:failed to flush chunk|export(?:er|ing)?\s+failed|permission denied|\bdropped?\b|\bdrop\b)"
)


def export_failure_message_matches(message: str) -> bool:
    return EXPORT_FAILURE_MESSAGE_PATTERN.search(message) is not None


def verify(root: Path) -> list[str]:
    errors = []
    for relative in REQUIRED_FILES:
        if not (root / relative).is_file():
            errors.append(f"missing required host-logging file: {relative}")

    module = (root / REQUIRED_FILES[0]).read_text() if (root / REQUIRED_FILES[0]).exists() else ""
    variables = (root / REQUIRED_FILES[1]).read_text() if (root / REQUIRED_FILES[1]).exists() else ""
    config = (root / REQUIRED_FILES[2]).read_text() if (root / REQUIRED_FILES[2]).exists() else ""
    service = (root / REQUIRED_FILES[3]).read_text() if (root / REQUIRED_FILES[3]).exists() else ""
    reconcile = (root / REQUIRED_FILES[4]).read_text() if (root / REQUIRED_FILES[4]).exists() else ""
    validate = (root / REQUIRED_FILES[5]).read_text() if (root / REQUIRED_FILES[5]).exists() else ""
    alerts = (root / REQUIRED_FILES[6]).read_text() if (root / REQUIRED_FILES[6]).exists() else ""
    normalized_alerts = alerts.replace(r'\"', '"')

    for required in ("journald:", "file_storage/cursor", "file_storage/queue", "googlecloud:",
                     "parse_application_message", "filter/info_plus", "host_logging.parse_outcome"):
        if required not in config:
            errors.append(f"OTel config missing {required} contract")
    for required in ("google_os_config_os_policy_assignment", "roles/logging.logWriter",
                     "SystemMaxUse", "SystemKeepFree", "otel-logs.service"):
        if required not in module and required not in service:
            errors.append(f"Terraform host logging module missing {required}")
    for required in ("otelcol-contrib", "sha256sum", "validate --config", "activation_committed=1",
                     "trap rollback EXIT", "superserve-otel-logs.service"):
        if required not in reconcile:
            errors.append(f"reconciliation missing {required}")
    if "superserve-otel-collector.service" in service:
        errors.append("logs service must not reuse the metrics collector unit")
    if "ops-agent" in config.lower() or "google-cloud-ops-agent" in config.lower():
        errors.append("OTel config must not retain Ops Agent sources")
    if "otel_release_sha256" not in variables or not re.search(r"[0-9a-f]{64}", variables):
        errors.append("selected OTel release must carry a pinned SHA-256 digest")
    if "log_id(\"superserve_host_logs\")" not in normalized_alerts:
        errors.append("export failure alert must consume the OTel host-log stream")
    if "absent(" not in normalized_alerts or "absent_over_time(" not in normalized_alerts:
        errors.append("alerts must cover never-seen hosts and retained-history lag")
    if "otelcol_process_uptime" not in alerts and "heartbeat_metric_type" not in alerts:
        errors.append("missing-heartbeat alert must remain independent of log export")
    if "storage: file_storage/cursor" not in validate or "storage: file_storage/queue" not in validate:
        errors.append("validation must check persistent cursor and queue state")
    return errors


if __name__ == "__main__":
    failures = verify(Path(__file__).resolve().parents[1])
    print("\n".join(failures) if failures else "Host logging contract OK", file=sys.stderr if failures else sys.stdout)
    raise SystemExit(bool(failures))
