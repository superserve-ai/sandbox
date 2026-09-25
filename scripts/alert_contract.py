"""Reviewed inventory for Terraform-managed alert policies."""

from pathlib import Path
import re

POLICIES = {
    "compute_instance_cpu": ("host_cpu", "host", "host", "capacity", ["each"]),
    "host_maintenance_events": ("host_maintenance", "host", "host", "maintenance", ["each"]),
    "sandbox_lifecycle_latency": ("lifecycle_latency", "sandbox_lifecycle", "api", "latency", ["create", "resume", "pause", "delete"]),
    "sandbox_failed": ("lifecycle_failure", "sandbox_lifecycle", "api", "lifecycle_failure", ["aggregate"]),
    "backup": ("backup_pipeline", "backup", "vmd", "variant", ["upload_failures", "backlog_age", "pause_hook_p99", "outbox_stalled", "backup_disabled"]),
    "backup_coverage": ("backup_coverage", "backup", "api", "backup_coverage", ["uncovered_paused", "uncovered_paused_<region>", "uncovered_orphaned"]),
    "host_disk": ("host_disk", "host", "host", "capacity", ["root_fs_warning", "root_fs_critical"]),
    "launch_path": ("vmd_launch|vmd_network", "vmd", "vmd", "variant", ["launcher_not_ready", "netns_accumulation", "netns_runaway"]),
    "ids_triage": ("investigation", "cloud_ids", "vmd", "security_finding", ["triage"]),
    "ids_medium": ("investigation", "cloud_ids", "vmd", "security_finding", ["retired"]),
}


def policy_inventory(root):
    errors = []
    found = {}
    for path in (root / "infra").rglob("*.tf"):
        source = path.read_text()
        for name in re.findall(r'(?m)^resource\s+"google_monitoring_alert_policy"\s+"([^"]+)"\s*\{', source):
            location = str(path.relative_to(root))
            found.setdefault(name, []).append(location)
            if name not in POLICIES:
                errors.append(f"{location}: google_monitoring_alert_policy.{name}: missing from reviewed inventory")
    for name in POLICIES:
        locations = found.get(name, [])
        if not locations:
            errors.append(f"infra/: google_monitoring_alert_policy.{name}: missing policy definition")
        elif len(locations) > 1:
            errors.append(f"{', '.join(locations)}: google_monitoring_alert_policy.{name}: duplicate definitions")
    return errors


def variant_inventory(root):
    errors = []
    generated = {
        "backup": ("backup-alerts.tf", "backup_alert_conditions"),
        "backup_coverage": ("backup-alerts.tf", "backup_coverage_alert_conditions"),
        "host_disk": ("backup-alerts.tf", "host_disk_alert_conditions"),
        "launch_path": ("launch-path-alerts.tf", "launch_path_alert_conditions"),
    }
    for name, (filename, local) in generated.items():
        path = root / "infra/modules/observability" / filename
        source = path.read_text()
        start = re.search(rf"(?m)^  {local}\s*=", source)
        end = re.search(rf'(?m)^resource "google_monitoring_alert_policy" "{name}" \{{', source)
        variants = set()
        if start and end and start.end() < end.start():
            section = source[start.end():end.start()]
            variants.update(re.findall(r"(?m)^\s+([a-z][a-z0-9_]*)\s*=\s*\{", section))
            for value in re.findall(r'(?m)^\s*(?:for region in local\.backup_coverage_regions\s*:\s*)?"([^"]+)"\s*=>\s*\{', section):
                if re.fullmatch(r"[a-z][a-z0-9_]*\$\{region\}", value):
                    variants.add(value.replace("${region}", "<region>"))
                else:
                    errors.append(f"{path.relative_to(root)}: google_monitoring_alert_policy.{name}: unsupported generated variant key {value}")
        expected = set(POLICIES[name][4])
        for variant in sorted(variants - expected):
            errors.append(f"{path.relative_to(root)}: google_monitoring_alert_policy.{name}[{variant}]: missing from reviewed inventory")
        for variant in sorted(expected - variants):
            errors.append(f"{path.relative_to(root)}: google_monitoring_alert_policy.{name}[{variant}]: missing generated variant definition")

    path = root / "infra/envs/production/us-central1/sandbox-lifecycle-alerts.tf"
    source = path.read_text()
    match = re.search(r"(?ms)^  lifecycle_latency_alerts = \{\n(.*?)^  \}", source)
    variants = set(re.findall(r"(?m)^    ([a-z][a-z0-9_]*)\s*=\s*\{", match.group(1))) if match else set()
    expected = set(POLICIES["sandbox_lifecycle_latency"][4])
    for variant in sorted(variants - expected):
        errors.append(f"{path.relative_to(root)}: google_monitoring_alert_policy.sandbox_lifecycle_latency[{variant}]: missing from reviewed inventory")
    for variant in sorted(expected - variants):
        errors.append(f"{path.relative_to(root)}: google_monitoring_alert_policy.sandbox_lifecycle_latency[{variant}]: missing generated variant definition")
    return errors


def mapping_rows(root):
    path = root / "infra/alerts/runbook-map.md"
    rows = {}
    for line in path.read_text().splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) == 6 and cells[0].startswith("`"):
            rows.setdefault(cells[0], []).append(cells[1:])
    return rows


def reviewed_variants():
    for name, (_, _, _, _, variants) in POLICIES.items():
        for variant in variants:
            label = f"`{name}`" if variant in ("aggregate", "triage", "retired") else f"`{name}[{variant}]`"
            if variant == "retired":
                label += " (disabled)"
            yield name, variant, label
