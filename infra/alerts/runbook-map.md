# Alert response mapping

Alerts use the repository Actions variable `RUNBOOK_BASE_URL`, matching Cloud IDS. Terraform combines that HTTPS base with one page ID per procedure from `infra/modules/alert-runbooks`. The same destinations apply to staging and production. Complete URLs stay out of source control; page IDs are not credentials and access is controlled by the documentation provider.

Workflows pass the shared variable as `TF_VAR_alert_runbook_base_url` for these alerts and `TF_VAR_cloud_ids_runbook_base_url` for Cloud IDS. Local Terraform runs use the corresponding inputs. Trailing slashes are normalized before appending a page ID. No full-URL map is required.

| Policy and variant | Runbook key | Family | Component | Failure family | Operation |
| --- | --- | --- | --- | --- | --- |
| `sandbox_lifecycle_latency[create]` | `lifecycle_latency` | `sandbox_lifecycle` | `api` | `latency` | `create` |
| `sandbox_lifecycle_latency[resume]` | `lifecycle_latency` | `sandbox_lifecycle` | `api` | `latency` | `resume` |
| `sandbox_lifecycle_latency[pause]` | `lifecycle_latency` | `sandbox_lifecycle` | `api` | `latency` | `pause` |
| `sandbox_lifecycle_latency[delete]` | `lifecycle_latency` | `sandbox_lifecycle` | `api` | `latency` | `delete` |
| `sandbox_failed` | `lifecycle_failure` | `sandbox_lifecycle` | `api` | `lifecycle_failure` | — |
| `backup[upload_failures]` | `backup_pipeline` | `backup` | `vmd` | `backup_upload_failure` | — |
| `backup[backlog_age]` | `backup_pipeline` | `backup` | `vmd` | `backup_backlog` | — |
| `backup[pause_hook_p99]` | `backup_pipeline` | `backup` | `vmd` | `backup_latency` | — |
| `backup[outbox_stalled]` | `backup_pipeline` | `backup` | `vmd` | `backup_outbox` | — |
| `backup[backup_disabled]` | `backup_pipeline` | `backup` | `vmd` | `backup_disabled` | — |
| `backup_coverage[uncovered_paused]` | `backup_coverage` | `backup` | `api` | `backup_coverage` | — |
| `backup_coverage[uncovered_paused_<region>]` | `backup_coverage` | `backup` | `api` | `backup_coverage` | — |
| `backup_coverage[uncovered_orphaned]` | `backup_coverage` | `backup` | `api` | `backup_coverage` | — |
| `host_disk[root_fs_warning]` | `host_disk` | `host` | `host` | `capacity` | — |
| `host_disk[root_fs_critical]` | `host_disk` | `host` | `host` | `capacity` | — |
| `launch_path[launcher_not_ready]` | `vmd_launch` | `vmd` | `vmd` | `launcher_unavailable` | — |
| `launch_path[netns_accumulation]` | `vmd_network` | `vmd` | `vmd` | `network_capacity` | — |
| `launch_path[netns_runaway]` | `vmd_network` | `vmd` | `vmd` | `network_capacity` | — |
| `compute_instance_cpu[each]` | `host_cpu` | `host` | `host` | `capacity` | — |
| `host_maintenance_events[each]` | `host_maintenance` | `host` | `host` | `maintenance` | — |
| `ids_triage` | Cloud IDS investigation | `cloud_ids` | `vmd` | `security_finding` | — |
| `ids_medium` (disabled) | Cloud IDS investigation | `cloud_ids` | `vmd` | `security_finding` | — |

Each procedure has its own page under Operations / Runbooks. The nine newer destinations are skeletons awaiting procedure content and testing. Fill those pages in place to preserve the committed IDs; do not substitute a generic index. Configure the shared base URL before applying, then inspect rendered policy links and labels. When structured Monitoring notifications are ingested, inspect one representative payload for the labels.
