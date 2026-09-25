# Alert response mapping

Each row names a logical destination in the private `ALERT_RUNBOOK_URLS` JSON map. Supply direct runbook pages before planning or applying alert-bearing roots. Production and staging share the input shape; operators may use distinct pages. The Cloud IDS module uses its existing validated `RUNBOOK_BASE_URL` plus the investigation page ID. No destination is stored here. The URL checks establish syntax and wiring only; operators verify that each page has the right procedure after deployment.

| Policy and variant | Runbook input | Family | Component | Failure family | Operation |
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

Reuse alert-specific pages where available. For missing procedures, create sparse pages under Operations / Runbooks from the canonical top-level Runbook Template after merge. Never use a generic index as a destination. Configure the private JSON map and existing Cloud IDS base URL before applying new inputs, then inspect rendered policy links and labels. When structured Monitoring notifications are ingested, inspect one representative payload for the labels.
