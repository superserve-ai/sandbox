# Cloud IDS rollout

This repository now models Cloud IDS as a combination of regional endpoint
resources, packet mirroring, and log-based alerting that reuses the existing
Cloud Monitoring notification channels.

## Network disposition

| Vanta-listed network | Disposition | Notes |
| --- | --- | --- |
| `superserve-production-vpc` | Active production VPC | Cloud IDS endpoints are deployed in `production/us-east4` and `production/us-west2`, mirroring the active VM host subnets in that shared VPC. |
| `rayai-production-vpc` | Transitional legacy VPC | Still used by the existing Serverless VPC Access connector. Temporarily excluded from Vanta while connector migration and VPC retirement remain in progress. |
| `default` | Temporarily retained with justification | The default VPC still hosts `prod-nat-router` in `us-west1`; Cloud IDS is not added until that router and the remaining default-network dependency are cleaned up or explicitly justified. |

## Regional detail

- `production/us-west2` creates the regional Cloud IDS endpoint, mirrors the
  VM host subnet, and sends threat incidents to the existing monitored
  channels. Cloud Run direct VPC egress is documented as not applicable to
  Packet Mirroring.
- `production/us-east4` creates the regional Cloud IDS endpoint, mirrors the
  VM host subnet, and sends threat incidents to the existing monitored
  channels. Cloud Run direct VPC egress is documented as not applicable to
  Packet Mirroring.
- `production/us-central1` remains the shared bootstrap networking root and
  does not create a Cloud IDS endpoint.

## Architecture

- Cloud IDS runs per region because each endpoint is zonal and inspects traffic
  from its own region.
- Packet mirroring is limited to the production VM subnet in that region.
- Cloud Run Direct VPC egress is not supported by Packet Mirroring, so that
  traffic path is handled separately and is not claimed as packet-level IDS
  coverage here.
- The shared Private Service Access prerequisite for Cloud IDS is managed
  outside this repository and must be confirmed before the first apply.
- Threat findings are surfaced through log-based Cloud Monitoring alert
  policies so notifications can reuse the existing monitored destination
  without adding a webhook secret to Terraform state.
- INFORMATIONAL and LOW findings remain in Cloud Logging only and are not sent
  to the incident channel.
- MEDIUM, HIGH, and CRITICAL findings share one `WARNING` triage policy per
  endpoint. Detector severity and signature names never select the urgent path.
- Both regions retain the externally managed `TF_VAR_notification_channel_ids`
  destination in `#on-call` intentionally. The on-call responder owns routine triage
  through the normal workflow, with no new response SLA. Verify the external
  channel honors WARNING without paging; severity configuration alone cannot
  prove the external channel's notification behavior.
- Threat ID, threat name, and observed source IP form the extracted activity
  labels, scoped to the regional endpoint policy. Detector severity, destination
  IP/port, URI, and filename remain in raw logs linked from the notification;
  extracting them would create additional incident timelines.
- Native notification rate limiting is five minutes **per policy**, shared across
  all signatures, sources, and detector severities. Extracted activity labels do
  not get independent notification limits: a MEDIUM finding can suppress a notice
  for an unrelated HIGH or CRITICAL finding during that interval. Keep the prior
  five-minute limit to bound this cross-activity suppression; consolidation means
  the severity bands now share that limit. A suppressed finding is not guaranteed
  a later notification. Inactive incidents retain a separate 30-minute auto-close
  interval, which does not set the notification rate limit.
- Stable labels reduce timelines created by variable evidence; notification rate
  limiting is not a guarantee of exactly one notification per activity. Different
  signatures/sources remain distinguishable, but NAT can merge activities with
  the same signature/source and source changes can split a burst. Missing labels
  also reduce differentiation. Cloud Monitoring's policy-wide incident and
  notification quotas can prevent notifications for distinct activities (currently
  20 incidents and 20 notifications per day, and 2 new incidents per minute per
  policy); raw logs are the complete evidence source. Repeated matching entries
  can notify again after five minutes; silence permits auto-close after 30 minutes. See
  [log alert behavior and limits](https://docs.cloud.google.com/logging/docs/alerting/monitoring-logs).

## Investigation and escalation

Each notification links to the endpoint's raw findings in Logs Explorer, initially
showing the last hour. For delayed investigation, change to an absolute time range
around the incident event time, then filter by the displayed threat ID/name and
source IP. Inspect all matching findings, including detector severity, destination
IP/port, URI/filename, and timestamps; a notification is not a burst summary.

Traffic direction and sandbox/team attribution are explicitly `unknown` in the
notification. Cloud IDS's `direction` describes client/server direction, which does
not prove inbound, outbound, or internal traffic relative to the platform. See
[Cloud IDS log fields](https://docs.cloud.google.com/intrusion-detection-system/docs/logging).
Correlate both addresses/ports and the event timestamp with available network and
host logs and event-time sandbox lifecycle records. Classify inbound/outbound/internal
and sandbox/team or host/platform origin only when those records establish it.
An observed translated IP or current host mapping cannot prove historical sandbox
ownership. Outbound host traffic alone must not be called sandbox-originated.
Missing attribution is not evidence of safety.

Notifications include three direct `Runbook:` links: IDS endpoint investigation,
VMD proxy correlation, and abusive-team containment. Configure the single repository
Actions variable `RUNBOOK_BASE_URL` with the shared HTTPS runbook base URL for
production and staging. The plan and regional apply workflows pass it as
`TF_VAR_cloud_ids_runbook_base_url`; local operators must export that variable or
set `cloud_ids_runbook_base_url` in an ignored `runbooks.local.auto.tfvars.json`
file in each regional root. Replace any old URL-map entry in that file.
Terraform owns the three page IDs in the module's `runbook_ids` defaults and joins
each to the base with exactly one slash. No per-runbook or environment-specific
GitHub configuration is needed. Missing or invalid base URLs and empty page IDs
fail planning. If CI cannot see the base, set the repository variable
`RUNBOOK_BASE_URL` before retrying.

The base URL is configuration, not a credential; the IDs are visible in Terraform.
Notion authorization controls access to the runbooks. Full assembled URLs remain
clickable in notification documentation and are marked sensitive to keep them out
of routine plan output. State and saved plans still contain them and must retain
their existing access controls. Do not copy assembled internal URLs into public
PR text.

Older runbook instructions to escalate HIGH/CRITICAL solely on detector severity
or move MEDIUM to another destination are superseded by this policy. Align those
pages as an operations documentation follow-up; the on-call ownership and
independent/manual escalation rules here govern the alert.

Independent evidence of platform compromise, customer impact, or other immediate
security impact requires manually contacting the on-call responder and opening a
separate urgent incident with that evidence, using the established containment
procedure. Do not wait for the routine IDS policy. No independent automated
compromise signal is configured in this module; existing urgent policies and human
escalation operate outside its suppression window.

## Policy migration

The existing move from `ids_threats` to `ids_high_critical` is retained and chained
to `ids_triage`. Terraform updates that policy in place. The historical
`ids_medium` resource remains as a disabled retirement marker, with an explicit
dependency so Terraform expands triage coverage before disabling the old policy.
This avoids a destroy/update race that could leave MEDIUM uncovered. No second
active policy remains after a successful apply; a new installation creates the
marker disabled. Remove the marker only in a later cleanup after both regions
are verified. An interrupted apply can temporarily leave both policies active;
resume the complete plan and confirm the old policy is disabled. GCP does not
provide an atomic cross-policy cutover, so brief overlap/propagation during the
update cannot be ruled out; do not claim zero duplicate notifications at cutover.
The singular `alert_policy_name` output and both historical severity-band keys in
`alert_policy_names` resolve to the same triage policy. Consumers must not treat
those aliases as distinct policies or derive incident severity from their keys.
Endpoint threshold, mirroring, raw log collection, and channel ownership do not
change. Check the plan contains no endpoint or packet-mirroring replacement.

## Cost estimate

Cloud IDS pricing is currently:

- $1.50 per hour per running endpoint
- $0.07 per GiB inspected by the endpoint
- Packet Mirroring is included in the Cloud IDS per-GiB inspection price, so
  there is no separate packet-mirroring charge

For the current two active regional endpoints, the fixed monthly floor is about
`2 * 24 * 30 * $1.50 = $2,160` before traffic-based charges.

Additional indirect costs can come from Cloud Logging storage if the threat log
volume grows enough to exceed the free allotment.

## Validation

The focused mocked module checks require Terraform 1.7 or newer. After provider
initialization, run `terraform -chdir=infra/modules/cloud-ids test`. These checks
cover configuration contracts for both regional inputs; they do not simulate GCP
notification delivery or suppression.

Run these checks before any apply:

```sh
terraform fmt -check -recursive infra
terraform -chdir=infra/envs/production/us-west2 plan -input=false -no-color
terraform -chdir=infra/envs/production/us-east4 plan -input=false -no-color
```

Confirm the shared service-networking connection and reserved range exist
outside this repo before the first Cloud IDS apply; do not create them here.

After the endpoints are live, locate a real IDS threat log in Cloud Logging and
confirm the alert policy matches the same `logName`, `resource.type`, and
`resource.labels.id` values before relying on notification delivery.
After applying, verify actual notification output and routing in **both**
`us-east4` and `us-west2`; a plan alone does not validate GCP suppression or the
external channel. PR merge may precede this verification, but keep the work item
open until both regions' results are recorded. Record the policy/incident identifiers, event times, observed
notification counts, rendered content, and raw-log query results for each case:

| Case | Expected result |
| --- | --- |
| Same threat/source, changing URI or filename inside 30 minutes | One activity timeline with bounded notifications, WARNING urgency. |
| Same threat/source, changing destination IP/port or IDS severity | Same activity labels; no new urgent notification per variation. |
| Concurrent unrelated signatures or sources | Distinct activity labels/timelines, subject to the shared five-minute notification limit and GCP policy-wide quotas. |
| MEDIUM followed by an unrelated HIGH/CRITICAL finding | Inside five minutes, the unrelated notice can be suppressed; a new matching finding after five minutes is eligible to notify, subject to GCP quotas. No 30-minute notification limit applies. |
| Unknown ownership, including outbound host traffic | Direction and sandbox/team remain unknown; working investigation link and event-time correlation instructions, no sandbox-origin claim. |
| Independent urgent evidence during a routine suppression window | Manual contact and a separate urgent incident remain possible; routine suppression does not govern other policies. |
| MEDIUM, HIGH, and CRITICAL findings | All render WARNING and triage guidance at the existing destination without page-level handling based on detector severity. |
| INFORMATIONAL and LOW findings | Still queryable in Cloud Logging, with no incident notification. |

Confirm MEDIUM/HIGH/CRITICAL raw entries also remain queryable, including every
variable evidence field removed from notification labels. Check the investigation
link selects the right project/endpoint and test changing its time range to the
original event. Open all three runbook links as the on-call responder and confirm
they resolve to the canonical procedures. Do not inject attack traffic into production for this check; use
approved test fixtures in an isolated environment or representative existing
findings. Real delivery verification requires access to the monitored destination.

## Rollback

An alert-only rollback requires two applies and a reverse state move in **each**
regional backend. A plain code revert can destroy/recreate the retained policy.
Restoring the old settings also restores severity inflation and duplicate noise.

This procedure has not been rehearsed; forward plans and mocked module tests do
not prove rollback behavior. A rollback rehearsal is not a rollout prerequisite.
If rollback is needed, review each regional plan against the actual deployed
state and verify delivery after applying, as described below. Resource ordering
does not guarantee notification continuity during GCP propagation.

1. Pause automated Terraform applies for both regions for the entire rollback.
   Use a dedicated rollback checkout with the deployed configuration and the same
   provider lock file, workspace, backend configuration, and deployment inputs.
   Save state and plans outside the repository with restricted access; they contain
   sensitive values. From the repository root, select one region:

   ```sh
   rollback_root=infra/envs/production/us-east4
   rollback_artifacts=$(mktemp -d)
   chmod 700 "$rollback_artifacts"
   terraform -chdir="$rollback_root" state pull > "$rollback_artifacts/before.tfstate"
   terraform -chdir="$rollback_root" state list
   ```

   Confirm the backend prefix matches the selected region and state contains
   `module.cloud_ids.google_monitoring_alert_policy.ids_triage` and `ids_medium`,
   with no `ids_high_critical` or `ids_threats`. Record both policy IDs. If state
   differs (including an interrupted rollout or a removed retirement marker),
   stop and reconcile it before using this procedure.

2. For stage A, change only `enabled = false` to `enabled = true` in the current
   `google_monitoring_alert_policy.ids_medium` resource. Keep triage's full
   MEDIUM/HIGH/CRITICAL filter, settings, address, and both moved blocks intact.
   Have the runner generate and inspect the regional plan, then apply that exact
   saved plan through the authorized deployment process:

   ```sh
   terraform -chdir="$rollback_root" plan -input=false -out="$rollback_artifacts/enable-medium.tfplan"
   terraform -chdir="$rollback_root" apply "$rollback_artifacts/enable-medium.tfplan"
   ```

   Require only an in-place enable of the existing MEDIUM policy, with no changes
   to triage, channels, endpoint, mirroring, or unrelated resources. Verify in
   Monitoring that MEDIUM is enabled and covers the regional endpoint at the
   existing destination before continuing. Both policies temporarily match MEDIUM;
   GCP propagation can produce duplicate routine notifications during this overlap.

3. For stage B, restore the Cloud IDS module's `main.tf`, `outputs.tf`, and
   `variables.tf` from the reviewed pre-consolidation revision that contains the
   two enabled `ids_medium` and `ids_high_critical` policies. Remove the now
   unsupported `runbook_base_url` argument from the regional module calls; retain all
   other current regional configuration and deployment inputs. Do not revert the
   whole regional root or unrelated changes. The old module must retain the
   historical `ids_threats` to `ids_high_critical` move and must have no move to
   `ids_triage`. Before any plan/apply of this configuration, back up the stage A
   state and rename the retained policy in the selected regional backend:

   ```sh
   terraform -chdir="$rollback_root" state pull > "$rollback_artifacts/medium-enabled.tfstate"
   terraform -chdir="$rollback_root" state mv -lock-timeout=5m \
     'module.cloud_ids.google_monitoring_alert_policy.ids_triage' \
     'module.cloud_ids.google_monitoring_alert_policy.ids_high_critical'
   terraform -chdir="$rollback_root" state list
   terraform -chdir="$rollback_root" plan -input=false -out="$rollback_artifacts/restore-policies.tfplan"
   ```

   Confirm `ids_triage` is absent and `ids_high_critical` has the recorded triage
   policy ID. The runner must inspect this post-move plan: both policies update
   in place, MEDIUM stays enabled, and only the retained policy narrows to
   HIGH/CRITICAL. Reject any policy creation, deletion, replacement, channel change,
   or endpoint/mirroring/unrelated change. Review restored output aliases as well:
   the severity-band keys once again identify two distinct policies.

4. Apply the reviewed stage B plan through the authorized deployment process:

   ```sh
   terraform -chdir="$rollback_root" apply "$rollback_artifacts/restore-policies.tfplan"
   ```

   Verify both original policy IDs remain, MEDIUM and HIGH/CRITICAL filters are
   disjoint and enabled, delivery still uses the existing destination, and raw
   logs remain queryable. Have the runner confirm a subsequent regional plan has
   no pending changes. If interrupted after the state move, keep automation paused
   and resume with the stage B configuration and a fresh reviewed plan; never apply
   the forward configuration or blindly push an old state backup over live state.

5. Repeat steps 1–4 with `rollback_root=infra/envs/production/us-west2` and a new
   artifact directory, starting from the deployed configuration for stage A.
   Each region has independent state; moving one does not migrate the other.
   Resume automation only when its configuration matches the final rollback in
   both regions. Record both regions' plans and live delivery checks.

The following steps are only for a full Cloud IDS teardown:

1. Remove the regional IDS endpoint and packet mirroring resources first.
2. Remove the log-based alert policy after the endpoints are gone.
3. Keep the shared Private Service Access plumbing outside this repo unless a
   separate bootstrap workflow owns its lifecycle, and remove it only after the
   last endpoint is deleted and the VPC no longer needs Cloud IDS.
4. Re-run the same plans to confirm Terraform only wants to remove the intended
   objects.

## Recheck

After the plan is applied, re-run the two Cloud IDS Vanta checks and verify
that the alert policy delivers to the monitored destination used by the other
production infrastructure alerts.
