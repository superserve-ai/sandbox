# infra

Terraform skeleton layout for Superserve GCP adoption.

- `modules/` defines resource-area contracts
- `envs/` wires those contracts into staging, production, and a greenfield new-region target

The current Terraform-managed Compute Engine inventory for Vanta is:

| Environment | Region | Instance | Status |
| --- | --- | --- | --- |
| staging | us-central1 | `superserve-vmd-staging` | Managed by Terraform |
| production | us-west2 | `superserve-vmd-usw2` | Managed by Terraform |
| production | us-east4 | `superserve-vmd-use4` | Managed by Terraform |
| production | us-central1 | none | Decommissioned, no Terraform-managed instance remains |

Each live instance is managed through the shared `sandbox-host` module and
receives the required labels on the actual instance label map:

- `environment`
- `managed_by`
- `region`
- `owner`
- `project`
- `dataclassification`
- `application`

Role-specific labels such as `component`, `sandbox_role`, `sandbox_status`,
and `goog-ops-agent-policy` remain instance-specific where needed. No
non-Terraform Compute Engine instances are documented in this repository, so
there are no remaining exceptions to track here.

The production roots still configure a shared Compute Engine CPU alert for
each Terraform-managed sandbox host. The alert fires when the 60-second mean
CPU utilization is above 80% for 15 minutes, with a 15-minute notification
rate limit and 30-minute auto-close. Notifications are sent to the existing
monitored Cloud Monitoring channel names supplied through
`TF_VAR_notification_channel_ids`; the channel and its Slack credential are
owned outside this repository.

Before the first apply, the infrastructure owner must compare this inventory
with any Vanta finding and run read-only checks such as
`gcloud monitoring policies list --project PROJECT_ID` filtered for each
instance name. If an existing policy covers a host, import or correct that
policy instead of creating a duplicate. The owner must also verify the
configured channel with `gcloud monitoring channels describe CHANNEL_ID`; this
checks channel ownership and delivery configuration without exposing a Slack
webhook credential. The reusable module contains one policy per instance only
because the instance-ID filter keeps each host's evidence and response path
unambiguous.

For an existing matching policy, use its full Monitoring policy name with
`terraform import module.observability.google_monitoring_alert_policy.compute_instance_cpu[\"sandbox_host\"] POLICY_NAME`
before planning. If the policy is not a match, update it in place or remove it
from the state/configuration deliberately before creating the managed policy.

For a review-only plan, supply the same variable as a Terraform list literal,
for example:

```sh
TF_VAR_notification_channel_ids='["projects/example-project/notificationChannels/123456789"]' \
  terraform -chdir=infra/envs/production/us-central1 plan -input=false -no-color -out=tfplan
scripts/sanitize-terraform-plan.sh infra/envs/production/us-central1/tfplan > plan.txt
```

Infrastructure Operations owns these alerts. On notification, verify the
metric and active workload, inspect host and sandbox capacity, then scale or
drain the host if saturation persists. Roll back by removing the alert policy
configuration from the relevant environment and planning the deletion; do not
apply that plan until the owner confirms the channel and policy are no longer
needed. After deployment, recheck the Vanta control for every production host
and retain the sanitized plan as evidence. The plan command documented here is
review-only; the repository's explicitly authorized production workflows can
apply Terraform changes after their normal approval gates.
