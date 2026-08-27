# observability

Terraform support for shared observability resources.

Current scope:

- Cloud Monitoring dashboards from checked-in JSON definitions
- Terraform-managed Compute Engine CPU saturation alert policies
- Terraform-managed sandbox lifecycle latency and failed-transition alert policies

The failed-transition policy alerts on `error`, `timeout`, and `client_error`
results. `conflict` results are excluded because they describe expected
concurrency/idempotency behavior. The condition groups the increase by the
bounded `operation`, `result`, `region`, and `host_id` dimensions, preserving
the affected operation and cell without adding a `sandbox_id` label. Use
structured logs to identify individual sandboxes when investigating an alert.

Although the policy is fleet-wide, it is instantiated once by the static
`production/us-central1` Terraform root. That root is the state owner; it does
not limit the regions covered by the project-wide metric.

Alert policies use the existing Cloud Monitoring notification channel resource
names supplied by `notification_channel_ids`. Every channel must belong to the
configured project. The channel itself, including any Slack webhook credential,
is managed outside this module and is never placed in Terraform configuration
or state.

Still intentionally out of scope here:

- log buckets
- uptime checks
