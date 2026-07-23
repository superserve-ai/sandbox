# observability

Terraform support for shared observability resources.

Current scope:

- Cloud Monitoring dashboards from checked-in JSON definitions
- Terraform-managed Compute Engine CPU saturation alert policies

Alert policies use the existing Cloud Monitoring notification channel resource
names supplied by `notification_channel_ids`. Every channel must belong to the
configured project. The channel itself, including any Slack webhook credential,
is managed outside this module and is never placed in Terraform configuration
or state.

Still intentionally out of scope here:

- log buckets
- uptime checks
