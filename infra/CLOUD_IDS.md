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
- Threat findings are surfaced through a log-based Cloud Monitoring alert so
  notifications can reuse the existing monitored destination without adding a
  webhook secret to Terraform state.

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

## Rollback

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
