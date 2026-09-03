# production/us-west2

Production us-west2 environment built from shared modules and driven by `terraform.tfvars`.

Notes:

- `terraform.tfvars` is the deployment data entrypoint for region, zone, suffixes, subnet ranges, and Supabase config.
- Terraform seeds `environment`, `region`, `component`, and `sandbox_role` labels for deploy discovery.
- Required host labels are enforced by the shared sandbox-host module.
- The current host shape is bare metal and intended for production use.

## API client-IP attribution

The west API service currently has no external Application Load Balancer,
forwarding rule, or reserved static-IP resource managed or exposed in this
repository. `EXTERNAL_LB_FORWARDING_RULE_IP` is therefore intentionally unset:
the API resolver falls back to the transport peer and does not trust caller
supplied X-Forwarded-For values. IP-based abuse restrictions and the shared
per-IP limiter are consequently degraded in this region; team and user
restrictions remain unaffected. Cloud Run ingress remains restricted to the
internal load-balancer path.

Follow-up infrastructure work: provision the west API external Application
Load Balancer for `api-usw.superserve.ai`, expose its forwarding-rule/static-IP
resource to this Terraform root, then populate `EXTERNAL_LB_FORWARDING_RULE_IP`
and add an end-to-end X-Forwarded-For verification before enabling west client
IP attribution.
