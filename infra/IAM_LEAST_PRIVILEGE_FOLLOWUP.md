# Follow-up: reduce predefined deployer administrator roles

## Purpose

The current Terraform change remediates the compliance finding for primitive
Owner, Editor, and Viewer roles. It does not claim that every remaining
predefined deployer role is least privilege.

## Roles requiring permission-usage analysis

- `roles/compute.instanceAdmin.v1`
- `roles/compute.networkAdmin`
- `roles/compute.securityAdmin`
- `roles/compute.loadBalancerAdmin`
- `roles/compute.osAdminLogin`
- `roles/iap.tunnelResourceAccessor`
- `roles/run.admin`
- `roles/artifactregistry.writer`
- `roles/vpcaccess.admin`
- `roles/monitoring.editor`
- `roles/secretmanager.viewer`
- `roles/iam.serviceAccountViewer`

The service-account-user grants are already resource-scoped to the two runtime
service accounts and should be reviewed separately from project-level roles.

## Follow-up acceptance criteria

1. Collect Cloud Audit Logs or equivalent permission-usage evidence for normal
   deployment and rollback workflows.
2. Map each observed permission to the workflow step that requires it.
3. Replace broad predefined roles with narrower predefined roles or a reviewed
   custom role where operationally safe.
4. Scope grants to individual resources when supported.
5. Separate network/security administration from routine application deploys if
   those permissions are not needed on every run.
6. Document every retained broad role with owner, business justification,
   compensating controls, and a review date.
7. Validate and plan without applying, then test through the approved staging
   and production rollout process.

Track this work separately if the primitive-role compliance remediation is closed
before the broader least-privilege work is complete.
