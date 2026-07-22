# production/us-central1

Production us-central1 environment built from shared modules and driven by `terraform.tfvars`.

Notes:

- `terraform.tfvars` is the deployment data entrypoint for region, zone, suffixes, subnet ranges, and Supabase config.
- Terraform seeds `environment`, `region`, `component`, and `sandbox_role` labels for deploy discovery.
- Required host labels are enforced by the shared sandbox-host module.
- The current host shape is bare metal and intended for production use.
