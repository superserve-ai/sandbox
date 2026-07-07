# New Region Plan Review

## Status

The plan succeeded and rendered cleanly to [plan.txt](/home/lando/superserve-ai/sandbox/infra/envs/new-region/plan.txt).

Plan summary:

- `27` resources to create
- `0` resources to modify
- `0` resources to delete
- `0` resources to replace

## Resources Terraform plans to create

- `module.api.google_cloud_run_v2_service.this`
- `module.artifact_storage.google_artifact_registry_repository.repositories["superserve"]`
- `module.artifact_storage.google_storage_bucket.buckets["superserve_artifacts"]`
- `module.iam.google_service_account.service_accounts["superserve_api"]`
- `module.iam.google_service_account.service_accounts["superserve_build"]`
- `module.iam.google_service_account.service_accounts["superserve_github_actions"]`
- `module.network.google_compute_firewall.rules["allow_proxy_lb"]`
- `module.network.google_compute_firewall.rules["allow_vmd_grpc"]`
- `module.network.google_compute_network.this`
- `module.network.google_compute_subnetwork.connector[0]`
- `module.network.google_compute_subnetwork.primary`
- `module.network.google_vpc_access_connector.this[0]`
- `module.proxy_lb.google_certificate_manager_certificate.certificates["primary"]`
- `module.proxy_lb.google_certificate_manager_certificate_map.this[0]`
- `module.proxy_lb.google_certificate_manager_certificate_map_entry.entries["primary"]`
- `module.proxy_lb.google_certificate_manager_dns_authorization.dns_authorizations["primary"]`
- `module.proxy_lb.google_compute_backend_service.services["ssl_proxy"]`
- `module.proxy_lb.google_compute_backend_service.services["tcp_redirect"]`
- `module.proxy_lb.google_compute_global_address.addresses["primary"]`
- `module.proxy_lb.google_compute_global_forwarding_rule.rules["ssl_proxy"]`
- `module.proxy_lb.google_compute_global_forwarding_rule.rules["tcp_redirect"]`
- `module.proxy_lb.google_compute_health_check.checks["proxy"]`
- `module.proxy_lb.google_compute_health_check.checks["redirect"]`
- `module.proxy_lb.google_compute_instance_group.unmanaged[0]`
- `module.proxy_lb.google_compute_target_ssl_proxy.ssl["ssl_proxy"]`
- `module.proxy_lb.google_compute_target_tcp_proxy.tcp["tcp_redirect"]`
- `module.sandbox_host.google_compute_instance.this`

## Resources Terraform plans to modify

- No infrastructure resources are planned for modification.
- Terraform does show output value changes after apply, but those are output recalculations, not resource modifications.

## Resources Terraform plans to delete

- None.

## Resources Terraform plans to replace

- None.

## Unknowns and manual inputs needed

- The Cloud Run image is still a placeholder:
  - `us-east1-docker.pkg.dev/rayai-dev/superserve-new-region-use1/controlplane:replace-me`
- The VM startup script is still a placeholder:
  - `replace-with-managed-startup-script`
- The current sandbox host is explicitly a VM placeholder, not the final bare-metal production shape:
  - `sandbox_platform=vm-placeholder`
- These Secret Manager secrets must exist before apply:
  - `database-url-new-region`
  - `internal-api-token-new-region`
  - `sandbox-access-token-seed-new-region`
  - `secretsproxy-signing-key-new-region`
- DNS must exist for Certificate Manager authorization and wildcard routing:
  - `new-region-sandbox.superserve.ai`
  - `*.new-region-sandbox.superserve.ai`
- This configuration still assumes a single VMD host and single unmanaged instance group for the first environment rollout.

## Safety for human review

- Yes, this plan is safe for human review.
- It matches the expected shape for a new environment rollout: creates only, with no deletes and no replacements.
- It is not yet safe to apply blindly because the placeholder image, startup script, DNS prerequisites, secrets, and bare-metal host model are still not final.
