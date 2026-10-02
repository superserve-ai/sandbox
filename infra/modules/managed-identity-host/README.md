# Creation-time managed identity host

Opt-in host module for new VMs requiring Managed Workload Identity certificates
in the Compute create request. Staging uses this module for its already-created identity host; other host modules are unchanged. This module
pins Google Beta 8.2.0; use a separately reviewed root/provider upgrade when
adopting it. Do not change an existing module address without reviewing state
migration and replacement consequences.

Create trust-domain/namespace/identity policy first, then pass its identity to
`managed_workload_identity`. Feed the resulting `instance_id` into peer identity
attestation reconciliation with `identity_at_creation = true`; that flow verifies
creation-time configuration and never retrofits the instance.

The sandbox data disk is an externally managed resource supplied through
`sandbox_data_disk`. It is attached, not owned or recreated by this module.
The boot disk belongs to the instance. `prevent_destroy` requires a separate
reviewed code change for any destructive replacement, including `-replace`.
Admission labels can change in place without authorizing replacement.

Run `terraform init -backend=false` and `terraform test` in this module to check
the mocked create request, data attachment, identity output and label lifecycle.
