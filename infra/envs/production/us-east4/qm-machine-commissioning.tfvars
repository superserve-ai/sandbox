# Explicit -var-file candidate; ordinary Terraform runs do not load this file.
# Values describe proposed effects, not readiness. Applying requires the
# commissioning approval and preactivation receipts in the identity runbook.
qm_machine_identity_activation = {
  contract_revision = "machine-identity-v1"
  environment       = "production"
  ownership_ready   = true
  verifier_ready    = true
  operator_ready    = true
}
