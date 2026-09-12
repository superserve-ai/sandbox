variable "peer_ca_operator_members" {
  type        = set(string)
  default     = ["user:alejandro@superserve.ai"]
  description = "Reviewed user/group IAM principals allowed to impersonate the staging peer issuer. No grant by default."
}

module "peer_ca" {
  source            = "../../../modules/peer-ca"
  project_id        = local.project_id
  region            = local.region
  name              = "superserve-peer-staging"
  issuer_account_id = "vmd-peer-issuer-staging"
  spiffe_uri        = "spiffe://${module.peer_identity.creation_identity}"
  operator_members  = var.peer_ca_operator_members
}

output "peer_ca_pool_resource_name" {
  value = module.peer_ca.pool_resource_name
}
output "peer_ca_issuer_service_account_email" {
  value = module.peer_ca.issuer_service_account_email
}
output "peer_ca_issuance_policy" {
  description = "Public custody/policy fields for operator issuance; merge a reviewed hosts allowlist before use."
  value       = module.peer_ca.issuance_policy
}
