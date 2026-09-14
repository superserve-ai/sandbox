# Manual-only identity for the east cell; do not retrofit MWI on its Z3 hosts.
# Match the peer-identity module's cell/project URI convention without its
# host configuration side effects.
data "google_project" "peer_ca" {
  project_id = local.project_id
}

locals {
  peer_spiffe_uri = "spiffe://vmd-peer-production-use4.global.${data.google_project.peer_ca.number}.workload.id.goog/ns/vmd/sa/vmd-peer-proxy"
}

variable "peer_ca_operator_members" {
  type        = set(string)
  default     = []
  description = "Reviewed user/group IAM principals allowed to impersonate the production us-east4 peer issuer. No grant by default."
}

resource "google_project_service" "peer_privateca" {
  project            = local.project_id
  service            = "privateca.googleapis.com"
  disable_on_destroy = false
}

module "peer_ca" {
  source            = "../../../modules/peer-ca"
  project_id        = local.project_id
  region            = local.region
  name              = "superserve-peer-production-use4"
  issuer_account_id = "vmd-peer-issuer-prod-use4"
  spiffe_uri        = local.peer_spiffe_uri
  operator_members  = var.peer_ca_operator_members
  depends_on        = [google_project_service.peer_privateca]
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

output "peer_identity_artifact" {
  description = "Manual provider identity.json inputs for east; not a bootstrap-host2.py payload or host admission."
  value = {
    spiffe_uri        = local.peer_spiffe_uri
    credential_policy = module.peer_ca.issuance_policy.credential_policy
  }
}
