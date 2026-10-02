output "pool_resource_name" { value = google_privateca_ca_pool.this.id }
output "issuer_service_account_email" { value = google_service_account.issuer.email }
output "issuance_policy" {
  description = "Non-secret provider policy inputs; caller supplies its reviewed host principal allowlist."
  value = {
    ca_pool                = google_privateca_ca_pool.this.id
    issuer_service_account = google_service_account.issuer.email
    spiffe_uri             = var.spiffe_uri
    credential_policy = {
      leaf_lifetime_seconds = var.leaf_lifetime_seconds
    }
  }
}
