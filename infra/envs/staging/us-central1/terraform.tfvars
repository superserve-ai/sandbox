project_id                            = "rayai-dev"
environment                           = "staging"
region                                = "us-central1"
zone                                  = "us-central1-a"
resource_suffix                       = "staging-usc1"
service_account_suffix                = "stg-usc1"
supabase_url                          = "https://staging.supabase.co"
database_url_secret_name              = "database-url-staging"
internal_api_token_secret_name        = "internal-api-token-staging"
sandbox_access_token_seed_secret_name = "sandbox-access-token-seed-staging"
secrets_signing_key_secret_name       = "secretsproxy-signing-key-staging"

# Hosted QM shared infrastructure (module qm). Disabled by default; set the
# images to tags that exist in the tenant image repository before enabling.
# enable_qm                            = true
# qm_domain                            = "qm.staging.superserve.ai"
# qm_marketing_url                     = "https://superserve.ai"
# qm_api_image                         = "us-central1-docker.pkg.dev/rayai-dev/superserve/qm-api:<sha>"
# qm_redirect_image                    = "us-central1-docker.pkg.dev/rayai-dev/superserve/qm-redirect:<tag>"
# qm_tenant_image                      = "us-central1-docker.pkg.dev/rayai-dev/qm-staging-usc1/qm:<tag>"
# qm_api_min_instances                 = 1
# qm_sql_tier                          = "db-custom-2-7680"
# qm_create_private_service_connection = true
# qm_dns_managed_zone                  = null
