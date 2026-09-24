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
peer_ca_operator_members              = ["user:alejandro@superserve.ai"]

proxy_generation_cells = {
  staging = {
    zone            = "us-central1-a"
    instance        = "superserve-vmd-staging-2"
    ip              = "10.0.0.3"
    network         = "projects/rayai-dev/global/networks/superserve-network-3cb2c3b"
    subnetwork      = "projects/rayai-dev/regions/us-central1/subnetworks/superserve-subnet-05cb005"
    target_tags     = ["superserve-vmd"]
    service_account = "vmd-runtime-staging-usc1@rayai-dev.iam.gserviceaccount.com"
    routes = {
      "public-http" = {
        protocol = "HTTP"
        listener = "public"
        probe    = "https://staging-sandbox.superserve.ai/health"
        probe_ip = "8.232.119.0"
      }
      "public-tcp" = {
        protocol = "TCP"
        listener = "public"
        probe    = "https://staging-sandbox.superserve.ai/health"
        probe_ip = "35.241.4.94"
      }
      redirect = {
        protocol = "TCP"
        listener = "redirect"
        probe    = "http://staging-sandbox.superserve.ai/health"
        probe_ip = "35.241.4.94"
      }
    }
  }
}
