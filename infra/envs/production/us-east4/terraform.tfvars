project_id             = "rayai-prod"
environment            = "production"
region                 = "us-east4"
zone                   = "us-east4-c"
create_network         = false
network_name           = "superserve-production-vpc"
resource_suffix        = "use4"
service_account_suffix = "use4"
subnet_cidr            = "10.2.0.0/24"
# Direct-VPC-egress subnet for the Cloud Run control plane — distinct from the
# host subnet, sourced by the vmd-gRPC + OTLP firewall rules so Cloud Run can
# reach the host. Direct VPC egress allocates instance IPs from this range and
# needs ~2x max_instances of headroom (Google's documented minimum is /26), so
# this is a /22, mirroring the usw2 cell's 10.1.4.0/22 in the 10.2 block.
connector_subnet_cidr = "10.2.4.0/22"
host_internal_ip      = "10.2.0.2"
machine_type          = "c4-highmem-288-lssd-metal"
boot_disk_type        = "hyperdisk-balanced"
# The reservation-us-east-c4-288-lssd-metal reservation is non-specific
# (specificReservationRequired=false), so it can't be targeted by name. Null =
# default affinity, which auto-consumes that matching reservation in the zone.
reservation_name = null

# A5 control plane — same "use" cell as us-central1. Point every runtime secret
# at the shared, suffix-less use-cell secrets (not per-region "-use4" names) so
# this service reads the same DB, seeds, and signing keys as us-central1 during
# the traffic split.
supabase_url                          = "https://use.supabase.co"
database_url_secret_name              = "database-url"
internal_api_token_secret_name        = "internal-api-token"
sandbox_access_token_seed_secret_name = "sandbox-access-token-seed"
secrets_signing_key_secret_name       = "secretsproxy-signing-key"
system_team_id_secret_name            = "system-team-id-production"
