terraform {
  required_version = ">= 1.5.0"

  backend "gcs" {
    bucket = "superserve-terraform-state-prod"
    prefix = "production/us-east4"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

provider "google" {
  project = local.project_id
  region  = local.region
}

locals {
  cloud_ids_mirrored_subnet_self_links = [
    module.network.subnetwork_self_link,
  ]
}

locals {
  project_id             = var.project_id
  environment            = var.environment
  region                 = var.region
  zone                   = var.zone
  resource_suffix        = coalesce(var.resource_suffix, var.environment)
  service_account_suffix = coalesce(var.service_account_suffix, local.resource_suffix)

  common_labels = {
    environment = local.environment
    managed_by  = "terraform"
    region      = local.region
  }

  sandbox_host_labels = merge(local.common_labels, {
    owner              = "platform"
    project            = "sandbox"
    dataclassification = "confidential"
    application        = "sandbox-host"
  })

  # The host_id that tags vmd's own metrics and scopes the reconciler: its
  # HOST_ID runtime env, which is ALSO its identity in the host table. The
  # cell's sole host derives it from the instance name (its deployed HOST_ID),
  # so DEFAULT_HOST_ID and every alert filter match the live host exactly.
  #
  # Verify against the host before changing: grep '^HOST_ID=' /etc/sandbox/vmd.env
  metrics_host_id = module.sandbox_host_b.instance_name

  # Control-plane address + alert identity for the cell's host.
  active_vmd_ip    = module.sandbox_host_b.internal_ip
  active_host_name = module.sandbox_host_b.instance_name
}

module "network" {
  source = "../../../modules/network"

  project_id  = local.project_id
  environment = local.environment
  region      = local.region

  create_network = var.create_network
  network_name   = var.network_name

  subnet_name            = "superserve-use4-subnet"
  subnet_cidr            = var.subnet_cidr
  manage_public_ssh_deny = true
  # true so CD (deploy-vmd/proxy/otel via `gcloud scp --tunnel-through-iap`) and
  # operators can reach the host on :22 — matches us-central1/us-west2. With this
  # false, manage_public_ssh_deny alone blocked ALL SSH to the host and broke the
  # vmd deploy.
  enable_iap_ssh      = true
  iap_ssh_target_tags = ["vmd-use4"]

  # Cloud Run reaches the vmd host over direct VPC egress (no connector),
  # matching the usw2 cell. The dedicated egress subnet carries the Cloud Run
  # sender range; the firewall rules below admit it to vmd gRPC + host OTLP.
  create_vpc_connector        = false
  create_vpc_connector_subnet = true
  vpc_connector_subnet        = "superserve-use4-cr-subnet"
  vpc_connector_subnet_ip     = var.connector_subnet_cidr

  firewall_rules = {
    allow_vmd_grpc = {
      name          = "superserve-use4-allow-cr-vmd"
      direction     = "INGRESS"
      source_ranges = [var.connector_subnet_cidr]
      target_tags   = ["vmd-use4"]
      allow = [{
        protocol = "tcp"
        ports    = ["50051"]
      }]
      description = "Allow API-to-VMD gRPC traffic"
    }
    allow_otel_ingress = {
      name          = "superserve-use4-allow-cr-to-host-otel"
      direction     = "INGRESS"
      source_ranges = [var.connector_subnet_cidr]
      target_tags   = ["vmd-use4"]
      allow = [{
        protocol = "tcp"
        ports    = ["4317", "4318"]
      }]
      description = "Allow Cloud Run connector traffic to host-local OTLP endpoints."
    }
  }

  labels = local.common_labels
}

data "google_service_account" "api_runner" {
  project    = local.project_id
  account_id = "superserve-api-runner"
}

# The CD service account needs Certificate Manager access to read/manage the
# api.superserve.ai cert map + DNS authorization this cell owns (the plan's
# import 403'd without it). Granted out-of-band to unblock; imported (see
# imports.tf) so the apply adopts the existing binding instead of creating a
# duplicate.
resource "google_project_iam_member" "cd_certificatemanager" {
  project = local.project_id
  role    = "roles/certificatemanager.editor"
  member  = "serviceAccount:superserve-github-actions@${local.project_id}.iam.gserviceaccount.com"
}

# A5: us-east4 control plane for the "use" cell.
#
# This is a host swap, not a new cell: us-east4 shares the use-cell Supabase,
# runtime secrets, api-runner service account, and KMS key with us-central1.
# Only the service name, region, and VMD address are region-local — traffic
# splits between this service and the us-central1 one during cutover, then
# us-central1 drains. Secrets resolve to the shared (suffix-less) use-cell
# names via the *_secret_name overrides in terraform.tfvars.
#
# No per-root secret IAM here: the shared api-runner SA already holds the
# runtime accessor grants (owned by us-central1's api_runtime_secrets) and the
# credentials-kek encrypt/decrypt grant (owned out-of-band). Re-declaring them
# from this state would double-manage the same bindings — the same split we
# settled for usw2 in #232/#233.
module "api" {
  source = "../../../modules/api"

  project_id            = local.project_id
  environment           = local.environment
  region                = local.region
  service_name          = "superserve-api-${local.resource_suffix}"
  service_account_email = data.google_service_account.api_runner.email
  # First create must reference a tag that actually exists, or the initial
  # revision never goes ready and the apply fails. The other regions can carry
  # a ":replace-me" placeholder only because their services already exist and
  # image is in the module's ignore_changes. us-east4's service is new, so pin
  # ":latest" for the create; CD's deploy step later moves it to the commit SHA
  # and ignore_changes keeps terraform from reverting that.
  image = "us-central1-docker.pkg.dev/${local.project_id}/superserve/controlplane:latest"

  cpu_limit    = "2"
  memory_limit = "1Gi"
  # Pooler client budget is 1,000 (XL tier), and the binding case is a
  # deploy under full load: max_instances applies per revision and Cloud Run
  # can overlap the old and new revisions completely, so the ceiling is
  # 60 instances x DB_MAX_CONNS. At 15 that is 900, plus explicitly capped
  # host services (vmd 8, secretsproxy 8) and ops clients ~= 940 worst case.
  # Any higher per-instance cap breaks that overlap math; burst headroom
  # comes from fast queries and pool lifecycle bounds, not a larger cap.
  # MaxConns is a cap, not a floor: idle instances hold ~MinIdleConns each,
  # so realized usage sits far below the ceiling. Declared rather than left to drift: the
  # module's ignore_changes is ineffective for the v2 resource.
  min_instances     = 10
  max_instances     = 30
  startup_cpu_boost = true
  cpu_idle          = true

  env = {
    API_PORT               = "8080"
    EDGE_PROXY_DOMAIN      = "sandbox.superserve.ai"
    SUPABASE_URL           = var.supabase_url
    SECRETS_SIGNING_KEY_ID = "v1"
    ALLOW_EPHEMERAL_SEED   = "0"
    DB_MAX_CONNS           = "15"
    VMD_GRPC_ADDRESS       = format("%s:50051", local.active_vmd_ip)
    # The cell host's identity, alongside the address above. Same value as
    # metrics_host_id.
    DEFAULT_HOST_ID  = local.metrics_host_id
    KMS_KEY_RESOURCE = "projects/rayai-prod/locations/us-central1/keyRings/superserve/cryptoKeys/credentials-kek"

    # Control-plane OTLP metrics export, mirroring the retired us-central1
    # primary. The host-local superserve-otel-collector receives OTLP on :4318
    # and forwards to Google Managed Prometheus; the use4 network already admits
    # the Cloud Run sender range to the host on 4317/4318 (allow_otel_ingress).
    OTEL_ENVIRONMENT            = local.environment
    OTEL_EXPORTER_OTLP_ENDPOINT = "http://${local.active_vmd_ip}:4318"
    OTEL_EXPORT_INTERVAL        = "15s"
    OTEL_METRICS_ENABLED        = "true"
    OTEL_SERVICE_NAME           = "sandbox-controlplane"
    STRIPE_API_BASE_URL         = "https://api.stripe.com"
    STRIPE_API_VERSION          = "2026-05-27.dahlia"
    STRIPE_CHECKOUT_PRICE_IDS   = "price_1U60fMPyzR3Q9AgflfcjIHsp,price_1U60hxPyzR3Q9AgfOsciXQ43"
    APP_ALLOWED_ORIGINS         = "https://console.superserve.ai"
  }

  secrets = {
    DATABASE_URL = {
      secret = coalesce(var.database_url_secret_name, "database-url-${local.resource_suffix}")
    }
    INTERNAL_API_TOKEN = {
      secret = coalesce(var.internal_api_token_secret_name, "internal-api-token-${local.resource_suffix}")
    }
    SANDBOX_ACCESS_TOKEN_SEED = {
      secret = coalesce(var.sandbox_access_token_seed_secret_name, "sandbox-access-token-seed-${local.resource_suffix}")
    }
    SECRETS_SIGNING_KEY = {
      secret = coalesce(var.secrets_signing_key_secret_name, "secretsproxy-signing-key-${local.resource_suffix}")
    }
    SENTRY_DSN = {
      secret = coalesce(var.sentry_dsn_secret_name, "sentry-dsn")
    }
    SYSTEM_TEAM_ID = {
      secret = coalesce(var.system_team_id_secret_name, "system-team-id-${local.resource_suffix}")
    }
    SLACK_QUOTA_ALERT_WEBHOOK = {
      secret = "slack-quota-alert-webhook"
    }
    POSTHOG_KEY = {
      secret = "posthog-project-key"
    }
    STRIPE_SECRET_KEY = {
      secret = "stripe-secret-key-use"
    }
    STRIPE_WEBHOOK_SECRET = {
      secret = "stripe-webhook-secret-use"
    }
    STRIPE_METER_ERROR_WEBHOOK_SECRET = {
      secret = "stripe-meter-error-webhook-secret-use"
    }
  }

  vpc_connector  = null
  vpc_egress     = "PRIVATE_RANGES_ONLY"
  vpc_network    = var.network_name
  vpc_subnetwork = module.network.vpc_connector_subnetwork_name
  vpc_tags       = ["cr-use4"]

  labels = local.common_labels
}

# api.superserve.ai external HTTPS load balancer (global). Fronts the use-cell
# control-plane Cloud Run service in this region via a serverless NEG and
# terminates TLS with a Certificate-Manager managed cert + cert map. Every
# resource here was created imperatively (gcloud) during the host migration and
# is adopted via `terraform import` — see the PR notes for the import commands.
module "api_cert_lb" {
  source = "../../../modules/cloud-run-cert-lb"

  project_id        = local.project_id
  region            = local.region
  cloud_run_service = module.api.service_name
  domain            = "api.superserve.ai"

  dns_authorization_name     = "api-superserve-dnsauth"
  certificate_name           = "api-superserve-cert"
  certificate_map_name       = "api-superserve-certmap"
  certificate_map_entry_name = "api-superserve-entry"
  address_name               = "api-superserve-use4-ip"
  https_proxy_name           = "api-superserve-use4-proxy"
  forwarding_rule_name       = "api-superserve-use4-fwd"
  url_map_name               = "superserve-api-url-map"
  backend_service_name       = "superserve-api-backend-use4"
  # NB: verify against the live NEG name before importing — the migration
  # created it imperatively and its exact name was not captured. Correct this
  # value to match `gcloud compute network-endpoint-groups list` output first.
  neg_name = "superserve-api-use4-neg"
}

module "cloud_ids" {
  source = "../../../modules/cloud-ids"

  project_id                 = local.project_id
  region                     = local.region
  zone                       = local.zone
  network_self_link          = module.network.network_self_link
  endpoint_name              = "superserve-ids-${local.resource_suffix}"
  mirrored_subnet_self_links = local.cloud_ids_mirrored_subnet_self_links
  notification_channel_ids   = var.notification_channel_ids
  labels                     = local.common_labels
}

# The cell's sole sandbox/VMD host. Distinct identity (its HOST_ID is its
# instance name) carried over from when it was provisioned as the standby.
# It replaced the original c4 host, whose module was removed after cutover.
module "sandbox_host_b" {
  source = "../../../modules/sandbox-host"

  project_id    = local.project_id
  environment   = local.environment
  region        = local.region
  zone          = local.zone
  instance_name = "superserve-vmd-${local.resource_suffix}-2"
  # The z3 replacement for the retired, maintenance-prone c4 host.
  machine_type = "z3-highmem-192-highlssd-metal"
  subnet       = module.network.subnetwork_self_link
  internal_ip  = "10.2.0.3"
  tags         = ["vmd-use4"]

  labels = merge(local.sandbox_host_labels, {
    component                  = "vmd"
    sandbox_role               = "vmd"
    sandbox_status             = "provisioning"
    "goog-ops-agent-policy"    = "v2-template-1-7-0"
    "vanta-contains-user-data" = "true"
    "vanta-user-data-stored"   = "customer_sandbox_files_and_runtime_data"
  })

  service_account_email = data.google_service_account.api_runner.email

  # 22.04 to match the primary and this cell's snapshot lineage (existing
  # paused sandboxes and us-central1-seeded snapshots are 22.04-taken); a
  # host-OS mismatch has been observed to break snapshot restore.
  boot_disk_image = "projects/ubuntu-os-cloud/global/images/family/ubuntu-2204-lts"

  # Metal machine types reject the API-default pd-standard boot disk.
  boot_disk_type = var.boot_disk_type

  can_ip_forward      = false
  on_host_maintenance = "TERMINATE"

  # Targets a z3 reservation (see standby_reservation_name); null uses default
  # affinity against a matching z3 reservation in the zone.
  reservation_name = var.standby_reservation_name

  metadata = {
    enable-osconfig = "TRUE"
    enable-oslogin  = "TRUE"
    startup-script = templatefile("${path.module}/../../../../deploy/unbound/unbound-bootstrap.sh.tftpl", {
      guest_cidr         = "10.11.0.0/16"
      local_dns_port     = "19053"
      dot_hostname       = "j0mqwd9sm7.cloudflare-gateway.com"
      dot_upstream_addrs = ["162.159.36.5", "162.159.46.5"]
    })
  }
}

module "observability" {
  source = "../../../modules/observability"

  project_id               = local.project_id
  environment              = local.environment
  notification_channel_ids = var.notification_channel_ids
  compute_instance_cpu_alerts = {
    sandbox_host_b = {
      display_name  = "Infrastructure / ${module.sandbox_host_b.instance_name} / CPU saturation"
      instance_name = module.sandbox_host_b.instance_name
      instance_id   = module.sandbox_host_b.instance_id
    }
  }
  # Backup pipeline alerts scoped to this cell's host via the host_id
  # metric label (vmd's HOST_ID — see metrics_host_id, which is not the
  # instance name on this cell). Module
  # defaults hold regardless of the cell's traffic: the failure-rate
  # threshold keys on retry pressure (one stuck generation retries ~6
  # times/hour under the capped backoff), not on pause volume.
  backup_alerts = {
    host_id        = local.metrics_host_id
    display_prefix = "Backup / ${local.active_host_name}"
  }
  # Backup coverage: paused sandboxes with no verified backup at all,
  # sampled by the control plane from this cell's database. Created
  # disabled so the policy config is validated and enablement is a
  # one-field flip once the cell's migration leftovers are classified
  # and covered. regions lists the host table's region column values in
  # the shared use-cell database, not GCP region names. The cell's host
  # rows all read us-east4 today, but this database has served the cell
  # under us-central1 labeling before the host swap, so the legacy
  # value stays scoped: host rows relabeled or restored under it must
  # not fall outside the alert.
  backup_coverage_alerts = {
    enabled        = false
    display_prefix = "Backup coverage / us-east4"
    regions        = ["us-east4", "us-central1"]
  }
  # Launch-path health for the same host: the pruned launcher mount namespace
  # being unavailable (VM starts fall back to walking the full host mount
  # table) and live network namespaces accumulating. Both degrade latency
  # while the service still reports healthy, so neither has another signal.
  #
  # Module defaults: page after 15 minutes on the legacy path; at 8,000 live
  # namespaces sustained 30 minutes; and at 9,000 after only 5 minutes, since
  # a host whose inflow has outrun the drain covers thousands of namespaces
  # in half an hour. Both namespace levels are deliberately above vmd's
  # reclaim ceiling (VMD_PAUSED_NETWORK_NETNS_THRESHOLD, currently 6,000) so
  # they mean "the controller engaged and still lost", not "the controller is
  # doing its job" — move them together with the ceiling or not at all.
  launch_path_alerts = {
    host_id        = local.metrics_host_id
    display_prefix = "Launch path / ${local.active_host_name}"
  }
  # Root-filesystem (OS disk) utilization for the same host, scoped through
  # the same host_id label the backup metrics use. Module defaults: warn at
  # 85% sustained 30 minutes, page at 95%.
  host_disk_alerts = {
    host_id        = local.active_host_name
    display_prefix = "Infrastructure / ${local.active_host_name}"
  }
  host_maintenance_event_alerts = {
    # Fires when a maintenance window is scheduled on the host — the exact
    # signal that motivated retiring the maintenance-prone c4.
    sandbox_host_b = {
      display_name  = "Infrastructure / ${module.sandbox_host_b.instance_name} / host maintenance event"
      instance_name = module.sandbox_host_b.instance_name
      instance_id   = module.sandbox_host_b.instance_id
    }
  }
  labels = local.common_labels
}

# Durability tier for the host's local-SSD artifacts (sandbox snapshots,
# template builds). The vmd host runs as the shared api-runner SA, so that SA
# is the writer: create-only on this bucket (see the module — objectCreator,
# no read, no delete, no overwrite), never delete — deletes belong to the
# module's dedicated GC identity, which nothing on the host runs as. Reads
# are reserved for the module's dedicated restore identity; a vmd feature
# that needs to READ from this bucket (fetch-before-resume) is not
# functional against this grant and needs its own, separately reviewed
# identity or read path — extending the shared writer identity to read
# would undo the isolation this module exists to provide (the identity is
# shared across cells, so read here is read of every cell's backups).
module "backup_storage" {
  source = "../../../modules/backup-storage"

  project_id  = local.project_id
  environment = local.environment
  location    = local.region
  bucket_name = "superserve-artifact-backup-${local.resource_suffix}"

  gc_service_account_id = "superserve-backup-gc-${local.resource_suffix}"

  restore_service_account_id = "superserve-backup-ro-${local.resource_suffix}"

  writer_members = [
    "serviceAccount:${data.google_service_account.api_runner.email}",
  ]

  labels = merge(local.common_labels, {
    component                  = "backup"
    "vanta-contains-user-data" = "true"
    "vanta-user-data-stored"   = "customer_sandbox_snapshots_and_files"
  })
}
