terraform {
  required_version = ">= 1.5.0"

  backend "gcs" {
    bucket = "superserve-terraform-state-prod"
    prefix = "production/us-west2"
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
  # impersonate_service_account = "terraform@rayai-dev.iam.gserviceaccount.com"
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
  api_sa_key             = "superserve_api"

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

  api_service_account_email = "superserve-api-runner@${local.project_id}.iam.gserviceaccount.com"

  # The control plane dials whichever host active_sandbox_host selects. The
  # selected host must already be running and serving before it is applied —
  # instance run state is operational, not Terraform-managed, so that a host
  # started for an incident is never stopped again by a later apply.
  active_vmd_ip = var.active_sandbox_host == "standby" ? module.sandbox_host_b.internal_ip : module.sandbox_host.internal_ip

  # The host currently serving vmd traffic, and so the host whose HOST_ID
  # tags its metrics. Alert filters must key on this, not on sandbox_host,
  # or a standby promotion leaves them watching a host_id that stopped
  # emitting.
  active_host_name = var.active_sandbox_host == "standby" ? module.sandbox_host_b.instance_name : module.sandbox_host.instance_name

  # The host_id that actually tags this cell's metrics: vmd's HOST_ID runtime
  # env, which is ALSO its identity in the host table. It is not derivable from
  # the instance name — this cell's row predates the convention of naming rows
  # after the instance, and HOST_ID must never be changed to match, because
  # heartbeats and reconciler scoping key on the existing row. Alert filters
  # that guess the instance name here select no series and never fire, which
  # looks identical to a healthy host.
  #
  # Verify against the host before changing: grep '^HOST_ID=' /etc/sandbox/vmd.env
  #
  # Deliberately NOT the same as active_host_name, and the two must not be
  # merged: the host-local collector stamps its own HOST_ID (the instance name,
  # rewritten on every collector deploy) onto the hostmetrics pipeline, so
  # host-level series like filesystem utilization carry the instance name while
  # vmd's own OTLP series carry vmd's HOST_ID. One machine, two host_id values,
  # depending on which process emitted the metric.
  metrics_host_id = var.active_sandbox_host == "standby" ? "usw2-2" : "usw2"

  # Exactly one host carries component=vmd, the label the shared deploy
  # pipeline discovers; the other is parked under a cell-scoped label so
  # rollouts skip it instead of failing against a host that is out of service.
  primary_component = var.active_sandbox_host == "primary" ? "vmd" : "vmd-usw2-standby"
  standby_component = var.active_sandbox_host == "standby" ? "vmd" : "vmd-usw2-standby"
}
module "network" {
  source = "../../../modules/network"

  project_id  = local.project_id
  environment = local.environment
  region      = local.region

  create_network = var.create_network
  network_name   = var.network_name

  subnet_name            = "superserve-usw2-subnet"
  subnet_cidr            = var.subnet_cidr
  manage_public_ssh_deny = true
  enable_iap_ssh         = true
  iap_ssh_target_tags    = ["vmd-usw2"]

  create_vpc_connector        = false
  create_vpc_connector_subnet = true
  vpc_connector_name          = "superserve-usw2-connector"
  vpc_connector_subnet        = "superserve-usw2-cr-subnet"
  vpc_connector_subnet_ip     = var.connector_subnet_cidr

  firewall_rules = {
    allow_vmd_grpc = {
      name          = "superserve-usw2-allow-cr-vmd"
      direction     = "INGRESS"
      source_ranges = [var.connector_subnet_cidr]
      target_tags   = ["vmd-usw2"]
      allow = [{
        protocol = "tcp"
        ports    = ["50051"]
      }]
      description = "Allow API-to-VMD gRPC traffic"
    }
    allow_otel_ingress = {
      name          = "superserve-usw2-allow-cr-to-host-otel"
      direction     = "INGRESS"
      source_ranges = [var.connector_subnet_cidr]
      target_tags   = ["vmd-usw2"]
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


data "google_service_account" "github_actions" {
  project    = local.project_id
  account_id = "superserve-github-actions"
}

# The api-runner SA's encrypt/decrypt grant on the credentials-kek KMS key is
# managed out-of-band and owned centrally: the CD Terraform SA lacks KMS
# setIamPolicy on the key, and the SA is shared across cells, so this follows
# the same out-of-band pattern as the shared runtime secrets.

# The runtime grant for the shared system-team-id-production secret is owned
# solely by production/us-central1 (its api_runtime_secrets set), matching how
# the other shared runtime secrets (posthog/slack/sentry) are granted to the
# shared api-runner SA — so this root doesn't double-manage the same binding
# from a separate state.

# deploy-proxy.yml fetches this secret directly via `gcloud secrets versions
# access` at deploy time for the usw cell step, instead of through a Cloud
# Run secret binding — so the CI service account needs read access here too,
# not just the Cloud Run runtime SA.
resource "google_secret_manager_secret_iam_member" "github_actions_sandbox_access_token_seed" {
  project   = local.project_id
  secret_id = coalesce(var.sandbox_access_token_seed_secret_name, "sandbox-access-token-seed-${local.resource_suffix}")
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${data.google_service_account.github_actions.email}"
}

module "api" {
  source = "../../../modules/api"

  project_id            = local.project_id
  environment           = local.environment
  region                = local.region
  service_name          = "superserve-api-${local.resource_suffix}"
  service_account_email = data.google_service_account.api_runner.email
  image                 = "us-central1-docker.pkg.dev/${local.project_id}/superserve/controlplane:replace-me"

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
  # so realized usage sits far below the ceiling.
  min_instances     = 10
  max_instances     = 30
  startup_cpu_boost = true
  cpu_idle          = true

  env = {
    API_PORT               = "8080"
    EDGE_PROXY_DOMAIN      = "usw-sandbox.superserve.ai"
    SANDBOX_ID_REGION      = "usw"
    SUPABASE_URL           = var.supabase_url
    SECRETS_SIGNING_KEY_ID = "v1"
    ALLOW_EPHEMERAL_SEED   = "0"
    DB_MAX_CONNS           = "15"
    VMD_GRPC_ADDRESS       = format("%s:50051", local.active_vmd_ip)
    KMS_KEY_RESOURCE       = "projects/rayai-prod/locations/us-central1/keyRings/superserve/cryptoKeys/credentials-kek"

    # Control-plane OTLP metrics export, matching us-east4. The host-local
    # superserve-otel-collector receives OTLP on :4318 and forwards to Google
    # Managed Prometheus; the usw2 firewall admits the Cloud Run sender range
    # to the host on 4317/4318 (allow_otel_ingress). The endpoint follows
    # active_vmd_ip, but the collector is installed by the deploy workflow
    # (which targets the active host's labels): a standby promotion must
    # re-run the otel deploy or metrics export silently drops until it does.
    # Export failure is non-fatal to the control plane.
    OTEL_ENVIRONMENT            = local.environment
    OTEL_EXPORTER_OTLP_ENDPOINT = "http://${local.active_vmd_ip}:4318"
    OTEL_EXPORT_INTERVAL        = "15s"
    OTEL_METRICS_ENABLED        = "true"
    OTEL_SERVICE_NAME           = "sandbox-controlplane"

    # The serving host's identity for VMD-call metric labels, following
    # active_sandbox_host like the address above. Without it the wrapper
    # falls back to labeling every series "default", which host-grouped
    # dashboards cannot attribute and a standby promotion would not update.
    DEFAULT_HOST_ID = local.metrics_host_id
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
  }

  vpc_connector  = null
  vpc_egress     = "PRIVATE_RANGES_ONLY"
  vpc_network    = var.network_name
  vpc_subnetwork = module.network.vpc_connector_subnetwork_name
  vpc_tags       = ["cr-usw2"]

  labels = local.common_labels
}

module "sandbox_host" {
  source = "../../../modules/sandbox-host"

  project_id    = local.project_id
  environment   = local.environment
  region        = local.region
  zone          = local.zone
  instance_name = "superserve-vmd-${local.resource_suffix}"
  machine_type  = var.machine_type
  subnet        = module.network.subnetwork_self_link
  internal_ip   = "10.1.0.2"
  tags          = ["vmd-usw2"]
  labels = merge(local.sandbox_host_labels, {
    component                  = local.primary_component
    sandbox_role               = "vmd"
    "vanta-contains-user-data" = "true"
    "vanta-user-data-stored"   = "customer_sandbox_files_and_runtime_data"
  })

  service_account_email = data.google_service_account.api_runner.email
  # 24.04 images are only published under the -amd64 family.
  boot_disk_image     = "projects/ubuntu-os-cloud/global/images/family/ubuntu-2404-lts-amd64"
  boot_disk_size_gb   = 250
  can_ip_forward      = false
  on_host_maintenance = "TERMINATE"

  metadata = {
    enable-osconfig = "TRUE"
    enable-oslogin  = "TRUE"
  }
}

# Cold standby for the cell, normally kept stopped. Promotion = start this
# host, then set active_sandbox_host = "standby" and apply: the switch routes
# the control plane here and moves the deploy-fleet label off the primary.
module "sandbox_host_b" {
  source = "../../../modules/sandbox-host"

  project_id    = local.project_id
  environment   = local.environment
  region        = local.region
  zone          = local.zone
  instance_name = "superserve-vmd-usw2-2"
  machine_type  = var.machine_type
  subnet        = module.network.subnetwork_self_link
  internal_ip   = "10.1.0.3"
  tags          = ["vmd-usw2"]
  labels = merge(local.sandbox_host_labels, {
    component                  = local.standby_component
    sandbox_role               = "vmd"
    "vanta-contains-user-data" = "true"
    "vanta-user-data-stored"   = "customer_sandbox_files_and_runtime_data"
  })

  service_account_email = data.google_service_account.api_runner.email
  boot_disk_image       = "projects/ubuntu-os-cloud/global/images/family/ubuntu-2404-lts-amd64"
  boot_disk_size_gb     = 250
  # Metal machine types reject the API-default pd-standard boot disk.
  boot_disk_type      = "hyperdisk-balanced"
  can_ip_forward      = false
  on_host_maintenance = "TERMINATE"

  metadata = {
    enable-osconfig = "TRUE"
    enable-oslogin  = "TRUE"
  }
}

module "observability" {
  source = "../../../modules/observability"

  project_id               = local.project_id
  environment              = local.environment
  notification_channel_ids = var.notification_channel_ids
  compute_instance_cpu_alerts = {
    sandbox_host = {
      display_name  = "Infrastructure / ${module.sandbox_host.instance_name} / CPU saturation"
      instance_name = module.sandbox_host.instance_name
      instance_id   = module.sandbox_host.instance_id
    }
    # Inert while the standby is stopped (no data, no fire).
    sandbox_host_b = {
      display_name  = "Infrastructure / ${module.sandbox_host_b.instance_name} / CPU saturation"
      instance_name = module.sandbox_host_b.instance_name
      instance_id   = module.sandbox_host_b.instance_id
    }
  }
  host_maintenance_event_alerts = {
    sandbox_host = {
      display_name  = "Infrastructure / ${module.sandbox_host.instance_name} / host maintenance event"
      instance_name = module.sandbox_host.instance_name
      instance_id   = module.sandbox_host.instance_id
    }
  }
  # Backup pipeline alerts scoped to this cell's host via the host_id
  # metric label (HOST_ID on the host matches the instance name). Follows
  # active_sandbox_host so a standby promotion keeps the filter on whichever
  # host is actually emitting.
  # Thresholds are the module defaults except oldest_pending_age_duration;
  # the rationale for each default sits on the module's variables.
  backup_alerts = {
    host_id        = local.metrics_host_id
    display_prefix = "Backup / ${local.active_host_name}"
    # A share of this cell's traffic pauses in scheduled batches rather
    # than steadily, confirmed via backup_journal_pending{priority="pause"}
    # and the control plane's pause-endpoint request log. The module
    # default's 15-minute window was shorter than a single batch's drain
    # time, so it paged on every batch. 20 minutes plus the
    # BACKUP_UPLOAD_CONCURRENCY bump in deploy-vmd.yml should clear a
    # batch before this sustains, while still catching a drain that's
    # actually stalled.
    oldest_pending_age_duration = "1200s"
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
  # the same host_id label the backup metrics use, and following
  # active_sandbox_host for the same reason. Module defaults: warn at 85%
  # sustained 30 minutes, page at 95%.
  host_disk_alerts = {
    host_id        = local.active_host_name
    display_prefix = "Infrastructure / ${local.active_host_name}"
  }
  labels = local.common_labels
}

# Durability tier for the host's local-SSD artifacts (sandbox snapshots,
# template builds). The vmd host runs as the shared api-runner SA, so that SA
# is the writer: create+read on this bucket, never delete — deletes belong to
# the module's dedicated GC identity, which nothing on the host runs as.
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
