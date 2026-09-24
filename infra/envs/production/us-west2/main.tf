terraform {
  required_version = ">= 1.7.0"

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
  project_id                = var.project_id
  environment               = var.environment
  region                    = var.region
  zone                      = var.zone
  resource_suffix           = coalesce(var.resource_suffix, var.environment)
  service_account_suffix    = coalesce(var.service_account_suffix, local.resource_suffix)
  legacy_runtime_account    = data.google_service_account.api_runner.email
  host_identity_unchanged   = google_service_account.vmd_runtime.email
  host_identities_unchanged = [google_service_account.vmd_runtime.email]

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

  # The control plane dials the cell's host.
  active_vmd_ip = module.sandbox_host_b.internal_ip

  # The host serving vmd traffic, and so the host whose HOST_ID tags its
  # metrics. Alert filters key on this.
  active_host_name = module.sandbox_host_b.instance_name

  # The host_id that actually tags this cell's metrics: vmd's HOST_ID runtime
  # env, which is ALSO its identity in the host table. It is the installed
  # host identity (slot name plus a generated suffix), not the instance name,
  # set in tfvars from the host itself:
  #   grep '^HOST_ID=' /etc/sandbox/host-identity.env
  #
  # The collector stamps active_host_name as collector_host_id for alert
  # selection, independently of the authoritative HOST_ID on managed hosts.
  metrics_host_id = var.standby_host_id
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
    peer_ingress = {
      name        = "superserve-usw2-allow-peer-ingress"
      direction   = "INGRESS"
      source_tags = ["vmd-use4", "vmd-usw2"]
      target_tags = ["vmd-usw2"]
      allow = [{
        protocol = "tcp"
        ports    = ["5009"]
      }]
      description = "Allow private mTLS forwarding between production VMD hosts."
    }
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

# Legacy host api-runner grants remain centrally owned. The control plane's
# dedicated identity and runtime grants are owned by controlplane-identity.tf.

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
  service_account_email = google_service_account.controlplane_runtime.email
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
  # In-process billing workers must run between requests.
  cpu_idle = false

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
    STRIPE_API_BASE_URL         = "https://api.stripe.com"
    STRIPE_API_VERSION          = "2026-05-27.dahlia"
    STRIPE_CHECKOUT_PRICE_IDS   = "price_1U60fMPyzR3Q9AgflfcjIHsp,price_1U60hxPyzR3Q9AgfOsciXQ43"
    APP_ALLOWED_ORIGINS         = "https://console.superserve.ai"

    # The serving host's identity for VMD-call metric labels. Without it the
    # wrapper falls back to labeling every series "default", which
    # host-grouped dashboards cannot attribute.
    DEFAULT_HOST_ID = local.metrics_host_id

    # The purge of deleted sandboxes' backups: the cell's bucket and the
    # GC identity the runtime impersonates to delete from it.
    BACKUP_BUCKET             = module.backup_storage.bucket_name
    BACKUP_GC_SERVICE_ACCOUNT = module.backup_storage.gc_service_account_email
  }

  secrets = local.controlplane_secrets

  vpc_connector  = null
  vpc_egress     = "PRIVATE_RANGES_ONLY"
  vpc_network    = var.network_name
  vpc_subnetwork = module.network.vpc_connector_subnetwork_name
  vpc_tags       = ["cr-usw2"]

  labels = local.common_labels

  depends_on = [
    google_secret_manager_secret_iam_member.controlplane_runtime_secrets,
    google_kms_crypto_key_iam_member.controlplane_credentials,
    google_project_iam_member.controlplane_metric_writer,
    google_service_account_iam_member.controlplane_deploy_act_as,
    module.backup_storage,
  ]
}

# Background-data disk of the retired host, kept detached until its staged
# backups are confirmed drained or empty. The attachment went with the host.
resource "google_compute_disk" "sandbox_data" {
  project = local.project_id
  name    = "superserve-vmd-usw2-sandbox-data"
  zone    = local.zone
  type    = "hyperdisk-balanced"
  size    = 1024

  labels = merge(local.common_labels, {
    component = "vmd"
    purpose   = "sandbox-data"
  })

  lifecycle {
    prevent_destroy = true
  }
}

# The cell's host.
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
    component                  = "vmd"
    sandbox_role               = "vmd"
    "vanta-contains-user-data" = "true"
    "vanta-user-data-stored"   = "customer_sandbox_files_and_runtime_data"
  })

  service_account_email     = google_service_account.vmd_runtime.email
  allow_stopping_for_update = true
  depends_on                = [google_project_iam_member.vmd_telemetry, google_storage_bucket_iam_member.vmd_backup, google_service_account_iam_member.vmd_deploy_act_as]
  boot_disk_image           = lookup(var.host_image_overrides, "sandbox_host_b", var.boot_disk_image)
  provisioning              = contains(var.provisioning_hosts, "sandbox_host_b")
  boot_disk_size_gb         = 250
  # Metal machine types reject the API-default pd-standard boot disk.
  boot_disk_type      = "hyperdisk-balanced"
  can_ip_forward      = false
  on_host_maintenance = "TERMINATE"

  metadata = {
    enable-osconfig = "TRUE"
    enable-oslogin  = "TRUE"
  }
}

# The standby's own background-data disk — see sandbox_data above for
# why every host carrying the "vmd" deploy label needs one, and for why
# hyperdisk-balanced (this is a Z3 metal host too). Hyperdisks only grow.
resource "google_compute_disk" "sandbox_data_b" {
  project = local.project_id
  name    = "superserve-vmd-usw2-2-sandbox-data"
  zone    = local.zone
  type    = "hyperdisk-balanced"
  size    = 8192

  labels = merge(local.common_labels, {
    component = "vmd"
    purpose   = "sandbox-data"
  })

  lifecycle {
    prevent_destroy = true
    # This disk carries host state across the standby's promotion lifecycle.
    # Its API shape may predate the current host definition (for example, a
    # provider-reported disk type or computed performance field). Never turn
    # that drift into a replacement of the protected disk; capacity changes
    # remain an explicit operator action because hyperdisks only grow.
    ignore_changes = all
  }
}

# Background-data disk, separate from the local-SSD array serving live VM
# disk I/O: pause-backup staging reads every staged file twice before it
# leaves the host (digest pre-check, then the upload stream), and on this
# host both reads would otherwise land on the same array as tenant reads.
# Only backup staging (BACKUP_STAGING_DIR, wired in deploy-vmd.yml) uses
# it today; deploy-vmd.py's mount precondition refuses to deploy onto a
# host missing this device. hyperdisk-balanced, not pd-balanced: this is
# a Z3 metal host, which rejects standard Persistent Disk types.
#
# No deletion_policy on the attachment: the google_compute_attached_disk
# resource under this file's pinned ~> 6.0 provider exposes no such
# argument. The disk survives instance deletion regardless: attaching it
# through this resource (the API's attachDisk call) rather than as an
# instance-creation-time disk means GCP does not auto-delete it, and
# prevent_destroy on the disk stops Terraform from deleting the disk
# itself. Deliberately NOT prevent_destroy on the attachment: it is keyed
# on the instance's self link, so the documented host-recreation flow
# (host-dr-runbook.md) replaces it whenever the instance is rebuilt.
resource "google_compute_attached_disk" "sandbox_data_b" {
  project     = local.project_id
  zone        = local.zone
  disk        = google_compute_disk.sandbox_data_b.id
  instance    = module.sandbox_host_b.instance_self_link
  device_name = "superserve-sandbox-data"
  mode        = "READ_WRITE"
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
  host_maintenance_event_alerts = {
    sandbox_host_b = {
      display_name  = "Infrastructure / ${module.sandbox_host_b.instance_name} / host maintenance event"
      instance_name = module.sandbox_host_b.instance_name
      instance_id   = module.sandbox_host_b.instance_id
    }
  }
  # Backup alerts use the stable collector identity plus the legacy host_id
  # selector while older collectors roll forward.
  # Thresholds are the module defaults except oldest_pending_age_duration;
  # the rationale for each default sits on the module's variables.
  backup_alerts = {
    collector_host_id = local.active_host_name
    host_id           = local.metrics_host_id
    display_prefix    = "Backup / ${local.active_host_name}"
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
  # Backup coverage: paused sandboxes with no verified backup at all,
  # sampled by the control plane from this cell's database. Created
  # disabled so the policy config is validated and enablement is a
  # one-field flip once the cell's backfill backlog converges to zero.
  # regions lists the host table's region column values in this cell's
  # database, NOT GCP region names; "usw" is the only value present.
  backup_coverage_alerts = {
    enabled        = false
    display_prefix = "Backup coverage / us-west2"
    regions        = ["usw"]
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
    collector_host_id = local.active_host_name
    host_id           = local.metrics_host_id
    display_prefix    = "Launch path / ${local.active_host_name}"
  }
  # Root-filesystem (OS disk) utilization for the same host, scoped through
  # the same host_id label the backup metrics use. Module defaults: warn at
  # 85% sustained 30 minutes, page at 95%.
  host_disk_alerts = {
    host_id        = local.active_host_name
    display_prefix = "Infrastructure / ${local.active_host_name}"
  }
  labels = local.common_labels
}

# Durability tier for the host's local-SSD artifacts (sandbox snapshots,
# template builds). The VMD host uses its dedicated identity below; the
# control-plane reader is separate and never receives write/delete access.
module "backup_storage" {
  source = "../../../modules/backup-storage"

  project_id  = local.project_id
  environment = local.environment
  location    = local.region
  bucket_name = "superserve-artifact-backup-${local.resource_suffix}"

  gc_service_account_id = "superserve-backup-gc-${local.resource_suffix}"

  restore_service_account_id = "superserve-backup-ro-${local.resource_suffix}"

  # Preserve the existing shared writer grant during the control-plane
  # identity cutover. Its removal is separate cleanup after host/rollback
  # consumers are audited.
  writer_members = [
    "serviceAccount:${data.google_service_account.api_runner.email}",
  ]

  reader_members = [
    "serviceAccount:${google_service_account.controlplane_runtime.email}",
  ]

  labels = merge(local.common_labels, {
    component                  = "backup"
    "vanta-contains-user-data" = "true"
    "vanta-user-data-stored"   = "customer_sandbox_snapshots_and_files"
  })
}

# The control plane deletes deleted sandboxes' backups as the bucket's GC
# identity, which it impersonates only for that client.
resource "google_service_account_iam_member" "controlplane_backup_gc" {
  service_account_id = "projects/${local.project_id}/serviceAccounts/${module.backup_storage.gc_service_account_email}"
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.controlplane_runtime.email}"
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
  runbook_base_url           = var.cloud_ids_runbook_base_url
  labels                     = local.common_labels
}
