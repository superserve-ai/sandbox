terraform {
  required_version = ">= 1.7.0"

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
  # HOST_ID runtime env, which is ALSO its identity in the host table. It is
  # the installed host identity, not the instance name; set it from
  #   grep '^HOST_ID=' /etc/sandbox/host-identity.env
  metrics_host_id = var.host_c_host_id

  # Control-plane address + alert identity for the cell's serving host.
  active_vmd_ip    = module.sandbox_host_c.internal_ip
  active_host_name = module.sandbox_host_c.instance_name
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
    peer_ingress = {
      name          = "superserve-use4-allow-peer-ingress"
      direction     = "INGRESS"
      source_ranges = ["10.2.0.4/32"]
      source_tags   = ["vmd-use4", "vmd-usw2"]
      target_tags   = ["vmd-use4"]
      allow = [{
        protocol = "tcp"
        ports    = ["5009"]
      }]
      description = "Allow private VMD peer ingress within the cell."
    }

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

data "google_service_account" "github_actions" {
  project    = local.project_id
  account_id = "superserve-github-actions"
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

# The use-cell control plane retains its shared secrets and KMS key.
# Runtime IAM is owned here for its dedicated control-plane identity.
module "api" {
  source = "../../../modules/api"

  project_id            = local.project_id
  environment           = local.environment
  region                = local.region
  service_name          = "superserve-api-${local.resource_suffix}"
  service_account_email = google_service_account.controlplane_runtime.email
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
  # In-process billing workers must run between requests.
  cpu_idle = false

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

  secrets = local.controlplane_secrets

  vpc_connector  = null
  vpc_egress     = "PRIVATE_RANGES_ONLY"
  vpc_network    = var.network_name
  vpc_subnetwork = module.network.vpc_connector_subnetwork_name
  vpc_tags       = ["cr-use4"]

  labels = local.common_labels

  depends_on = [
    google_secret_manager_secret_iam_member.controlplane_runtime_secrets,
    google_kms_crypto_key_iam_member.controlplane_credentials,
    google_service_account_iam_member.controlplane_deploy_act_as,
  ]
}

# api.superserve.ai external HTTPS load balancer (global). Fronts the use-cell
# control-plane Cloud Run service in this region via a serverless NEG and
# terminates TLS with a Certificate-Manager managed cert + cert map. Every
# resource here was created imperatively (gcloud) during the host migration and
# is adopted via `terraform import` — see the PR notes for the import commands.
module "api_cert_lb" {
  source = "../../../modules/cloud-run-cert-lb"

  ssl_policy = google_compute_ssl_policy.https.id

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
  runbook_base_url           = var.cloud_ids_runbook_base_url
  labels                     = local.common_labels
}

# The cell's host.
locals {
  host_c_artifact_bucket = module.backup_storage.bucket_name
  host_c_kernel_object   = "vmlinux-4.14-fuse"
  # Expected MD5 of each hostprep object, as the object store attests it;
  # the bootstrap refuses a download that does not match.
  host_c_kernel_md5 = "e897201a3ba4d45f3f0e5aac78288d92"
  host_c_rootfs_md5 = "121426943f2dc7c0d6b0227063b1a482"
  # The release the fleet runs and the digest it verified; the fleet deploy
  # refuses a host on any other.
  host_c_firecracker_version = "v1.15.3"
  host_c_firecracker_sha256  = "a771380d8707a7026949c8ec9dbd2b393893238fe77ab03ba25fb026920079e0"

  # Non-secret vmd.env keys the bootstrap writes once. The deploy upserts
  # its own keys on top; secrets are appended by an operator.
  host_c_vmd_env = {
    HOST_REGION                 = local.region
    VMD_SCHEDULABLE_MEMORY_MIB  = "1500000"
    VMD_SCHEDULABLE_VCPUS       = "192"
    VMD_DNS_REDIRECT_PORT       = "19053"
    VMD_EGRESS_BLOCKLIST_CONFIG = "/etc/sandbox/egress-blocklist.yaml"
    SECRETSPROXY_CA_CERT        = "/var/lib/secretsproxy/ca.crt"
  }
}

module "sandbox_host_c" {
  source = "../../../modules/sandbox-host"

  project_id    = local.project_id
  environment   = local.environment
  region        = local.region
  zone          = local.zone
  instance_name = "superserve-vmd-${local.resource_suffix}-3"
  machine_type  = "z3-highmem-192-highlssd-metal"
  subnet        = module.network.subnetwork_self_link
  internal_ip   = "10.2.0.4"
  tags          = ["vmd-use4"]

  labels = merge(local.sandbox_host_labels, {
    component                  = "vmd"
    sandbox_role               = "vmd"
    sandbox_status             = "ready"
    "goog-ops-agent-policy"    = "v2-template-1-7-0"
    "vanta-contains-user-data" = "true"
    "vanta-user-data-stored"   = "customer_sandbox_files_and_runtime_data"
  })

  service_account_email = google_service_account.vmd_runtime.email

  boot_disk_image   = lookup(var.host_image_overrides, "sandbox_host_c", var.boot_disk_image)
  provisioning      = contains(var.provisioning_hosts, "sandbox_host_c")
  boot_disk_size_gb = 200
  boot_disk_type    = var.boot_disk_type

  can_ip_forward      = false
  on_host_maintenance = "TERMINATE"
  reservation_name    = var.host_c_reservation_name

  # The subnet has no NAT, so this address is the host's path to the
  # internet: first-boot downloads, guest egress, and the guest DNS
  # forwarder all go through it. Every serving host in the cell carries one.
  external_ip = true

  # First boot fetches artifacts and writes logs and metrics under the
  # runtime identity's grants below; create those first so the boot is not
  # racing them.
  depends_on = [
    google_storage_bucket_iam_member.vmd_backup,
    google_project_iam_member.vmd_telemetry,
    google_service_account_iam_member.vmd_deploy_act_as,
  ]

  metadata = {
    enable-osconfig = "TRUE"
    enable-oslogin  = "TRUE"
    startup-script = join("\n\n", [
      templatefile("${path.module}/../../../../deploy/host-bootstrap/sandbox-host-bootstrap.sh.tftpl", {
        localssd_script     = file("${path.module}/../../../../deploy/host-bootstrap/sandbox-localssd.sh")
        artifact_bucket     = local.host_c_artifact_bucket
        kernel_object       = local.host_c_kernel_object
        kernel_md5          = local.host_c_kernel_md5
        rootfs_object       = "base.ext4"
        rootfs_md5          = local.host_c_rootfs_md5
        data_disk_device    = "superserve-sandbox-data"
        vmd_env             = local.host_c_vmd_env
        firecracker_version = local.host_c_firecracker_version
        firecracker_sha256  = local.host_c_firecracker_sha256
      }),
      templatefile("${path.module}/../../../../deploy/unbound/unbound-bootstrap.sh.tftpl", {
        guest_cidr         = "10.11.0.0/16"
        local_dns_port     = "19053"
        dot_hostname       = "j0mqwd9sm7.cloudflare-gateway.com"
        dot_upstream_addrs = ["162.159.36.5", "162.159.46.5"]
      }),
    ])
  }
}

resource "google_compute_disk" "sandbox_data_c" {
  project = local.project_id
  name    = "${module.sandbox_host_c.instance_name}-sandbox-data"
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

resource "google_compute_attached_disk" "sandbox_data_c" {
  project     = local.project_id
  zone        = local.zone
  disk        = google_compute_disk.sandbox_data_c.id
  instance    = module.sandbox_host_c.instance_self_link
  device_name = "superserve-sandbox-data"
  mode        = "READ_WRITE"
}

# Dedicated runtime identity for the standby: logs and metrics, write-only
# backup uploads, and the deploy pipeline may attach it to the instance.
resource "google_service_account" "vmd_runtime" {
  project      = local.project_id
  account_id   = "vmd-runtime-production-use4"
  display_name = "VMD runtime production-use4"
}

resource "google_project_iam_member" "vmd_telemetry" {
  for_each = toset(["roles/logging.logWriter", "roles/monitoring.metricWriter"])
  project  = local.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.vmd_runtime.email}"
}

resource "google_service_account_iam_member" "vmd_deploy_act_as" {
  service_account_id = google_service_account.vmd_runtime.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${data.google_service_account.github_actions.email}"
}

# The dedicated runtime identity creates and reads backup objects within
# its cell, never deletes or overwrites: pause uploads, the hostprep
# artifacts at first boot, and cross-host restores all run under it.
resource "google_storage_bucket_iam_member" "vmd_backup" {
  for_each = toset(["roles/storage.objectCreator", "roles/storage.objectViewer"])
  bucket   = module.backup_storage.bucket_name
  role     = each.value
  member   = "serviceAccount:${google_service_account.vmd_runtime.email}"
}

module "observability" {
  source = "../../../modules/observability"

  project_id               = local.project_id
  environment              = local.environment
  notification_channel_ids = var.notification_channel_ids
  compute_instance_cpu_alerts = {
    sandbox_host_c = {
      display_name  = "Infrastructure / ${module.sandbox_host_c.instance_name} / CPU saturation"
      instance_name = module.sandbox_host_c.instance_name
      instance_id   = module.sandbox_host_c.instance_id
    }
  }
  # Scope through the stable collector identity, retaining the legacy host_id
  # selector until older collectors have rolled forward. Module
  # defaults hold regardless of the cell's traffic: the failure-rate
  # threshold keys on retry pressure (one stuck generation retries ~6
  # times/hour under the capped backoff), not on pause volume.
  backup_alerts = {
    collector_host_id = local.active_host_name
    host_id           = local.metrics_host_id
    display_prefix    = "Backup / ${local.active_host_name}"
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
  host_maintenance_event_alerts = {
    # Fires when a maintenance window is scheduled on the host — the exact
    # signal that motivated retiring the maintenance-prone c4.
    sandbox_host_c = {
      display_name  = "Infrastructure / ${module.sandbox_host_c.instance_name} / host maintenance event"
      instance_name = module.sandbox_host_c.instance_name
      instance_id   = module.sandbox_host_c.instance_id
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

  writer_members = []

  labels = merge(local.common_labels, {
    component                  = "backup"
    "vanta-contains-user-data" = "true"
    "vanta-user-data-stored"   = "customer_sandbox_snapshots_and_files"
  })
}
