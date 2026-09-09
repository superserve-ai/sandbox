terraform {
  required_version = ">= 1.5.0"

  backend "gcs" {
    bucket = "superserve-terraform-state"
    prefix = "staging/us-central1"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
    }
  }
}

provider "google" {
  project = local.project_id
  region  = local.region
}

locals {
  project_id      = var.project_id
  environment     = var.environment
  region          = var.region
  zone            = var.zone
  resource_suffix = coalesce(var.resource_suffix, var.environment)

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

  staging_otlp_endpoint = "http://10.0.0.2:4318"
}

module "network" {
  source = "../../../modules/network"

  project_id                  = local.project_id
  environment                 = local.environment
  region                      = local.region
  network_name                = "superserve-network-3cb2c3b"
  subnet_name                 = "superserve-subnet-05cb005"
  subnet_cidr                 = "10.0.0.0/24"
  create_vpc_connector        = true
  vpc_connector_name          = "ss-vpc-conn-f1b3552"
  vpc_connector_mode          = "ip_cidr_range"
  vpc_connector_ip_cidr_range = "10.8.0.0/28"
  manage_public_ssh_deny      = true
  enable_iap_ssh              = true
  iap_ssh_target_tags         = ["superserve-vmd"]
  firewall_rules = {
    vmd_grpc = {
      name          = "superserve-allow-internal-7506206"
      direction     = "INGRESS"
      source_ranges = ["10.0.0.0/24"]
      target_tags   = ["superserve-vmd"]
      allow = [
        {
          protocol = "tcp"
          ports    = ["5007", "5008", "50051"]
        }
      ]
      description = "Allow private sandbox control traffic only."
    }
    api_to_host_otel = {
      name          = "superserve-staging-api-to-host-otel"
      direction     = "INGRESS"
      source_ranges = ["10.8.0.0/28"]
      target_tags   = ["superserve-vmd"]
      allow = [
        {
          protocol = "tcp"
          ports    = ["4317", "4318", "50051"]
        }
      ]
      description = "Allow Cloud Run staging connector traffic to host-local VMD and OTEL Collector endpoints."
    }
  }
  labels = local.common_labels
}

module "iam" {
  source = "../../../modules/iam"

  project_id  = local.project_id
  environment = local.environment
  service_accounts = {
    superserve_api = {
      account_id   = "superserve-api"
      display_name = "Superserve API (Cloud Run)"
    }
    superserve_build = {
      account_id   = "superserve-build"
      display_name = "Superserve Build (Cloud Build / CI)"
    }
    superserve_github_actions = {
      account_id   = "superserve-github-actions"
      display_name = "GitHub Actions CI/CD Service Account"
    }
    grafana_monitoring = {
      account_id   = "grafana-monitoring"
      display_name = "Grafana Monitoring"
    }
  }
  project_bindings = {
    staging_host_collector_metric_writer = {
      role    = "roles/monitoring.metricWriter"
      members = ["serviceAccount:superserve-api@${local.project_id}.iam.gserviceaccount.com"]
    }
    # The CD service account needs subnetworks.update to enable VPC flow logs
    # (added in #257). Granted out-of-band to unblock the staging apply; imported
    # (see imports.tf) so a rebuild adopts it instead of creating a duplicate.
    # Prod's CD SA already carries networkAdmin.
    cd_network_admin = {
      role    = "roles/compute.networkAdmin"
      members = ["serviceAccount:superserve-github-actions@${local.project_id}.iam.gserviceaccount.com"]
    }
    grafana_monitoring_viewer = {
      role = "roles/monitoring.viewer"
      members = [
        "serviceAccount:grafana-monitoring@${local.project_id}.iam.gserviceaccount.com"
      ]
    }

    grafana_browser = {
      role = "roles/browser"
      members = [
        "serviceAccount:grafana-monitoring@${local.project_id}.iam.gserviceaccount.com"
      ]
    }
  }
  labels = local.common_labels
}

module "artifact_storage" {
  source = "../../../modules/artifact-storage"

  project_id  = local.project_id
  environment = local.environment
  region      = local.region
  buckets = {
    superserve_artifacts = {
      name          = "superserve-artifacts"
      location      = "US-CENTRAL1"
      storage_class = "STANDARD"
    }
  }
  labels = local.common_labels
}

module "api" {
  source = "../../../modules/api"

  project_id            = local.project_id
  environment           = local.environment
  region                = local.region
  service_name          = "superserve-api"
  service_account_email = module.iam.service_account_emails["superserve_api"]
  image                 = "us-central1-docker.pkg.dev/${local.project_id}/superserve/controlplane:replace-me"
  env = {
    API_PORT                    = "8080"
    EDGE_PROXY_DOMAIN           = "staging-sandbox.superserve.ai"
    OTEL_ENVIRONMENT            = local.environment
    OTEL_EXPORTER_OTLP_ENDPOINT = local.staging_otlp_endpoint
    OTEL_EXPORT_INTERVAL        = "15s"
    OTEL_METRICS_ENABLED        = "true"
    OTEL_SERVICE_NAME           = "sandbox-controlplane"
    SUPABASE_URL                = var.supabase_url
    VMD_GRPC_ADDRESS            = format("%s:50051", module.sandbox_host.internal_ip)
    STRIPE_API_BASE_URL         = "https://api.stripe.com"
    STRIPE_CHECKOUT_PRICE_IDS   = "price_1U1UnbQ9Sm5V6nX8PqeQuuOz,price_1U1UqtQ9Sm5V6nX8E1or6k4w"
    STRIPE_API_VERSION          = "2026-05-27.dahlia"
    APP_ALLOWED_ORIGINS         = "https://console-staging.superserve.ai"
  }
  secrets = {
    SANDBOX_ACCESS_TOKEN_SEED = {
      secret = coalesce(var.sandbox_access_token_seed_secret_name, "sandbox-access-token-seed-${local.resource_suffix}")
    }
    SECRETS_SIGNING_KEY = {
      secret = coalesce(var.secrets_signing_key_secret_name, "secretsproxy-signing-key-${local.resource_suffix}")
    }
    DATABASE_URL = {
      secret = coalesce(var.database_url_secret_name, "database-url-${local.resource_suffix}")
    }
    INTERNAL_API_TOKEN = {
      secret = coalesce(var.internal_api_token_secret_name, "internal-api-token-${local.resource_suffix}")
    }
    SYSTEM_TEAM_ID = {
      secret = coalesce(var.system_team_id_secret_name, "system-team-id-${local.resource_suffix}")
    }
    STRIPE_SECRET_KEY = {
      secret = google_secret_manager_secret.stripe_secret_key.secret_id
    }

    STRIPE_WEBHOOK_SECRET = {
      secret = google_secret_manager_secret.stripe_webhook_secret.secret_id
    }
    STRIPE_METER_ERROR_WEBHOOK_SECRET = {
      secret = google_secret_manager_secret.stripe_meter_error_webhook_secret.secret_id
    }
  }
  vpc_connector = module.network.vpc_connector_id
  labels        = local.common_labels

  depends_on = [
    google_secret_manager_secret_iam_member.api_runtime_system_team_id,
    google_secret_manager_secret_iam_member.api_runtime_stripe_secret_key,
    google_secret_manager_secret_iam_member.api_runtime_stripe_webhook_secret,
    google_secret_manager_secret_iam_member.api_runtime_stripe_meter_error_webhook_secret,
  ]
}
resource "google_compute_disk" "sandbox_data" {
  project = local.project_id
  name    = "superserve-vmd-staging-sandbox-data"
  zone    = local.zone
  type    = "pd-balanced"
  size    = 500

  labels = merge(local.common_labels, {
    component = "vmd"
    purpose   = "sandbox-data"
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_compute_attached_disk" "sandbox_data" {
  project     = local.project_id
  zone        = local.zone
  disk        = google_compute_disk.sandbox_data.id
  instance    = module.sandbox_host.instance_self_link
  device_name = "superserve-sandbox-data"
  mode        = "READ_WRITE"

  deletion_policy = "PREVENT"
}
resource "google_secret_manager_secret_iam_member" "api_runtime_system_team_id" {
  project   = local.project_id
  secret_id = coalesce(var.system_team_id_secret_name, "system-team-id-${local.resource_suffix}")
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${module.iam.service_account_emails["superserve_api"]}"
}
resource "google_secret_manager_secret_iam_member" "api_runtime_stripe_secret_key" {
  project   = local.project_id
  secret_id = google_secret_manager_secret.stripe_secret_key.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${module.iam.service_account_emails["superserve_api"]}"
}

resource "google_secret_manager_secret_iam_member" "api_runtime_stripe_webhook_secret" {
  project   = local.project_id
  secret_id = google_secret_manager_secret.stripe_webhook_secret.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${module.iam.service_account_emails["superserve_api"]}"
}

resource "google_secret_manager_secret_iam_member" "api_runtime_stripe_meter_error_webhook_secret" {
  project   = local.project_id
  secret_id = google_secret_manager_secret.stripe_meter_error_webhook_secret.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${module.iam.service_account_emails["superserve_api"]}"
}
resource "google_secret_manager_secret" "stripe_secret_key" {
  project   = local.project_id
  secret_id = "stripe-secret-key-${local.resource_suffix}"

  replication {
    auto {}
  }

  labels = local.common_labels
}

resource "google_secret_manager_secret" "stripe_webhook_secret" {
  project   = local.project_id
  secret_id = "stripe-webhook-secret-${local.resource_suffix}"

  replication {
    auto {}
  }

  labels = local.common_labels
}

resource "google_secret_manager_secret" "stripe_meter_error_webhook_secret" {
  project   = local.project_id
  secret_id = "stripe-meter-error-webhook-secret-${local.resource_suffix}"

  replication {
    auto {}
  }

  labels = local.common_labels
}

module "sandbox_host" {
  source = "../../../modules/sandbox-host"

  project_id    = local.project_id
  environment   = local.environment
  region        = local.region
  zone          = local.zone
  instance_name = "superserve-vmd-staging"
  machine_type  = "n2-standard-32"

  subnet      = "projects/rayai-dev/regions/us-central1/subnetworks/superserve-subnet-05cb005"
  internal_ip = "10.0.0.2"
  tags        = ["superserve-vmd"]

  labels = merge(local.sandbox_host_labels, {
    component    = "vmd"
    sandbox_role = "vmd"
  })

  service_account_email = module.iam.service_account_emails["superserve_api"]
  boot_disk_image       = "projects/rayai-dev/global/images/superserve-vmd-20260401-224137"
  boot_disk_size_gb     = 200
  can_ip_forward        = true

  metadata = {
    startup-script = <<-EOT
      #!/bin/bash
      # Minimal startup script — the Packer image has everything pre-installed.
      # This just detects the host network interface and starts VMD.
      set -euo pipefail
      exec > /var/log/startup-script.log 2>&1

      echo "=== Superserve VMD startup ==="

      # Detect host network interface and update env
      HOST_IFACE=$(ip -4 route show default | awk '{print $5}' | head -1)
      sed -i "s/^HOST_INTERFACE=.*/HOST_INTERFACE=$${HOST_IFACE}/" /etc/superserve/vmd.env

      # Ensure KVM is available
      modprobe kvm
      modprobe kvm_intel 2>/dev/null || modprobe kvm_amd 2>/dev/null || true
      chmod 0666 /dev/kvm 2>/dev/null || true

      # Ensure IP forwarding
      sysctl -w net.ipv4.ip_forward=1

      # Clean stale state from previous run
      pkill -9 firecracker 2>/dev/null || true
      for ns in $(ip netns list 2>/dev/null | awk '{print $1}'); do ip netns del $ns 2>/dev/null; done
      rm -rf /var/lib/superserve/snapshots/* /var/lib/superserve/rundir/*

      # Start VMD
      systemctl start superserve-vmd

      echo "=== Superserve VMD started ==="
    EOT
  }
}

# Second staging host, so a cell with two serving hosts can be rehearsed
# before it exists anywhere else: placement spreading across hosts, taking a
# host out of rotation, moving sandbox ownership between hosts, and the
# data-plane forwarding that makes both hosts reachable. Same image and shape
# as the first host so the two are interchangeable, and labeled component=vmd
# from creation so every deploy that discovers hosts by label reaches both
# without a relabel step.
#
# The host self-registers as provisioning and stays invisible to placement
# until an operator activates it, so creating it changes nothing for the cell
# until that deliberate step.
module "sandbox_host_b" {
  source = "../../../modules/sandbox-host"

  project_id    = local.project_id
  environment   = local.environment
  region        = local.region
  zone          = local.zone
  instance_name = "superserve-vmd-staging-2"
  machine_type  = "n2-standard-32"

  subnet      = "projects/rayai-dev/regions/us-central1/subnetworks/superserve-subnet-05cb005"
  internal_ip = "10.0.0.3"
  tags        = ["superserve-vmd"]

  labels = merge(local.sandbox_host_labels, {
    component    = "vmd"
    sandbox_role = "vmd"
  })

  service_account_email = module.iam.service_account_emails["superserve_api"]
  boot_disk_image       = "projects/rayai-dev/global/images/superserve-vmd-20260401-224137"
  boot_disk_size_gb     = 200
  # The first host runs on pd-ssd, but only because its disk predates this
  # module and was imported: the module's own default is the API's
  # pd-standard. Declared so the two hosts actually match.
  boot_disk_type = "pd-ssd"
  can_ip_forward = true

  metadata = {
    startup-script = <<-EOT
      #!/bin/bash
      # Runs on every boot. Everything here is idempotent.
      set -euo pipefail
      exec > /var/log/startup-script.log 2>&1

      echo "=== Superserve VMD startup ==="

      # The image ships an env file carrying the first host's identity, and
      # the deploy pipeline only sets HOST_ID when none is present. Left
      # alone, this host would heartbeat under a name already in use and be
      # refused. Take this instance's own name from the metadata server.
      NAME=$(curl -sf -H 'Metadata-Flavor: Google' \
        http://metadata.google.internal/computeMetadata/v1/instance/name)
      if grep -q '^HOST_ID=' /etc/sandbox/vmd.env; then
        sed -i "s/^HOST_ID=.*/HOST_ID=$${NAME}/" /etc/sandbox/vmd.env
      else
        echo "HOST_ID=$${NAME}" >> /etc/sandbox/vmd.env
      fi

      HOST_IFACE=$(ip -4 route show default | awk '{print $5}' | head -1)
      sed -i "s/^HOST_INTERFACE=.*/HOST_INTERFACE=$${HOST_IFACE}/" /etc/sandbox/vmd.env

      # Background-data disk: backup journal and upload staging. Formatted
      # once, when blank; mounted every boot. The vmd deploy refuses to run
      # against a host where this path is not a real mount. A plain mount on
      # purpose: the first host's migration tooling never completed a
      # migration, and its effective state is exactly this.
      DEV=/dev/disk/by-id/google-superserve-sandbox-data
      for _ in $(seq 1 120); do [ -e "$DEV" ] && break; sleep 1; done
      if [ -z "$(blkid -s TYPE -o value "$DEV" 2>/dev/null)" ]; then
        mkfs.xfs -m crc=1,reflink=1 "$DEV"
      fi
      mkdir -p /mnt/sandbox-data
      mountpoint -q /mnt/sandbox-data || mount -t xfs -o noatime,discard "$DEV" /mnt/sandbox-data
      grep -q 'google-superserve-sandbox-data' /etc/fstab || \
        echo "$DEV /mnt/sandbox-data xfs noatime,discard,nofail 0 2" >> /etc/fstab

      # Runtime flags the first host carries as hand-installed drop-ins.
      # Nothing deploys these, and without them the two hosts would launch
      # and track VMs differently.
      mkdir -p /etc/systemd/system/superserve-vmd.service.d
      printf '[Service]\nEnvironment=VMD_DIRTY_TRACKING_SESSION=true\n' \
        > /etc/systemd/system/superserve-vmd.service.d/dirty-session.conf
      printf '[Service]\nEnvironment=VMD_LAUNCH_VIA_LAUNCHER_NS=true\n' \
        > /etc/systemd/system/superserve-vmd.service.d/launcher.conf
      printf '[Service]\nEnvironment=VMD_SYSTEMD_DBUS=true\n' \
        > /etc/systemd/system/superserve-vmd.service.d/sdbus.conf
      printf '[Service]\nEnvironment=VMD_RECYCLE_TAP_RESET=true\n' \
        > /etc/systemd/system/superserve-vmd.service.d/tap-reset.conf
      systemctl daemon-reload

      modprobe kvm
      modprobe kvm_intel 2>/dev/null || modprobe kvm_amd 2>/dev/null || true
      chmod 0666 /dev/kvm 2>/dev/null || true
      sysctl -w net.ipv4.ip_forward=1

      # Best effort: the image's vmd may lack per-host files the deploy does
      # not carry (egress blocklist, guest kernel, proxy CA). Those are
      # copied from the first host before the first deploy, which then
      # (re)starts vmd. A failure here must not fail the boot.
      systemctl start superserve-vmd || true

      echo "=== Superserve VMD started ==="
    EOT
  }
}

# The second host's own background-data disk, same shape as the first's.
resource "google_compute_disk" "sandbox_data_b" {
  project = local.project_id
  name    = "superserve-vmd-staging-2-sandbox-data"
  zone    = local.zone
  type    = "pd-balanced"
  size    = 500

  labels = merge(local.common_labels, {
    component = "vmd"
    purpose   = "sandbox-data"
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_compute_attached_disk" "sandbox_data_b" {
  project     = local.project_id
  zone        = local.zone
  disk        = google_compute_disk.sandbox_data_b.id
  instance    = module.sandbox_host_b.instance_self_link
  device_name = "superserve-sandbox-data"
  mode        = "READ_WRITE"

  deletion_policy = "PREVENT"
}

module "observability" {
  source = "../../../modules/observability"

  project_id  = local.project_id
  environment = local.environment
  # Backup pipeline alerts, same set as the production cells so staging
  # validates the queries before they matter. The disabled-host alert
  # stays off here: staging toggles BACKUP_BUCKET deliberately.
  backup_alerts = {
    host_id             = module.sandbox_host.instance_name
    display_prefix      = "Backup / ${module.sandbox_host.instance_name}"
    alert_disabled_host = false
  }
  # Backup coverage, same disabled-by-default shape as the production
  # cells so staging validates the policy config (including the
  # region-scoped companion condition) before it matters. regions lists
  # the host table's region column values in this cell's database, not
  # GCP region names; "us-central1" is the only value present.
  backup_coverage_alerts = {
    enabled        = false
    display_prefix = "Backup coverage / staging"
    regions        = ["us-central1"]
  }
  # Root-filesystem (OS disk) utilization, same policies as the production
  # cells so staging validates the query shape first. Module defaults:
  # warn at 85% sustained 30 minutes, page at 95%.
  host_disk_alerts = {
    host_id        = module.sandbox_host.instance_name
    display_prefix = "Infrastructure / ${module.sandbox_host.instance_name}"
  }
  dashboards = {
    sandbox_operations = {
      display_name = "Sandbox Telemetry / Staging Operations"
      definition = templatefile("${path.module}/../../../dashboards/cloud-monitoring/sandbox-telemetry-operations.json.tftpl", {
        environment  = local.environment
        display_name = "Sandbox Telemetry / Staging Operations"
      })
    }

    sandbox_collector = {
      display_name = "Sandbox Telemetry / Collector"
      definition   = file("${path.module}/../../../dashboards/cloud-monitoring/sandbox-telemetry-collector.json")
    }

    sandbox_fleet = {
      display_name = "Sandbox Telemetry / Staging Fleet"
      definition = templatefile("${path.module}/../../../dashboards/cloud-monitoring/sandbox-telemetry-fleet.json.tftpl", {
        environment  = local.environment
        display_name = "Sandbox Telemetry / Staging Fleet"
      })
    }

    sandbox_hosts = {
      display_name = "Sandbox Telemetry / Staging Hosts"
      definition = templatefile("${path.module}/../../../dashboards/cloud-monitoring/sandbox-telemetry-hosts.json.tftpl", {
        environment  = local.environment
        display_name = "Sandbox Telemetry / Staging Hosts"
      })
    }

    sandbox_database = {
      display_name = "Sandbox Telemetry / Staging Database"
      definition = templatefile("${path.module}/../../../dashboards/cloud-monitoring/sandbox-telemetry-database.json.tftpl", {
        environment  = local.environment
        display_name = "Sandbox Telemetry / Staging Database"
      })
    }
  }
  uptime_checks = {
    api = {
      display_name = "superserve-api-staging"
      host         = "staging-sandbox.superserve.ai"
      path         = "/"
      port         = 443
    }
  }
  labels = local.common_labels
}

# Durability tier for the host's local artifacts (sandbox snapshots, template
# builds); mirrors the production cells so the uploader and restore tooling
# exercise the same IAM shape (write-only host, dedicated GC identity) before
# they ever run in prod.
module "backup_storage" {
  source = "../../../modules/backup-storage"

  project_id  = local.project_id
  environment = local.environment
  location    = local.region
  bucket_name = "superserve-artifact-backup-${local.resource_suffix}"

  # Not suffixed with resource_suffix: "superserve-backup-gc-staging-usc1"
  # would exceed the 30-char SA account_id cap. Same for the restore reader.
  gc_service_account_id      = "superserve-backup-gc-staging"
  restore_service_account_id = "superserve-backup-ro-staging"

  writer_members = [
    "serviceAccount:${module.iam.service_account_emails["superserve_api"]}",
  ]

  labels = merge(local.common_labels, {
    component = "backup"
  })
}
