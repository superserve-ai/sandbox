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
  firewall_rules = {
    vmd_grpc = {
      name          = "superserve-allow-internal-7506206"
      direction     = "INGRESS"
      source_ranges = ["10.0.0.0/24"]
      target_tags   = []
      allow = [
        {
          protocol = "tcp"
          ports    = ["0-65535"]
        },
        {
          protocol = "udp"
          ports    = ["0-65535"]
        },
        {
          protocol = "icmp"
          ports    = []
        }
      ]
      description = null
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
  }
  project_bindings = {
    staging_host_collector_metric_writer = {
      role    = "roles/monitoring.metricWriter"
      members = ["serviceAccount:superserve-api@${local.project_id}.iam.gserviceaccount.com"]
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
  }
  vpc_connector = module.network.vpc_connector_id
  labels        = local.common_labels

  depends_on = [google_secret_manager_secret_iam_member.api_runtime_system_team_id]
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

  labels = merge(local.common_labels, {
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

module "observability" {
  source = "../../../modules/observability"

  project_id  = local.project_id
  environment = local.environment
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
