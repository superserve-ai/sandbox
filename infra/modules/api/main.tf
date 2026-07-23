terraform {
  required_version = ">= 1.5.0"
}

locals {
  use_direct_vpc = var.vpc_connector == null && var.vpc_network != null && var.vpc_subnetwork != null
  use_vpc_access = var.vpc_connector != null || local.use_direct_vpc
}

resource "google_cloud_run_v2_service" "this" {
  project  = var.project_id
  name     = var.service_name
  location = var.region
  ingress  = var.ingress

  template {
    service_account = var.service_account_email
    timeout         = "300s"

    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    dynamic "vpc_access" {
      for_each = local.use_vpc_access ? [1] : []

      content {
        connector = var.vpc_connector
        egress    = var.vpc_egress

        dynamic "network_interfaces" {
          for_each = local.use_direct_vpc ? [1] : []

          content {
            network    = var.vpc_network
            subnetwork = var.vpc_subnetwork
            tags       = var.vpc_tags
          }
        }
      }
    }

    containers {
      image = var.image

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = var.cpu_limit
          memory = var.memory_limit
        }

        cpu_idle          = var.cpu_idle
        startup_cpu_boost = var.startup_cpu_boost
      }

      dynamic "env" {
        for_each = var.env

        content {
          name  = env.key
          value = env.value
        }
      }

      dynamic "env" {
        for_each = var.secrets

        content {
          name = env.key

          value_source {
            secret_key_ref {
              secret  = env.value.secret
              version = env.value.version
            }
          }
        }
      }
    }

    labels = var.labels
  }

  lifecycle {
    ignore_changes = [
      client,
      client_version,
      # Deploy tooling adds transient service labels (e.g. cachebust) the module
      # does not declare; ignore label drift so an apply doesn't strip them.
      labels,
      scaling,
      template[0].containers[0].image,
      traffic,
    ]
  }

  labels              = var.labels
  deletion_protection = true
}

# Public, unauthenticated invoker. The API is reached through an external
# HTTPS load balancer (serverless NEG -> this service), which forwards requests
# as allUsers, so the service must grant run.invoker to allUsers. This binding
# was applied imperatively (`gcloud run services add-iam-policy-binding`) in
# every cell; declaring it here adopts the live grants via import.
resource "google_cloud_run_v2_service_iam_member" "public_invoker" {
  count = var.allow_public_invoker ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.this.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

locals {
  api_contract = {
    project_id            = var.project_id
    environment           = var.environment
    region                = var.region
    service_name          = google_cloud_run_v2_service.this.name
    service_account_email = var.service_account_email
    image                 = var.image
    ingress               = var.ingress
    cpu_limit             = var.cpu_limit
    memory_limit          = var.memory_limit
    cpu_idle              = var.cpu_idle
    startup_cpu_boost     = var.startup_cpu_boost
    min_instances         = var.min_instances
    max_instances         = var.max_instances
    env                   = var.env
    secrets               = var.secrets
    vpc_connector         = var.vpc_connector
    vpc_network           = var.vpc_network
    vpc_subnetwork        = var.vpc_subnetwork
    vpc_tags              = var.vpc_tags
    vpc_egress            = var.vpc_egress
    labels                = var.labels
  }
}
