# Cloud Run workloads. Shapes follow the api module: Direct VPC egress, image
# and label drift owned by deploy tooling, secrets mounted as env from Secret
# Manager. Names are locals rather than resource references because the job
# and service both carry the full QM_* set, including their own names.
locals {
  api_service_name      = coalesce(var.api_service_name, "superserve-qm-api-${var.resource_suffix}")
  redirect_service_name = coalesce(var.redirect_service_name, "qm-redirect-${var.resource_suffix}")
  provisioner_job_name  = var.provisioner_job_name
  provisioner_image     = coalesce(var.provisioner_image, var.api_image)

  tenant_image = coalesce(var.tenant_image, "${local.tenant_image_repository}/qm:latest")

  # Everything qm-api and the provisioner need to find the shared pieces.
  # Both get the same map so a tenant provisioned by the job and one
  # inspected by the API agree on names. GCP_PROJECT, QM_BASE_DOMAIN,
  # QM_PROVISIONER_JOB, QM_PROVISIONER_REGION and QM_TENANT_IMAGE are what
  # internal/qm.LoadConfig reads today; the rest is for the step clients
  # behind internal/qm/provisioner/steps as they land.
  runtime_env = {
    GCP_PROJECT                      = var.project_id
    QM_BASE_DOMAIN                   = var.domain
    QM_PROVISIONER_REGION            = var.region
    QM_ENVIRONMENT                   = var.environment
    QM_VPC_NETWORK                   = var.vpc_network
    QM_VPC_SUBNETWORK                = var.vpc_subnetwork
    QM_SQL_INSTANCE                  = google_sql_database_instance.tenants.name
    QM_SQL_CONNECTION_NAME           = google_sql_database_instance.tenants.connection_name
    QM_SQL_PRIVATE_IP                = google_sql_database_instance.tenants.private_ip_address
    QM_SQL_ADMIN_USER                = var.sql_admin_user
    QM_SQL_ADMIN_SECRET              = google_secret_manager_secret.sql_admin.secret_id
    QM_LB_ADDRESS                    = google_compute_global_address.edge.address
    QM_LB_URL_MAP                    = google_compute_url_map.https.name
    QM_LB_HTTPS_PROXY                = google_compute_target_https_proxy.this.name
    QM_LB_REDIRECT_BACKEND           = google_compute_backend_service.redirect.name
    QM_CERTIFICATE_MAP               = google_certificate_manager_certificate_map.this.name
    QM_PROVISIONER_JOB               = local.provisioner_job_name
    QM_PROVISIONER_SERVICE_ACCOUNT   = google_service_account.provisioner.email
    QM_TENANT_SERVICE_ACCOUNT_PREFIX = local.tenant_service_account_prefix
    QM_TENANT_BUCKET_NAME_PATTERN    = local.tenant_bucket_name_pattern
    QM_TENANT_SLUG_MAX_LENGTH        = tostring(local.tenant_slug_max_length)
    QM_TENANT_BUCKET_LOCATION        = local.tenant_bucket_location
    QM_TENANT_BUCKET_LIFECYCLE_JSON  = jsonencode(local.tenant_bucket_lifecycle_policy)
    QM_TENANT_IMAGE_REPOSITORY       = local.tenant_image_repository
    QM_TENANT_IMAGE                  = local.tenant_image
  }

  api_env         = merge(local.runtime_env, var.api_env)
  provisioner_env = merge(local.runtime_env, var.provisioner_env)

  # The tenant registry lives in the control-plane Postgres, and both the
  # API and the provisioner (which records what it created) connect to it as
  # qm_api. The instance admin credentials are separate and provisioner-only.
  database_url_secret = {
    DATABASE_URL = {
      secret  = google_secret_manager_secret.api_database_url.secret_id
      version = "latest"
    }
  }

  api_secrets         = merge(local.database_url_secret, var.api_secrets)
  provisioner_secrets = local.database_url_secret
}

resource "google_cloud_run_v2_service" "api" {
  project             = var.project_id
  name                = local.api_service_name
  location            = var.region
  ingress             = var.api_ingress
  deletion_protection = var.api_deletion_protection

  template {
    service_account = google_service_account.api.email
    timeout         = "300s"

    scaling {
      min_instance_count = var.api_min_instances
      max_instance_count = var.api_max_instances
    }

    vpc_access {
      egress = var.vpc_egress

      network_interfaces {
        network    = var.vpc_network
        subnetwork = var.vpc_subnetwork
        tags       = var.vpc_tags
      }
    }

    containers {
      image = var.api_image

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = var.api_cpu_limit
          memory = var.api_memory_limit
        }
      }

      dynamic "env" {
        for_each = local.api_env

        content {
          name  = env.key
          value = env.value
        }
      }

      dynamic "env" {
        for_each = local.api_secrets

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

  labels = var.labels

  lifecycle {
    ignore_changes = [
      client,
      client_version,
      labels,
      template[0].containers[0].image,
      traffic,
    ]
  }

  depends_on = [
    google_project_service.required,
    google_secret_manager_secret_iam_member.api_database_url,
  ]
}

resource "google_cloud_run_v2_service_iam_member" "api_public_invoker" {
  count = var.api_allow_public_invoker ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.api.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# Default backend of the tenant load balancer: 302s /<slug> to
# https://<slug>.<domain> and / to the marketing page. Reachable only through
# the load balancer, which forwards as allUsers.
resource "google_cloud_run_v2_service" "redirect" {
  project             = var.project_id
  name                = local.redirect_service_name
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
  deletion_protection = false

  template {
    service_account = google_service_account.redirect.email
    timeout         = "30s"

    scaling {
      min_instance_count = 0
      max_instance_count = 3
    }

    containers {
      image = var.redirect_image

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "256Mi"
        }
      }

      dynamic "env" {
        for_each = merge({
          QM_BASE_DOMAIN   = var.domain
          QM_MARKETING_URL = var.marketing_url
        }, var.redirect_env)

        content {
          name  = env.key
          value = env.value
        }
      }
    }

    labels = var.labels
  }

  labels = var.labels

  lifecycle {
    ignore_changes = [
      client,
      client_version,
      labels,
      template[0].containers[0].image,
      traffic,
    ]
  }

  depends_on = [google_project_service.required]
}

resource "google_cloud_run_v2_service_iam_member" "redirect_public_invoker" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.redirect.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# The provisioner runs as a job rather than inside qm-api so tenant creation
# (minutes of Cloud SQL, Cloud Run, and load balancer operations) survives API
# deploys, and so the broad provisioning grants sit on an identity that
# serves no request traffic. qm-api triggers executions with run.jobs.run.
resource "google_cloud_run_v2_job" "provisioner" {
  project             = var.project_id
  name                = local.provisioner_job_name
  location            = var.region
  deletion_protection = false

  template {
    task_count  = 1
    parallelism = 1
    labels      = var.labels

    template {
      service_account = google_service_account.provisioner.email
      timeout         = "${var.provisioner_timeout_seconds}s"
      # Provisioning is not idempotent across a blind retry; qm-api decides
      # whether to re-run a failed execution.
      max_retries = 0

      vpc_access {
        egress = var.vpc_egress

        network_interfaces {
          network    = var.vpc_network
          subnetwork = var.vpc_subnetwork
          tags       = var.vpc_tags
        }
      }

      containers {
        image = local.provisioner_image

        resources {
          limits = {
            cpu    = var.provisioner_cpu_limit
            memory = var.provisioner_memory_limit
          }
        }

        dynamic "env" {
          for_each = local.provisioner_env

          content {
            name  = env.key
            value = env.value
          }
        }

        dynamic "env" {
          for_each = local.provisioner_secrets

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
    }
  }

  labels = var.labels

  lifecycle {
    ignore_changes = [
      client,
      client_version,
      labels,
      template[0].template[0].containers[0].image,
    ]
  }

  depends_on = [
    google_project_service.required,
    google_secret_manager_secret_iam_member.provisioner_database_url,
  ]
}
