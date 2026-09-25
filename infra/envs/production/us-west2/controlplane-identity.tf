resource "google_service_account" "controlplane_runtime" {
  project      = local.project_id
  account_id   = "superserve-controlplane-${local.resource_suffix}"
  display_name = "Control plane runtime ${local.resource_suffix}"
}

# Secret values are provisioned by operators, never stored in Terraform state.
resource "google_secret_manager_secret" "operator_api_token" {
  project   = local.project_id
  secret_id = "operator-api-token-${local.resource_suffix}"
  replication {
    auto {}
  }
  labels = local.common_labels
}

resource "google_secret_manager_secret" "promotion_auth_database_url" {
  project   = local.project_id
  secret_id = "promotion-auth-database-url-${local.resource_suffix}"
  replication {
    auto {}
  }
  labels = local.common_labels
}

resource "google_secret_manager_secret" "promotion_capture_token" {
  project   = local.project_id
  secret_id = "promotion-capture-token-${local.resource_suffix}"
  replication {
    auto {}
  }
  labels = local.common_labels
}

resource "google_secret_manager_secret" "promotion_account_token" {
  project   = local.project_id
  secret_id = "promotion-account-token-${local.resource_suffix}"
  replication {
    auto {}
  }
  labels = local.common_labels
}

locals {
  # Operators publish versions; Terraform manages only the mount and access.
  controlplane_secret_volumes = {
    compute-restrictions = {
      secret     = var.compute_restrictions_secret_name
      mount_path = "/etc/superserve"
      path       = "abuse-restrictions.json"
      version    = "latest"
    }
  }
  controlplane_secret_ids = toset(concat(
    [for config in values(local.controlplane_secrets) : config.secret],
    [for config in values(local.controlplane_secret_volumes) : config.secret],
  ))

  controlplane_secrets = {
    PROMOTION_AUTH_DATABASE_URL = {
      secret = google_secret_manager_secret.promotion_auth_database_url.secret_id
    }
    PROMOTION_CAPTURE_TOKEN = {
      secret = google_secret_manager_secret.promotion_capture_token.secret_id
    }
    PROMOTION_ACCOUNT_TOKEN = {
      secret = google_secret_manager_secret.promotion_account_token.secret_id
    }
    DATABASE_URL = {
      secret = coalesce(var.database_url_secret_name, "database-url-${local.resource_suffix}")
    }
    OPERATOR_API_TOKEN = {
      secret = google_secret_manager_secret.operator_api_token.secret_id
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
      secret = "stripe-secret-key-usw"
    }
    STRIPE_WEBHOOK_SECRET = {
      secret = "stripe-webhook-secret-usw"
    }
    STRIPE_METER_ERROR_WEBHOOK_SECRET = {
      secret = "stripe-meter-error-webhook-secret-usw"
    }
  }
}

resource "google_secret_manager_secret_iam_member" "controlplane_runtime_secrets" {
  for_each = toset([for config in values(local.controlplane_secrets) : config.secret])

  project   = local.project_id
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.controlplane_runtime.email}"
}

resource "google_secret_manager_secret_iam_member" "controlplane_runtime_secret_volumes" {
  for_each = local.controlplane_secret_volumes

  project   = local.project_id
  secret_id = each.value.secret
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.controlplane_runtime.email}"
}

# CD receives key-scoped IAM administration from the shared us-central1
# bootstrap before this regional root applies runtime grants.
resource "google_kms_crypto_key_iam_member" "controlplane_credentials" {
  crypto_key_id = "projects/${local.project_id}/locations/us-central1/keyRings/superserve/cryptoKeys/credentials-kek"
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.controlplane_runtime.email}"
}

resource "google_service_account_iam_member" "controlplane_deploy_act_as" {
  service_account_id = google_service_account.controlplane_runtime.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${data.google_service_account.github_actions.email}"
}

resource "google_project_iam_member" "controlplane_metric_writer" {
  project = local.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.controlplane_runtime.email}"
}

# The rollout verifier impersonates the runtime identity for permission probes.
resource "google_service_account_iam_member" "controlplane_deploy_token_creator" {
  service_account_id = google_service_account.controlplane_runtime.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${data.google_service_account.github_actions.email}"
}

locals {
  controlplane_identity_contract = {
    environment               = local.environment
    region                    = local.region
    runtime_service_account   = google_service_account.controlplane_runtime.email
    legacy_runtime_account    = local.legacy_runtime_account
    deployment_identity       = data.google_service_account.github_actions.email
    deployment_permissions    = ["iam.serviceAccounts.actAs", "iam.serviceAccounts.getAccessToken"]
    backup_bucket             = module.backup_storage.bucket_name
    backup_object_prefix      = module.backup_storage.contract.reader_object_prefix
    backup_object_prefixes    = module.backup_storage.contract.reader_object_prefixes
    backup_permissions        = ["storage.objects.get", "storage.objects.list"]
    secret_ids                = sort(tolist(local.controlplane_secret_ids))
    kms_key_resource          = "projects/${local.project_id}/locations/us-central1/keyRings/superserve/cryptoKeys/credentials-kek"
    kms_grant_principal       = google_service_account.controlplane_runtime.email
    kms_grant_role            = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
    kms_verification          = "encrypt-decrypt-as-runtime-identity-before-cutover"
    kms_grant_evidence        = "control-plane-identity rollout kms-grant.txt and evidence.json"
    kms_grant_owner           = "regional Terraform root"
    host_identity_unchanged   = local.host_identity_unchanged
    host_identities_unchanged = local.host_identities_unchanged
  }
}
