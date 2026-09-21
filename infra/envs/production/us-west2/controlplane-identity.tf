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

locals {
  controlplane_secrets = {
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
