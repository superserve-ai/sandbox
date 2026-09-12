terraform {
  required_version = ">= 1.7.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 7.0, < 8.0"
    }
  }
}

# Private CA and IAM APIs must already be enabled by the environment.
resource "google_privateca_ca_pool" "this" {
  project  = var.project_id
  location = var.region
  name     = var.name
  tier     = "ENTERPRISE"

  issuance_policy {
    maximum_lifetime = "${var.leaf_lifetime_seconds}s"
    allowed_issuance_modes {
      # The issuer verifies the CSR but constructs the certificate from its own policy.
      allow_csr_based_issuance    = false
      allow_config_based_issuance = true
    }
    identity_constraints {
      allow_subject_passthrough           = true
      allow_subject_alt_names_passthrough = true
      cel_expression {
        expression = "subject.common_name == 'vmd-peer-proxy' && subject_alt_names.size() == 1 && subject_alt_names.all(san, san.type == URI && san.value == ${jsonencode(var.spiffe_uri)})"
        title      = "Exact cell peer identity"
      }
    }
    baseline_values {
      ca_options { is_ca = false }
      key_usage {
        base_key_usage { digital_signature = true }
        extended_key_usage {
          server_auth = true
          client_auth = true
        }
      }
    }
  }
  lifecycle { prevent_destroy = true }
}

resource "google_privateca_certificate_authority" "root" {
  project                  = var.project_id
  location                 = var.region
  pool                     = google_privateca_ca_pool.this.name
  certificate_authority_id = "${var.name}-root"
  type                     = "SELF_SIGNED"
  lifetime                 = "${var.ca_lifetime_seconds}s"
  desired_state            = "ENABLED"
  deletion_protection      = true

  # CAS creates/custodies the non-exportable KMS signing key. State stores only
  # its algorithm/reference; neither Terraform nor the issuer receives key bytes.
  key_spec { algorithm = "EC_P256_SHA256" }
  config {
    subject_config {
      subject {
        common_name  = "${var.name} root"
        organization = "Superserve"
      }
    }
    x509_config {
      ca_options {
        is_ca                       = true
        zero_max_issuer_path_length = true
      }
      key_usage {
        base_key_usage {
          cert_sign = true
          crl_sign  = true
        }
        extended_key_usage {
          server_auth = true
          client_auth = true
        }
      }
    }
  }
  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.ca_lifetime_seconds > var.leaf_lifetime_seconds
      error_message = "CA lifetime must exceed the leaf lifetime."
    }
  }
}

resource "google_service_account" "issuer" {
  project      = var.project_id
  account_id   = var.issuer_account_id
  display_name = "Peer certificate issuer ${var.name}"
  lifecycle { prevent_destroy = true }
}

# Authoritative for this pool role. Project/folder/org inheritance must also be
# audited; a resource-level binding cannot revoke inherited issuance permission.
resource "google_privateca_ca_pool_iam_binding" "issuer" {
  project  = var.project_id
  location = var.region
  ca_pool  = google_privateca_ca_pool.this.id
  role     = "roles/privateca.certificateRequester"
  members  = ["serviceAccount:${google_service_account.issuer.email}"]
}

resource "google_service_account_iam_binding" "operators" {
  count              = length(var.operator_members) == 0 ? 0 : 1
  service_account_id = google_service_account.issuer.name
  role               = "roles/iam.serviceAccountTokenCreator"
  members            = var.operator_members
}
