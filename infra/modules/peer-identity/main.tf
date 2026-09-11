terraform {
  required_version = ">= 1.5.0"
}

data "google_project" "this" { project_id = var.project_id }

resource "google_project_service" "privateca" {
  project            = var.project_id
  service            = "privateca.googleapis.com"
  disable_on_destroy = false
}

# A cell shares this CA and trust domain; adding hosts adds attestation rules,
# not another CA. Staging and production do not trust one another.
resource "google_privateca_ca_pool" "peer" {
  project  = var.project_id
  location = var.region
  name     = "vmd-peer-${var.cell}"
  tier     = "ENTERPRISE"
  issuance_policy {
    maximum_lifetime = "86400s"
    baseline_values {
      ca_options { is_ca = false }
      key_usage {
        base_key_usage {
          digital_signature = true
          key_encipherment  = true
        }
        extended_key_usage {
          server_auth = true
          client_auth = true
        }
      }
    }
  }
  depends_on = [google_project_service.privateca]
  lifecycle { prevent_destroy = true }
}

resource "google_privateca_certificate_authority" "peer" {
  project                  = var.project_id
  location                 = var.region
  pool                     = google_privateca_ca_pool.peer.name
  certificate_authority_id = "vmd-peer-root"
  type                     = "SELF_SIGNED"
  lifetime                 = "315360000s"
  deletion_protection      = true
  config {
    subject_config {
      subject {
        common_name  = "VMD peer ${var.cell}"
        organization = "Superserve"
      }
    }
    x509_config {
      ca_options {
        is_ca                  = true
        max_issuer_path_length = 0
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
  key_spec { algorithm = "EC_P256_SHA256" }
  desired_state = "ENABLED"
  lifecycle { prevent_destroy = true }
}

locals {
  pool_id = "vmd-peer-${var.cell}"
  subject = "${local.pool_id}.global.${data.google_project.this.number}.workload.id.goog/ns/vmd/sa/vmd-peer-proxy"
  configuration = {
    project_id     = var.project_id
    project_number = data.google_project.this.number
    region         = var.region
    pool_id        = local.pool_id
    ca_pool        = google_privateca_ca_pool.peer.id
    namespace      = "vmd"
    identity       = "vmd-peer-proxy"
    spiffe_uri     = "spiffe://${local.subject}"
    instance_name  = var.instance_name
    instance_id    = var.instance_id
    zone           = var.zone
    internal_ip    = var.internal_ip
    host_id        = var.host_id
    runtime_email  = var.runtime_email
  }
}

# Stable Google 6.x lacks the trust-domain and Compute identity fields. Keep
# the API adapter and its inputs in Terraform rather than upgrading all hosts.
resource "terraform_data" "managed_identity" {
  triggers_replace = [local.configuration, filesha256("${path.module}/configure.py")]
  provisioner "local-exec" {
    command     = "python3 \"${path.module}/configure.py\""
    environment = { PEER_IDENTITY_CONFIG = jsonencode(local.configuration) }
  }
  depends_on = [google_privateca_certificate_authority.peer]
}

output "bootstrap" {
  value      = local.configuration
  depends_on = [terraform_data.managed_identity]
}
