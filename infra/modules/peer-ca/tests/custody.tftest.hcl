mock_provider "google" {
  mock_resource "google_service_account" {
    defaults = {
      name  = "projects/example-project/serviceAccounts/peer-example-issuer@example-project.iam.gserviceaccount.com"
      email = "peer-example-issuer@example-project.iam.gserviceaccount.com"
    }
  }
}

variables {
  project_id        = "example-project"
  region            = "us-central1"
  name              = "peer-example"
  issuer_account_id = "peer-example-issuer"
  spiffe_uri        = "spiffe://example.test/ns/vmd/sa/vmd-peer-proxy"
}

run "custody_and_policy" {
  command = apply
  assert {
    condition     = google_privateca_certificate_authority.root.key_spec[0].algorithm == "EC_P256_SHA256" && google_privateca_certificate_authority.root.deletion_protection
    error_message = "The CA must use managed signing custody and deletion protection."
  }
  assert {
    condition     = google_privateca_certificate_authority.root.config[0].x509_config[0].ca_options[0].zero_max_issuer_path_length
    error_message = "The root must not issue subordinate CAs."
  }
  assert {
    condition     = google_privateca_ca_pool.this.issuance_policy[0].maximum_lifetime == "2592000s" && !google_privateca_ca_pool.this.issuance_policy[0].allowed_issuance_modes[0].allow_csr_based_issuance
    error_message = "Only issuer-authored config with the configured maximum lifetime is allowed."
  }
  assert {
    condition     = google_privateca_ca_pool_iam_binding.issuer.members == toset(["serviceAccount:${google_service_account.issuer.email}"]) && google_privateca_ca_pool_iam_binding.issuer.role == "roles/privateca.certificateRequester"
    error_message = "Only the issuer may receive the pool issuance role."
  }
  assert {
    condition     = length(google_service_account_iam_binding.operators) == 0
    error_message = "No operator impersonation grants may be inferred."
  }
  assert {
    condition     = strcontains(google_privateca_ca_pool.this.issuance_policy[0].identity_constraints[0].cel_expression[0].expression, jsonencode(var.spiffe_uri)) && strcontains(google_privateca_ca_pool.this.issuance_policy[0].identity_constraints[0].cel_expression[0].expression, "subject_alt_names.size() == 1")
    error_message = "Pool policy must constrain the sole URI SAN to the exact cell identity."
  }
  assert {
    condition     = output.pool_resource_name == google_privateca_ca_pool.this.id && output.issuer_service_account_email == google_service_account.issuer.email
    error_message = "Outputs must expose only the custody resource identifiers."
  }
}

run "explicit_operator" {
  command = plan
  variables { operator_members = ["group:operators@example.test"] }
  assert {
    condition     = google_service_account_iam_binding.operators[0].members == toset(["group:operators@example.test"]) && google_service_account_iam_binding.operators[0].service_account_id == google_service_account.issuer.name
    error_message = "Operator impersonation must be scoped to the issuer account."
  }
}

run "reject_runtime_impersonation" {
  command = plan
  variables { operator_members = ["serviceAccount:runtime@example-project.iam.gserviceaccount.com"] }
  expect_failures = [var.operator_members]
}

run "reject_short_ca" {
  command = plan
  variables { ca_lifetime_seconds = 86400 }
  expect_failures = [google_privateca_certificate_authority.root]
}
