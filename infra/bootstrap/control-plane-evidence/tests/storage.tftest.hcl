mock_provider "google" {}

variables {
  project_id                 = "example-staging"
  deployment_service_account = "deployer@example-staging.iam.gserviceaccount.com"
  policy_reader_service_accounts = [
    "deployer@example-staging.iam.gserviceaccount.com",
    "deployer@example-production.iam.gserviceaccount.com",
  ]
}

run "private_retained_staging_evidence" {
  command = plan
  assert {
    condition = (
      google_storage_bucket.evidence.name == "example-staging-control-plane-evidence" &&
      google_storage_bucket.evidence.uniform_bucket_level_access &&
      google_storage_bucket.evidence.public_access_prevention == "enforced" &&
      !google_storage_bucket.evidence.force_destroy &&
      tonumber(one(google_storage_bucket.evidence.retention_policy).retention_period) == 90 * 86400 &&
      one(one(google_storage_bucket.evidence.lifecycle_rule).condition).age == 90
    )
    error_message = "Evidence must be private and retained for 90 days before lifecycle deletion."
  }
  assert {
    condition = (
      toset(keys(google_storage_bucket_iam_member.upload)) == toset(["roles/storage.objectCreator", "roles/storage.objectViewer"]) &&
      google_storage_bucket_iam_member.upload["roles/storage.objectCreator"].member == "serviceAccount:deployer@example-staging.iam.gserviceaccount.com"
    )
    error_message = "The deployment account may create evidence objects with destination discovery but without delete grants."
  }
  assert {
    condition = (
      toset(keys(google_project_service.verification)) == toset(["cloudasset.googleapis.com", "policytroubleshooter.googleapis.com"]) &&
      alltrue([for api in google_project_service.verification : !api.disable_on_destroy]) &&
      toset(keys(google_project_iam_member.analysis)) == toset(["roles/cloudasset.viewer", "roles/iam.roleViewer", "roles/serviceusage.serviceUsageConsumer"]) &&
      alltrue([for grant in google_project_iam_member.analysis : grant.member == "serviceAccount:deployer@example-staging.iam.gserviceaccount.com"])
    )
    error_message = "Both verification APIs and the deployment account's analysis permissions must be bootstrapped without disabling APIs on destroy."
  }
  assert {
    condition = (
      toset(keys(google_project_iam_member.policy_reader)) == toset([
        "deployer@example-staging.iam.gserviceaccount.com/roles/iam.securityReviewer",
        "deployer@example-production.iam.gserviceaccount.com/roles/iam.securityReviewer",
      ]) &&
      alltrue([for grant in google_project_iam_member.policy_reader : grant.role == "roles/iam.securityReviewer"]) &&
      google_project_iam_member.policy_reader["deployer@example-production.iam.gserviceaccount.com/roles/iam.securityReviewer"].project == "example-staging"
    )
    error_message = "Cross-project readers must retain their Security Reviewer addresses and exclude organization-only Deny Reviewer bindings."
  }
  assert {
    condition     = length(google_kms_crypto_key_iam_member.verification_metadata) == 0
    error_message = "Staging must not receive production KMS permissions."
  }
}

run "shared_production_evidence" {
  command = plan
  variables {
    project_id                 = "example-production"
    deployment_service_account = "deployer@example-production.iam.gserviceaccount.com"
    verification_kms_key       = "projects/example-production/locations/example-region/keyRings/example/cryptoKeys/credentials"
  }
  assert {
    condition = (
      google_storage_bucket.evidence.name == "example-production-control-plane-evidence" &&
      google_storage_bucket_iam_member.upload["roles/storage.objectCreator"].member == "serviceAccount:deployer@example-production.iam.gserviceaccount.com"
    )
    error_message = "Production regions must use the production project store and uploader."
  }
  assert {
    condition = (
      length(google_kms_crypto_key_iam_member.verification_metadata) == 1 &&
      one(values(google_kms_crypto_key_iam_member.verification_metadata)).role == "roles/cloudkms.viewer" &&
      one(values(google_kms_crypto_key_iam_member.verification_metadata)).crypto_key_id == var.verification_kms_key &&
      one(values(google_kms_crypto_key_iam_member.verification_metadata)).member == "serviceAccount:deployer@example-production.iam.gserviceaccount.com"
    )
    error_message = "Production preflight needs key-scoped metadata read before attempting to describe the primary version."
  }
}
