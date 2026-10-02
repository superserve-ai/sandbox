# Project IAM is already managed by CD. Install this conditional grant in the
# shared bootstrap before either regional root manages runtime key grants.
resource "google_project_iam_member" "cd_credentials_key_iam" {
  project = local.project_id
  role    = "roles/iam.securityAdmin"
  member  = "serviceAccount:superserve-github-actions@${local.project_id}.iam.gserviceaccount.com"

  condition {
    title       = "credentials-key-iam-only"
    description = "Manage IAM only on the application credentials key."
    expression  = "resource.type == 'cloudkms.googleapis.com/CryptoKey' && resource.name == 'projects/${local.project_id}/locations/us-central1/keyRings/superserve/cryptoKeys/credentials-kek'"
  }
}
