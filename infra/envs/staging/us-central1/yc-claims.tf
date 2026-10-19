variable "yc_claims_enabled" {
  type        = bool
  default     = false
  description = "Enable YC claim credentials only after shared migrations, mail and Console are ready. Requires promotion_evidence_enabled."
}
variable "yc_claim_api_access_enabled" {
  type        = bool
  default     = false
  nullable    = false
  description = "Grant staging runtime access to capture and Console credentials before enabling YC claims or mail."
}
variable "yc_claim_console_url" {
  type        = string
  default     = ""
  description = "HTTPS Console origin for bound YC confirmation links."
}
variable "yc_claim_email_from" {
  type        = string
  default     = ""
  description = "Verified mail sender for YC confirmation messages."
}
variable "yc_existing_exception_user_id" {
  type        = string
  default     = ""
  description = "Exact approved existing-account exception; empty disables migration."
}
variable "yc_existing_exception_team_id" {
  type        = string
  default     = ""
  description = "Exact approved team for the existing-account exception."
}
resource "google_secret_manager_secret" "yc_claim" {
  for_each  = toset(["capture-token", "console-token", "email-api-key"])
  project   = local.project_id
  secret_id = "yc-claim-${each.key}-${local.resource_suffix}"
  replication {
    auto {}
  }
  labels = local.common_labels
  lifecycle {
    precondition {
      condition     = !var.yc_claims_enabled || (var.promotion_evidence_enabled && startswith(var.yc_claim_console_url, "https://") && var.yc_claim_email_from != "")
      error_message = "YC claims require shared Auth authority, HTTPS Console origin and a verified sender."
    }
  }
}
locals {
  yc_claim_secrets = var.yc_claims_enabled ? {
    YC_CLAIM_CAPTURE_TOKEN = { secret = google_secret_manager_secret.yc_claim["capture-token"].secret_id }
    YC_CLAIM_CONSOLE_TOKEN = { secret = google_secret_manager_secret.yc_claim["console-token"].secret_id }
    YC_EMAIL_API_KEY       = { secret = google_secret_manager_secret.yc_claim["email-api-key"].secret_id }
  } : {}
}
