terraform {
  required_version = ">= 1.5.0"
}

locals {
  observability_contract = {
    project_id         = var.project_id
    environment        = var.environment
    notification_email = var.notification_email
    log_buckets        = var.log_buckets
    uptime_checks      = var.uptime_checks
    alert_policies     = var.alert_policies
    dashboards         = var.dashboards
    labels             = var.labels
  }
}
