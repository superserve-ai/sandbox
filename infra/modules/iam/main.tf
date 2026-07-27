terraform {
  required_version = ">= 1.5.0"
}

resource "google_service_account" "service_accounts" {
  for_each = var.service_accounts

  project      = var.project_id
  account_id   = each.value.account_id
  display_name = each.value.display_name
  description  = each.value.description
}

resource "google_project_iam_member" "project_bindings" {
  for_each = var.project_bindings

  project = var.project_id
  role    = each.value.role
  member  = one(each.value.members)

  depends_on = [google_service_account.service_accounts]
}

resource "google_service_account_iam_member" "service_bindings" {
  for_each = var.service_bindings

  service_account_id = each.value.service_account
  role               = each.value.role
  member             = one(each.value.members)
}

locals {
  iam_contract = {
    project_id        = var.project_id
    environment       = var.environment
    service_accounts  = { for key, sa in google_service_account.service_accounts : key => sa.email }
    project_bindings  = keys(var.project_bindings)
    service_bindings  = keys(var.service_bindings)
    workload_identity = var.workload_identity
    labels            = var.labels
  }
}
