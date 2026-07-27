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
  member  = each.value.members[0]

  depends_on = [google_service_account.service_accounts]
}

resource "google_project_iam_member" "project_binding_additional_members" {
  for_each = merge({}, [
    for binding_key, binding in var.project_bindings : {
      for member in slice(binding.members, 1, length(binding.members)) :
      "${binding_key}:${member}" => {
        role   = binding.role
        member = member
      }
    }
  ]...)

  project = var.project_id
  role    = each.value.role
  member  = each.value.member

  depends_on = [google_service_account.service_accounts]
}

resource "google_service_account_iam_member" "service_bindings" {
  for_each = var.service_bindings

  service_account_id = each.value.service_account
  role               = each.value.role
  member             = each.value.members[0]

  depends_on = [google_service_account.service_accounts]
}

resource "google_service_account_iam_member" "service_binding_additional_members" {
  for_each = merge({}, [
    for binding_key, binding in var.service_bindings : {
      for member in slice(binding.members, 1, length(binding.members)) :
      "${binding_key}:${member}" => {
        service_account = binding.service_account
        role            = binding.role
        member          = member
      }
    }
  ]...)

  service_account_id = each.value.service_account
  role               = each.value.role
  member             = each.value.member

  depends_on = [google_service_account.service_accounts]
}

resource "google_service_account_iam_member" "workload_identity" {
  for_each = var.workload_identity

  service_account_id = each.value.service_account
  role               = "roles/iam.workloadIdentityUser"
  member             = each.value.principal

  depends_on = [google_service_account.service_accounts]
}

locals {
  iam_contract = {
    project_id        = var.project_id
    environment       = var.environment
    service_accounts  = { for key, sa in google_service_account.service_accounts : key => sa.email }
    project_bindings  = keys(var.project_bindings)
    service_bindings  = keys(var.service_bindings)
    workload_identity = keys(var.workload_identity)
    labels            = var.labels
  }
}
