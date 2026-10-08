locals {
  legacy_baseline = try(var.legacy_migration.baseline_user_config, null)
  legacy_config   = yamldecode(local.legacy_baseline == null || local.legacy_baseline == "" ? "{}" : local.legacy_baseline)
  legacy_retired = merge(local.legacy_config, {
    logging = merge(try(local.legacy_config.logging, {}), {
      service = merge(try(local.legacy_config.logging.service, {}), {
        pipelines = {
          for name in setunion(toset(keys(try(local.legacy_config.logging.service.pipelines, {}))), toset(["default_pipeline"])) : name => { receivers = [] }
        }
      })
    })
  })
  legacy_target = {
    heartbeat_receipt_view  = "projects/${var.project_id}/locations/global/buckets/_Default/views/${var.assignment_name}-heartbeats"
    legacy_policy_name      = var.legacy_policy_name
    phase                   = var.legacy_transition
    baseline                = local.legacy_baseline
    retired                 = jsonencode(local.legacy_retired)
    deadline                = try(var.legacy_migration.overlap_deadline, null)
    instance_ids            = sort([for host in values(var.enrolled_hosts) : host.instance_id])
    initialize_instance_ids = sort(tolist(try(var.legacy_migration.initialize_instance_ids, toset([]))))
    verified_instance_ids   = sort(tolist(try(var.legacy_migration.verified_instance_ids, toset([]))))
    drained_instance_ids    = sort(tolist(try(var.legacy_migration.drained_instance_ids, toset([]))))
  }
}
resource "terraform_data" "legacy_migration" {
  count = var.legacy_policy_name == null ? 0 : 1
  input = local.legacy_target
  lifecycle {
    precondition {
      condition     = var.legacy_transition == "preserve" || var.legacy_migration != null
      error_message = "Migrating a legacy writer requires its exact audited user configuration."
    }
    precondition {
      condition     = var.legacy_transition != "retire" || (length(setsubtract(toset(local.legacy_target.instance_ids), toset(local.legacy_target.verified_instance_ids))) == 0 && length(setsubtract(toset(local.legacy_target.instance_ids), toset(local.legacy_target.drained_instance_ids))) == 0)
      error_message = "Retirement requires cloud receipt and drain evidence for every enrolled instance."
    }
  }
}
resource "google_storage_bucket_object" "legacy_migration_script" {
  count   = var.legacy_policy_name == null ? 0 : 1
  bucket  = google_storage_bucket.host_logging_artifacts.name
  name    = "${var.assignment_name}/${var.assignment_revision}/legacy-migration.py"
  content = file("${path.module}/../../../scripts/host_logging_legacy_migration.py")
}
resource "google_storage_bucket_object" "legacy_migration_target" {
  count      = var.legacy_policy_name == null ? 0 : 1
  bucket     = google_storage_bucket.host_logging_artifacts.name
  name       = "${var.assignment_name}/${var.assignment_revision}/legacy-migration.json"
  content    = jsonencode(local.legacy_target)
  depends_on = [terraform_data.legacy_migration]
}

# One view per migrating assignment, not per sandbox or host. Only trusted
# heartbeat metadata is readable; application logs are outside this view.
resource "google_logging_log_view" "heartbeat_receipts" {
  count       = var.legacy_policy_name == null ? 0 : 1
  parent      = "projects/${var.project_id}"
  location    = "global"
  bucket      = "_Default"
  name        = "${var.assignment_name}-heartbeats"
  description = "Host logging cutover heartbeat receipts"
  filter      = "log_id(\"superserve_host_logs\") AND resource.type=\"gce_instance\" AND labels.journal_unit=\"superserve-host-logging-heartbeat.service\" AND labels.host_logging_heartbeat=\"true\" AND labels.environment=${jsonencode(var.environment)} AND labels.region=${jsonencode(var.region)}"
}

# Test the conditional grant on the real view after creation, so fresh projects
# and partial applies both wait for IAM propagation before setting its policy.
resource "terraform_data" "heartbeat_view_iam_ready" {
  count            = var.legacy_policy_name == null ? 0 : 1
  triggers_replace = [google_logging_log_view.heartbeat_receipts[0].id, filesha256("${path.module}/prerequisites.py")]
  provisioner "local-exec" {
    command = "python3 \"${path.module}/prerequisites.py\""
    environment = {
      HOST_LOGGING_PREREQUISITE = jsonencode({
        phase = "view-iam"
        view  = google_logging_log_view.heartbeat_receipts[0].id
      })
    }
  }
}

resource "google_logging_log_view_iam_member" "heartbeat_reader" {
  for_each   = var.legacy_policy_name == null ? toset([]) : toset([for host in values(var.enrolled_hosts) : host.service_account_email])
  parent     = google_logging_log_view.heartbeat_receipts[0].parent
  location   = google_logging_log_view.heartbeat_receipts[0].location
  bucket     = google_logging_log_view.heartbeat_receipts[0].bucket
  name       = google_logging_log_view.heartbeat_receipts[0].name
  depends_on = [terraform_data.heartbeat_view_iam_ready]
  role       = "roles/logging.viewAccessor"
  member     = "serviceAccount:${each.value}"
}
