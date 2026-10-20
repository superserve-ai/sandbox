terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0, < 9.0"
    }
  }
}

locals {
  metric_scope   = "project_id=\"${var.project_id}\",job=\"sandbox-controlplane\",location=~\"${join("|", sort(distinct([for cell in values(var.cells) : cell.metric_location])))}\""
  error_selector = "billing_operations_total{${local.metric_scope},operation=~\"entitlement_coverage_sample|usage_entitlement_backlog\",result=\"error\"}"
  sampler_checks = merge([
    for name, cell in var.cells : {
      for operation in concat(["usage_entitlement_backlog"], cell.coverage_checks_enabled ? ["entitlement_coverage_sample"] : []) :
      "${name}-${operation}" => {
        cell      = name
        operation = operation
        location  = cell.metric_location
      }
    }
  ]...)
  metric_alerts = merge({
    paid_missing = {
      title    = "Paid contract missing current entitlement"
      query    = "max(billing_event_backlog_capped{${local.metric_scope},state=\"entitlement_paid_missing\"}) > 0"
      duration = "0s"
      severity = "CRITICAL"
      failure  = "missing_entitlement"
      detail   = "The application already waits 15 minutes after eligibility. No additional sustained delay is added. Unknown debt is a subset of this count; this is a recovery candidate, never authorization to issue credit. Counts are capped and replicated: maximum, not sum."
    }
    debt_unknown = {
      title    = "Entitlement eligibility observation unknown"
      query    = "max(billing_event_backlog_capped{${local.metric_scope},state=\"entitlement_debt_unknown\"}) > 0"
      duration = "0s"
      severity = "WARNING"
      failure  = "unknown_eligibility"
      detail   = "Debt evidence is missing or stale. This does not establish customer nonpayment and overlaps the paid-missing recovery candidates. Restore observation before deciding eligibility."
    }
    sampler_errors = {
      title    = "Entitlement monitoring failed"
      query    = "sum(increase(${local.error_selector}[5m])) > 0 or sum(${local.error_selector} unless ${local.error_selector} offset 5m) > 0"
      duration = "0s"
      severity = "CRITICAL"
      failure  = "observation_failure"
      detail   = "At least one coverage or backlog observation failed in five minutes. Counter increases are computed before aggregation so process restarts do not hide errors. A newly observed positive error counter also fires: error series are created lazily and have no preceding zero sample. Error-free observation for a full lookback clears this predicate; it does not prove customer recovery."
    }
    }, {
    for key, check in local.sampler_checks : "silent-${key}" => {
      title    = "Entitlement monitoring stopped / ${check.cell} / ${check.operation}"
      query    = "(sum(increase(billing_operations_total{project_id=\"${var.project_id}\",job=\"sandbox-controlplane\",location=\"${check.location}\",operation=\"${check.operation}\"}[5m])) or vector(0)) == 0"
      duration = "60s"
      severity = "CRITICAL"
      failure  = "missing_telemetry"
      detail   = "No sampler progress in ${check.cell}. A never-seen counter can alert after one minute; the five-minute lookback is not startup grace. Previously observed counters alert after progress ages out of the lookback plus the one-minute hold. Includes absent and frozen counters. Both success and error count as progress; errors have their own policy. Check the process and collector before interpreting backlog counts. Coverage liveness must be disarmed when issuance is intentionally disabled."
    }
  })
  # The API currently uses zerolog ConsoleWriter on stderr. Accept structured
  # entries too so switching to JSON logging does not break recovery paging.
  console_error_pattern = "^[^ ]+ (\\x1b\\[[0-9;]*m)*ERR(\\x1b\\[[0-9;]*m)* "
  recovery_log_filter   = <<-EOT
    resource.type="cloud_run_revision"
    (${join(" OR ", [for cell in values(var.cells) : "(resource.labels.service_name=\"${cell.cloud_run_service}\" AND resource.labels.location=\"${cell.cloud_run_region}\")"])})
    (
      ((severity=ERROR OR jsonPayload.level="error") AND jsonPayload.message="usage entitlement requires operator recovery; inspect pending grants before collecting invoices")
      OR
      (textPayload:"usage entitlement requires operator recovery; inspect pending grants before collecting invoices" AND textPayload=~${jsonencode(local.console_error_pattern)})
    )
  EOT
  triage_labels = merge(var.labels, {
    environment          = var.environment
    managed_by           = "terraform"
    superserve_family    = "billing"
    superserve_component = "api"
  })
}

resource "google_monitoring_alert_policy" "entitlement_metric" {
  for_each = local.metric_alerts

  project               = var.project_id
  display_name          = "Billing / ${each.value.title}"
  combiner              = "OR"
  enabled               = true
  severity              = each.value.severity
  notification_channels = var.notification_channel_ids

  conditions {
    display_name = each.value.title
    condition_prometheus_query_language {
      query                     = each.value.query
      duration                  = each.value.duration
      evaluation_interval       = "60s"
      disable_metric_validation = true
    }
  }
  documentation {
    mime_type = "text/markdown"
    content   = "${each.value.detail}\n\nNormal issuance target: one minute; alert escalation is separate. Missing data is not zero customers or confirmed recovery. Preserve pending grant identity and invoice collection holds.\n\nRunbook: ${var.runbook_url}"
  }
  user_labels = merge(local.triage_labels, {
    superserve_failure_family = each.value.failure
    alert_type                = "entitlement_${each.value.failure}"
    severity                  = lower(each.value.severity)
  })
  lifecycle {
    precondition {
      condition = length(var.notification_channel_ids) > 0 && alltrue([
        for id in var.notification_channel_ids : can(regex("^projects/${var.project_id}/notificationChannels/[0-9]+$", id))
      ])
      error_message = "Billing alerts require existing notification channels in the monitored project."
    }
  }
}

resource "google_monitoring_alert_policy" "entitlement_recovery" {
  project               = var.project_id
  display_name          = "Billing / Entitlement operator recovery required"
  combiner              = "OR"
  enabled               = true
  severity              = "CRITICAL"
  notification_channels = var.notification_channel_ids

  conditions {
    display_name = "Operator recovery required across API cells"
    condition_matched_log {
      filter = local.recovery_log_filter
      # No extracted labels: every contract, replica and cell shares one incident.
    }
  }
  alert_strategy {
    notification_rate_limit {
      period = "300s"
    }
    auto_close = "86400s"
  }
  documentation {
    mime_type = "text/markdown"
    content   = "An entitlement requires manual recovery, including platform failures or approaching expiry. Notify on the first matching ERROR; coalesce subsequent contracts/replicas/cells for at least five minutes. A continuing incident may notify again after five minutes only when another matching event arrives. Logs retain contract details; incident labels deliberately do not. Cloud Monitoring limits log-based policies to 20 notifications/day; inspect all matching logs when handling the incident.\n\nAuto-close after 24 hours without a matching event is notification housekeeping, not proof of recovery. Verify affected entitlement state and preserve collection holds and uncertain-write identity before declaring recovery.\n\nRunbook: ${var.runbook_url}"
  }
  user_labels = merge(local.triage_labels, {
    superserve_failure_family = "manual_recovery"
    alert_type                = "entitlement_manual_recovery"
    severity                  = "critical"
  })
  lifecycle {
    precondition {
      condition = length(var.notification_channel_ids) > 0 && alltrue([
        for id in var.notification_channel_ids : can(regex("^projects/${var.project_id}/notificationChannels/[0-9]+$", id))
      ])
      error_message = "Billing alerts require existing notification channels in the monitored project."
    }
  }
}

output "metric_queries" {
  description = "Rendered predicates for non-notifying evaluation and behavior tests."
  value       = { for key, alert in local.metric_alerts : key => alert.query }
}
