# Project-wide billing policies have one state owner, independent of API region.
module "billing_alerts" {
  source = "../../../modules/billing-alerts"

  project_id  = local.project_id
  environment = local.environment
  labels      = local.common_labels
  # Preserve the existing billing route; the general infrastructure route differs.
  notification_channel_ids = ["projects/${local.project_id}/notificationChannels/17044408421759047225"]
  cells = {
    east = {
      metric_location   = "us-east4-c"
      cloud_run_service = "superserve-api-use4"
      cloud_run_region  = "us-east4"
      # Deploy with the East activation sequence, before enabled workers start.
      coverage_checks_enabled = true
    }
    west = {
      metric_location         = "us-west2-a"
      cloud_run_service       = "superserve-api-usw2"
      cloud_run_region        = "us-west2"
      coverage_checks_enabled = false
    }
  }
}

# Adopt the existing coverage policy instead of creating duplicate pages.
import {
  to = module.billing_alerts.google_monitoring_alert_policy.entitlement_metric["paid_missing"]
  id = "projects/rayai-prod/alertPolicies/7844139494762088007"
}

# Preserve the existing billing safeguards while adopting their resource IDs.
locals {
  preserved_billing_alerts = {
    overdue = {
      id              = "13770534520076996403"
      title           = "Pro monthly allowance overdue"
      condition_title = "Due allowance age"
      metric          = "billing_event_oldest_age_seconds/gauge"
      selector        = " AND metric.labels.state=\"entitlement_due\""
      threshold       = 1800
      duration        = "300s"
      alignment       = "300s"
      aligner         = "ALIGN_MAX"
      reducer         = "REDUCE_MAX"
    }
    recovery_choices = {
      id              = "4218501655425048810"
      title           = "Overdue Pro recovery choices"
      condition_title = "Recovery choices overdue"
      metric          = "billing_pro_recovery_overdue/gauge"
      selector        = ""
      threshold       = 0
      duration        = "900s"
      alignment       = "300s"
      aligner         = "ALIGN_MAX"
      reducer         = "REDUCE_MAX"
    }
    activation = {
      id              = "5038607942292649071"
      title           = "Paid Pro purchases awaiting activation"
      condition_title = "Paid purchase not activated"
      metric          = "billing_pro_paid_activation_pending/gauge"
      selector        = ""
      threshold       = 0
      duration        = "600s"
      alignment       = "300s"
      aligner         = "ALIGN_MAX"
      reducer         = "REDUCE_MAX"
    }
    reconciliation = {
      id              = "1974495689613576722"
      title           = "Billing entitlement reconciliation failures"
      condition_title = "Entitlement reconciliation failed"
      metric          = "billing_work_items_total/counter"
      selector        = " AND metric.labels.operation=\"usage_entitlement\" AND metric.labels.result=\"error\""
      threshold       = 5
      duration        = "0s"
      alignment       = "900s"
      aligner         = "ALIGN_DELTA"
      reducer         = "REDUCE_SUM"
    }
  }
}

resource "google_monitoring_alert_policy" "billing_preserved" {
  for_each = local.preserved_billing_alerts

  project               = local.project_id
  display_name          = "Billing / ${each.value.title}"
  combiner              = "OR"
  enabled               = true
  notification_channels = ["projects/${local.project_id}/notificationChannels/17044408421759047225"]

  conditions {
    display_name = each.value.condition_title
    condition_threshold {
      filter          = "metric.type=\"prometheus.googleapis.com/${each.value.metric}\" AND resource.type=\"prometheus_target\"${each.value.selector}"
      comparison      = "COMPARISON_GT"
      threshold_value = each.value.threshold
      duration        = each.value.duration
      trigger {
        count = 1
      }
      aggregations {
        alignment_period     = each.value.alignment
        per_series_aligner   = each.value.aligner
        cross_series_reducer = each.value.reducer
      }
    }
  }
  documentation {
    mime_type = "text/markdown"
    content   = "${each.value.title}. Existing predicate, timing and routing are preserved during Terraform adoption. Inspect billing work and provider evidence; preserve grant identity and invoice collection holds.\n\nRunbook: https://github.com/superserve-ai/sandbox/blob/main/docs/pro-billing.md#entitlement-alert-response"
  }
  user_labels = merge(local.common_labels, {
    superserve_family         = "billing"
    superserve_component      = "api"
    superserve_failure_family = "billing_backlog"
    alert_type                = "billing_${each.key}"
    managed_by                = "terraform"
  })
}

import {
  for_each = local.preserved_billing_alerts
  to       = google_monitoring_alert_policy.billing_preserved[each.key]
  id       = "projects/rayai-prod/alertPolicies/${each.value.id}"
}
