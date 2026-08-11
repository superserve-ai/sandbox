variable "project_id" {
  description = "GCP project ID."
  type        = string
}

variable "environment" {
  description = "Environment name."
  type        = string
}

variable "notification_email" {
  description = "Optional alerting email target."
  type        = string
  default     = null
}

variable "notification_channel_ids" {
  description = "Existing Cloud Monitoring notification channel resource names. Channel credentials are owned by Monitoring and are never stored here."
  type        = list(string)
  default     = []
}

variable "compute_instance_cpu_alerts" {
  description = "CPU saturation alerts keyed by a stable logical name."
  type = map(object({
    display_name        = string
    instance_name       = string
    instance_id         = string
    threshold           = optional(number, 0.8)
    evaluation_duration = optional(string, "900s")
    documentation       = optional(string, null)
  }))
  default = {}
}

variable "log_buckets" {
  description = "Logging bucket definitions keyed by logical name."
  type = map(object({
    bucket_id      = string
    location       = string
    retention_days = number
    description    = optional(string, null)
  }))
  default = {}
}

variable "uptime_checks" {
  description = "Uptime checks keyed by logical name."
  type = map(object({
    display_name = string
    host         = string
    path         = optional(string, "/")
    port         = optional(number, 443)
    use_ssl      = optional(bool, true)
  }))
  default = {}
}

variable "alert_policies" {
  description = "Alert policies keyed by logical name."
  type = map(object({
    display_name  = string
    combiner      = optional(string, "OR")
    documentation = optional(string, null)
  }))
  default = {}
}

variable "dashboards" {
  description = "Dashboard definitions keyed by logical name."
  type = map(object({
    display_name = string
    definition   = string
  }))
  default = {}
}

variable "labels" {
  description = "Labels to apply to supported resources."
  type        = map(string)
  default     = {}
}

variable "backup_alerts" {
  description = <<-EOT
    Alert policies over the vmd backup pipeline's Managed Prometheus
    metrics (exported by the host-local OTel collector), scoped to one
    cell's vmd host via the host_id metric label. host_id follows the
    sandbox host's HOST_ID runtime env, which matches the instance name.
    Null disables the whole set.
  EOT
  type = object({
    host_id        = string
    display_prefix = string
    # Sustained failed upload attempts per hour. The retry backoff caps at
    # 10 minutes, so a single permanently failing generation produces ~6
    # attempts/hour; the default catches one stuck task on any cell while
    # ignoring transient bucket blips that succeed on retry.
    upload_failures_per_hour = optional(number, 4)
    # Age of the oldest queued generation. Overlays are tens of MB packed
    # and upload in seconds under the default 100 Mbit/s cap; even the
    # west cell's ~1000 pauses/day is one pause per ~90s, so queue
    # residence is normally under a minute and a 30 minute old head means
    # the drain is stalled or the backlog is growing.
    oldest_pending_age_seconds = optional(number, 1800)
    # p99 of the synchronous pause-RPC backup hook. The hook is bounded
    # by design to a marker write, an O(dirtied-bytes) staging copy, and
    # a tens-of-KB vmstate hash: tens to low hundreds of ms. The hashing
    # regression this alert exists for added ~5s; 2s catches that class
    # while tolerating occasional large staged overlays.
    pause_hook_p99_seconds = optional(number, 2)
    # How long the completion-notification outbox may stay nonzero. The
    # outbox drains on every ack and idle tick (seconds), so an hour of
    # standing entries means completion write-back is stalled.
    outbox_stalled_duration = optional(string, "3600s")
    # Fire when the host reports backup_enabled=0 (BACKUP_BUCKET unset).
    # On in production, where a silently disabled host once ran for a
    # day; staging may disable backup deliberately.
    alert_disabled_host = optional(bool, true)
  })
  default = null
}
