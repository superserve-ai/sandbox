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

variable "host_maintenance_event_alerts" {
  description = "Log-based alerts on GCE host maintenance / restart system events, keyed by logical name."
  type = map(object({
    display_name  = string
    instance_name = string
    instance_id   = string
    documentation = optional(string, null)
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
    metrics, scoped to one cell's vmd host via the host_id metric label.
    host_id is vmd's HOST_ID runtime env, which is its identity in the host
    table — NOT necessarily the instance name, and not the host_id the
    collector stamps on its own host-level series. Pass the value read from
    the host's /etc/sandbox/vmd.env; a guess selects no series and the
    policies stay silent. Null disables the whole set.
  EOT
  type = object({
    host_id        = string
    display_prefix = string
    # Sustained failed upload attempts per hour. The retry backoff caps at
    # 10 minutes, so a single permanently failing generation produces ~6
    # attempts/hour; the default catches one stuck task on any cell while
    # ignoring transient bucket blips that succeed on retry.
    upload_failures_per_hour = optional(number, 4)
    # Age of the oldest queued generation. Sparse-packed overlays upload
    # in seconds under the default bandwidth cap, so queue residence is
    # normally well under a minute even on a busy cell, and a 30 minute
    # old head means the drain is stalled or the backlog is growing.
    oldest_pending_age_seconds = optional(number, 1800)
    # p99 of the synchronous pause-RPC backup hook. The hook is bounded
    # by design to a marker write, an O(dirtied-bytes) staging copy, and
    # a tens-of-KB vmstate hash: tens to low hundreds of ms. A
    # synchronous term that scales with disk size instead of dirtied
    # bytes lands far above that; 2s catches the class while tolerating
    # occasional large staged overlays.
    pause_hook_p99_seconds = optional(number, 2)
    # How long the completion-notification outbox may stay nonzero. The
    # outbox drains on every ack and idle tick (seconds), so an hour of
    # standing entries means completion write-back is stalled.
    outbox_stalled_duration = optional(string, "3600s")
    # Fire when the host reports backup_enabled=0 (BACKUP_BUCKET unset).
    # On in production, where a host without backup accrues unmet
    # durability with no other signal; staging may disable backup
    # deliberately.
    alert_disabled_host = optional(bool, true)
  })
  default = null
}

variable "host_disk_alerts" {
  description = <<-EOT
    Alert policies over root-filesystem utilization exported by the
    host-local OTel collector's hostmetrics receiver, scoped to one
    cell's vmd host via the host_id metric label (stamped from HOST_ID
    in the collector env, which matches the instance name). The metric
    covers the root mountpoint only, so utilization means the OS disk
    rather than the sandbox data arrays. Null disables the set.
  EOT
  type = object({
    host_id        = string
    display_prefix = string
    # Warning threshold as a fraction of capacity. 85% still leaves
    # working headroom for logs, package state, and deploy artifacts,
    # so cleanup can happen deliberately instead of under pressure.
    warning_utilization = optional(number, 0.85)
    # Sustained window for the warning. 30 minutes filters spikes from
    # transient files that free themselves.
    warning_duration = optional(string, "1800s")
    # Paging threshold. At 95% the OS disk is close to exhaustion:
    # writes for logs, journals, and system state start failing shortly
    # after, which takes down the host's control services.
    critical_utilization = optional(number, 0.95)
    # Short window on the paging path; it only debounces single-scrape
    # blips.
    critical_duration = optional(string, "300s")
  })
  default = null
}

variable "launch_path_alerts" {
  description = <<-EOT
    Alert policies over the vmd launch path's Managed Prometheus metrics,
    scoped to one cell's vmd host via the host_id metric label. Covers the
    pruned launcher mount namespace being unavailable and live network
    namespaces accumulating, both of which degrade latency silently.

    host_id is vmd's HOST_ID runtime env (the same label the backup metrics
    carry), NOT the instance name and NOT the collector's own host_id — read
    it from the host's /etc/sandbox/vmd.env. A guess selects no series, and
    a policy watching nothing is indistinguishable from a healthy host.
    Null disables the set.
  EOT
  type = object({
    host_id        = string
    display_prefix = string
    # How long launches may run on the legacy path before paging. Pin
    # rebuilds retry every 5 minutes, so this must exceed one retry cycle
    # or a transient failure that self-heals would page; 15 minutes gives
    # two attempts and still catches a stuck host long before the mount
    # table makes it un-deployable.
    launcher_not_ready_duration = optional(string, "900s")
    # Live network namespaces on the host. Steady state should be running
    # VMs plus the warm pool (low thousands). Deploy duration and ssh
    # session setup both scale with the mount table these produce, so the
    # default sits well above normal operation and well below the range
    # where those operations begin to time out.
    netns_total_threshold = optional(number, 8000)
  })
  default = null
}
