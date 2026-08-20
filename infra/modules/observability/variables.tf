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
    # Sustained window for the backlog-age condition. 15 minutes is enough
    # margin for a cell whose pause arrivals are roughly steady; a cell
    # whose traffic arrives in scheduled batches (a scheduler firing many
    # sandboxes' work at once) can legitimately push the queue past the
    # threshold for longer while it drains a single batch, so that cell's
    # override should exceed the batch's expected drain time.
    oldest_pending_age_duration = optional(string, "900s")
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

variable "backup_coverage_alerts" {
  description = <<-EOT
    Alert policy over the control plane's per-cell backup coverage
    gauge (backup_uncovered_paused_sandboxes): paused, non-destroyed
    sandboxes with no verified backup generation, grouped by region and
    host_id. Unlike backup_alerts, these series are emitted by the
    control plane from database state, not by a vmd host, so they are
    not scoped to one HOST_ID and deliberately do not share
    backup_alerts' host filter.

    The policy defaults to disabled (enabled = false) even when this
    object is set: cells currently carry large known-uncovered backlogs
    (a region-wide backfill that has not yet converged, and migration
    leftovers still pending classification), so an armed policy today
    would fire permanently and teach responders to ignore it. Flip
    enabled to true per environment once its backlog has converged to
    zero. Null omits the policy entirely.
  EOT
  type = object({
    display_prefix = string
    # Arm the policy. Kept separate from the object's presence so the
    # policy can be created disabled, reviewed in the console, and
    # flipped on without a shape change once coverage converges.
    enabled = optional(bool, false)
    # Scope the policies to one cell via the series' region label.
    # Production cells share a monitoring project, so once more than
    # one cell exports the gauge, an unscoped instance would watch (and
    # duplicate alerts for) every cell's series. A list, one condition
    # per entry, because a cell's database can legitimately carry more
    # than one host-region value: the use cell is a host swap whose
    # host rows have already been relabeled across regions once, and a
    # single-region scope would silently miss series still labeled with
    # a retired value. List every region value present in the cell's
    # host table (the host table's region column, not GCP region
    # names; a guess selects no series). Leave null only while a
    # single cell emits the metric. A non-empty list also arms a
    # companion policy over region="unknown" series (paused sandboxes
    # whose host row is gone), which region scoping would otherwise
    # hide.
    regions = optional(list(string))
    # Uncovered paused sandboxes tolerated per series. Zero: any paused
    # sandbox without a verified backup that persists for the window is
    # unmet durability exposure.
    uncovered_threshold = optional(number, 0)
    # Sustained window. A backup trails its pause by queue and upload
    # time, so an hour tolerates normal drain latency (and the sweep
    # re-enqueueing after a restart) while still catching a stalled
    # pipeline within the day.
    uncovered_duration = optional(string, "3600s")
  })
  default = null

  # Region values flow into Monitoring filters, resource addresses, and
  # the user_labels alert_type ("backup_coverage_uncovered_paused_"
  # plus the value, against Monitoring's 63-character lowercase label
  # limit), and the host table's region column constrains none of that:
  # reject here rather than fail mid-apply. "unknown" is reserved for
  # the orphaned-host companion policy, and duplicates would collide as
  # resource keys.
  validation {
    condition = var.backup_coverage_alerts == null ? true : (
      var.backup_coverage_alerts.regions == null ? true : (
        length(var.backup_coverage_alerts.regions) == length(distinct(var.backup_coverage_alerts.regions)) &&
        alltrue([
          for region in var.backup_coverage_alerts.regions :
          can(regex("^[a-z0-9][a-z0-9-]{0,29}$", region)) && region != "unknown"
        ])
      )
    )
    error_message = "backup_coverage_alerts.regions entries must be unique, must not be \"unknown\", and must match ^[a-z0-9][a-z0-9-]{0,29}$ (lowercase alphanumerics and dashes, at most 30 characters)."
  }
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
    #
    # COUPLED to vmd's reclaim band (VMD_PAUSED_NETWORK_NETNS_THRESHOLD /
    # _HYSTERESIS): this must sit ABOVE the reclaim ceiling, so it fires only
    # when the controller engaged and still could not hold the line — the
    # controller losing to inflow, not the normal sawtooth between the band's
    # floor and ceiling. Move this whenever the reclaim ceiling moves, or it
    # silently degrades into either a duplicate of the controller's own
    # trigger or an alert that can never fire.
    netns_total_threshold = optional(number, 8000)
    # Fast path for runaway growth. The 30 minute window above is right for a
    # count drifting just over the ceiling, but too slow when inflow is
    # outrunning the drain: at the growth rates a busy host reaches, half an
    # hour spent confirming 8,000 can end well past 12,000, and the cost of
    # every operation that walks the mount table rises the whole way. This
    # tier trades the long window for a higher bar, so a host climbing fast
    # is caught in minutes while a slow drift still waits out the 30.
    netns_critical_threshold = optional(number, 9000)
    netns_critical_duration  = optional(string, "300s")
    # Sustained window for the namespace threshold. The controller drains a
    # backlog over tens of minutes, so a window shorter than that would page
    # during a recovery that is working.
    netns_total_duration = optional(string, "1800s")
  })
  default = null
}
