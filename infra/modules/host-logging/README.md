# Managed host logs

This module installs a dedicated OpenTelemetry Collector Contrib logs process
through Terraform and OS Config. It is separate from the existing metrics
collector, including its binary, configuration, systemd service, and storage.
VMD and legacy/generated proxy messages are filtered using parsed application
severity; selected host services and kernel events use journal priority.
Unknown fields are discarded. Malformed application messages export only
trusted metadata and a parse-failure marker. Host diagnostics currently export
bounded event classifications rather than arbitrary command/tenant text.

**Delivery limitation:** Cloud export is best effort across a collector crash
under queue pressure. The released journald receiver persists its read cursor
before durable downstream acceptance; it can skip records on restart. An OTel
process crash does not remove those records from the local journal. Operators
can retrieve them while retained, but automatic no-gap recovery is deferred to
a separate change. Journal rotation and host/disk loss can make recovery
impossible. Do not describe this configuration as crash-safe or lossless.

## Release and compatibility

The logs process pins Contrib **0.156.0**, Linux amd64, independently of the
existing metrics release. Its archive SHA-256 is
`ee70d7b1221be8a9cc4700f48bf985c04b1ab8aaeef24409fe79623849e2f9f2`.
The fixture verifies both the configured digest and the
[release checksum manifest](https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.156.0/opentelemetry-collector-releases_otelcol-contrib_checksums.txt).

The [journald receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/v0.156.0/receiver/journaldreceiver)
is alpha and requires a compatible local `journalctl`. The Linux fixture uses
Ubuntu 24.04 journal tooling and creates genuine journal files; production
compatibility must also be verified against each enrolled image. The
[file-storage extension](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/v0.156.0/extension/storage/filestorage)
is beta. Component maturity and a successful configuration validation are not
delivery guarantees.

The exporter uses Google's [native OTLP logs endpoint](https://docs.cloud.google.com/stackdriver/docs/reference/telemetry/v1.logs).
Terraform enables the Telemetry and OS Config APIs. Staging orders the logging
module after both services; production enables OS Config in the shared
us-central1 bootstrap that both regional infrastructure jobs require. The runtime identity needs
`roles/logging.logWriter`, `roles/serviceusage.serviceUsageConsumer`, and read
access to the dedicated artifact bucket. Production
Telemetry remains owned by west and must exist before east activation. Direct
regional applies must establish these project prerequisites first; east does
not duplicate project-service ownership in its regional state.

Metrics priority is checked against the running process's OOM adjustment. When
an active metrics collector has drifted, reconciliation restarts it under the
managed priority settings and verifies the result; inactive metrics stay stopped.
Rollback restores the prior unit configuration and restarts metrics when needed,
repairing preexisting live-process drift to that configuration. Metrics service
start/stop timeouts apply to the restart; reconciliation waits for the systemd
job to finish and checks the actual score after startup.

## State and resource bounds

| Resource | Initial setting | Meaning |
| --- | --- | --- |
| Persistent journal | 4 GiB; 10 GiB keep-free | Shared host history, subject to journald rotation |
| Export queue database | 2 GiB maximum | Physical file-storage cap; compaction disabled |
| Logical queue | 512 MiB | Byte sizing leaves room for storage overhead |
| Cursor database | 16 MiB maximum | Separate state; a read position is not a delivery acknowledgment |
| Logs process | 512 MiB; 25% CPU; 8 MiB/s I/O | Memory limiter and service thresholds scale with the configured budget |
| Metrics process | 256 MiB; lower CPU/I/O weight | Prefer losing metrics under pressure over starving logs or VMD |
| Installation staging | 2 GiB preflight reserve | Archive, extracted binary, backup, and atomic install copy; interrupted attempts cleaned under lock |
| Collector self-logs | 100 records per 30 seconds | Stored in the shared bounded journal |
| Cloud retention | Existing 30 days | This module does not silently change bucket retention |

First installation starts at the beginning of retained journal history.
Subsequent starts use the persisted cursor. Do not delete state to force a
replay: that can duplicate the entire retained journal. An expired cursor,
rotated source history, inaccessible host, or a corrupted database requires
explicit diagnosis; the local journal is not an unlimited archive. Loss of
history outside retention cannot be repaired by increasing the queue later.

A 72-hour outage target is a sizing objective, not a measured guarantee. Before
activation, record retained journal bytes per day, selected INFO+ serialized
bytes per day, actual queue database growth including overhead, and catch-up
throughput under the configured CPU/I/O limits. Include existing syslog,
legacy agent buffers, release staging files, and other disk consumers in the
10 GiB free-space check. The queue must fit three days of measured output plus
headroom; the journal must retain that interval at the measured *whole-host*
input rate. A logical queue limit alone does not prove either condition.

## Reconciliation, rollout, and rollback

Candidate files and the authenticated archive are validated before activation.
Reconciliation compares content and permissions, replaces active files
atomically, and restores prior files after activation failure. Reapplying an
unchanged configuration does not restart the logs process. Cursor and queue
state are retained across configuration changes and rollback. Release upgrades
must first demonstrate that both the new release and rollback release can
read the preserved state; never reinterpret or erase an incompatible database.

East defaults to `legacy_transition = "preserve"`: its existing Ops Agent keeps
running and the new logs writer stays disabled. The existing installation-only
OS policy and enrollment label remain unchanged. Terraform manages a separate
migration target and helper; there are no manual labels or cloud CLI mutations.
Before activating a host, audit the installation policy and the exact Ops Agent
user configuration. Supply that configuration as `baseline_user_config`, the
current provider instance IDs, and an explicit overlap deadline (at most 24 hours).

The migration phases are `preserve`, `verify`, `overlap`, `drain`, `retire`, and
`rollback`. Verification/overlap retain the old writer; a local timer and service
start guard stop OTel when the deadline expires. Drain requires measured cloud
receipt and duplicate/gap counts. Retirement requires receipt and empty-buffer
evidence for every enrolled instance plus a local overlap snapshot for that
same instance, policy, and baseline. A bounded check requires the exact newly
injected heartbeat receipt, an empty queue with no in-flight requests, no new
export failures, and an unchanged collector process. Its metrics endpoint
listens only on loopback. Retirement disables all Ops Agent logging pipelines
while preserving metrics configuration and receiver definitions. Applying the
Ops Agent configuration briefly restarts that agent; the independent application
metrics collector is not changed by migration. Rollback restores the exact
audited baseline before stopping OTel, and retains the OTel cursor and queue.

Retirement additionally restarts the managed heartbeat and obtains its trusted
journal invocation ID, then requires that exact ID and current host incarnation
in Cloud Logging before disabling legacy logging. Older queue completions cannot
satisfy this check. Terraform creates one heartbeat-only view per migrating
assignment in the project's global `_Default` bucket and grants runtime accounts
read access on that view only. The bounded, one-minute query window is used only
at retirement; inaccessible or delayed receipts preserve the legacy writer.
Deployments routing these logs elsewhere must configure an equivalent restricted
view and matching target before attempting retirement. View filters and grants
are bound to the migration evidence digest.

A replacement must go through `preserve` then `overlap` with fresh receipt and
drain evidence before `retire`. If its user configuration is absent, explicitly
include its current provider ID in `initialize_instance_ids` to authorize
baseline initialization during overlap or rollback. Existing mismatched files
fail closed. A new host cannot inherit a predecessor's retirement evidence.

Production workflows require an HTTPS JSON evidence receipt when a plan changes
active logging. Its top-level fields are `environment: "staging"`,
`accepted: true`, `configuration_revision`, and `deployment_content_digest`.
Compute the revision and digest with `scripts/host_logging_plan_requires_evidence.py`
using `--revision` and `--digest` on the saved JSON plan. The digest binds rendered
artifacts, policy, IAM, alerts, notification routing, and runbook content.
Cross-project channel IDs may differ only through an explicitly reviewed
`notification_channel_map` from production channel names to staging channel names.

For a legacy transition, the receipt also contains `migration`: `phase`,
`legacy_policy_name`, `instance_ids`, `verified_instance_ids`,
`drained_instance_ids`, `deployment_content_digest` (from `--migration-digest`),
`otel_deployment_content_digest` (from `--digest`), `metrics_continuity: true`,
`rollback_verified: true`, and an `observed_at` UTC timestamp from the last hour.
Drain and retirement also require `overlap_gap_count: 0` and a measured
`duplicate_count`. Retirement requires `pending_records: 0` and
`oldest_pending_age_seconds: 0`. These fields attest actual observations; they
must not be filled from local fixture results. Preserve does not require an
activation receipt; rollback still requires fresh migration evidence.

Terraform inventories drive independent per-host heartbeat alerts. A missing
or never-seen host triggers absence detection even if application metrics work.
Provider instance identity separates VM replacements; an explicitly supplied
incarnation further scopes receipt. An in-place reinstall keeps the same
provider ID, so a recent predecessor heartbeat may postpone detection by at
most the five-minute freshness window plus the configured alert duration.
Optional authoritative incarnation inventory enables stricter fencing without
changing host identity provisioning. Source timestamps prevent replay from
extending that freshness window. Cloud-side freshness queries use the original timestamps of minute heartbeats,
so queue delay cannot make stale history appear current and metric volume scales
with hosts rather than application log volume. Export
failure events complement absence detection but cannot be delivered during a
complete export outage.

Run actual collector privacy/severity/timestamp fixtures, accepted-queue restart
recovery, reconciler convergence/failure tests, and affected Terraform tests
before staging. Production additionally requires actual Cloud Logging receipt,
72-hour sizing and bounded catch-up evidence, constrained-resource lifecycle
latency, alert delivery, replacement-host enrollment, and tested legacy cutover
and rollback. Local fixture results do not substitute for those observations.

The manual host-provisioning guard accepts logging alert identity substitutions
only when the complete planned query/filter is known and otherwise unchanged.
Terraform normally makes the entire string unknown when a replacement or absent
VM receives a new instance ID, so those provisioning plans are blocked. An old
instance ID and a configuration reference do not prove the new query is safe.
Do not bypass the guard: a separately reviewed logging rollout with the required
staging evidence is needed. Automatic provisioning with unresolved logging alert
identities requires additional proof of the unchanged query/filter template.

The same rule applies to the east migration JSON artifact, including in
`preserve` before logging alerts are active. An unresolved artifact is rejected:
a separately validated migration input does not prove the file contains that
input. Known content may substitute only the selected instance ID, and the
bucket, object path, and other configurable fields must remain unchanged.
East replacement plans with unresolved migration content therefore require a
separately reviewed logging rollout with staging evidence; they cannot proceed
through the identity-only provisioning exception.
