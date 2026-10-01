# Managed host logging

This module adopts one zonal OS Config policy assignment per environment and
reconciles the Google Ops Agent on existing and replacement serving hosts.
Terraform owns the assignment, staged package/file/service reconciliation, runtime logging
grant, private versioned configuration artifacts, journald retention, and
rollback revision.

The supported `systemd_journald` receiver is paired with a processor allowlist
(the receiver itself has no unit-filter option) for VMD/proxy, secrets-proxy,
systemd-manager and host/kernel
records. Zerolog `level` is mapped to Cloud Logging severity before
DEBUG/TRACE exclusion. Application parse failures keep trusted journal
metadata and a static `labels.parse_failure` marker derived from the parser's
retained `MESSAGE` field, but export trusted metadata only; the raw record remains locally
available within journal retention and is never uploaded. Parsed JSON is reduced to the explicit
diagnostic/correlation allowlist (`request_id`, `sandbox_id`, proxy
generation/revision, service, component, event, error code, and status); the
remaining payload, including secrets-proxy/systemd `MESSAGE`, is removed
before export. The default syslog-file
pipeline is deliberately absent so each journal record has one steady-state
collection path. Platform identity is rendered from the installed provider
identity at reconciliation time; Terraform descriptors remain rollout/IAM
inputs, and application fields remain subordinate. Journal unit/transport
provenance is copied before JSON parsing so application payloads cannot replace
the source identity used for filtering.

The initial journal budget is 4 GiB with a 10 GiB free-space reserve. The
Ops Agent 2.71.0 uses the documented built-in disk-buffer protection introduced
in 2.28. The selected release documents that its buffer amount is
platform-specific and does not expose a supported numeric configuration knob;
`agent_buffer_bytes` is therefore a conservative accounting/enforcement
threshold and not a claim about the agent's internal cap. Staging must record
the generated configuration and observed aggregate buffer growth for this
release before production activation. If the observed cap cannot meet the
reserve, production activation is unsupported rather than silently treating a
warning as a limit. The managed logging and metrics subagents and the actual standalone
`superserve-otel-collector.service` receive explicit CPU/memory limits, with
metrics receiving the smaller share so its existing queue/memory limiter sheds
metrics before log export is constrained. Reconciliation manages explicit
logrotate bounds for the disposable self-log and legacy syslog stores and
checks the combined buffer budget before activation; successful activation
then vacuums journald. It never deletes checkpoints or pending buffers; an
oversized disposable store is reported and reclaimed in a separately bounded
post-commit pass, while an oversized supported buffer is reported without
blocking exporter recovery. Incomplete or skipped reclamation returns
noncompliance so the next OS Config run remains observable. Recursive
accounting uses one bounded scan deadline and a fixed enumeration cap so
rotated-file growth cannot amplify OS Config retries.
Staging must measure combined growth before
production. The configured 4 GiB journal maximum is counted conservatively in
the combined free-space precondition without adding a second recursive
journal walk.
Each host emits one independent heartbeat per configured 60-second period;
the policy performs no fleet-sized heartbeat loop, so monitoring work is
linear in the expected-host inventory and constant per host.
Candidate configuration and the journald drop-in are validated before atomic
activation. A package upgrade is validated by the staged selected-release
artifact before installation, with the installed package staged for rollback;
a failed reconciliation restores the previous package, service/configuration
state, and delivery state. The policy never
restarts VMD or mutates identity/admission files. A managed minute heartbeat
supplies a timestamped log-based freshness signal keyed by the stable VM
identity, while runtime host ID and incarnation remain distinct. Ops Agent's
supported logging-module self log is collected through one bounded explicit
file receiver for flush/drop diagnostics. The standalone OTel uptime alert
remains independent of log export; the log freshness query uses the logs-based
metric directly and emits an unhealthy result even before a host has produced
its first heartbeat.

Each enrolled runtime identity receives only `roles/logging.logWriter` here;
the existing metric-writer and workload grants remain owned by their roots.
Historical permission-denied reports are retained as incident evidence, not
treated as proof of the current exporter failure cause; staging must verify the
active identity and absence of new permission errors.

The selected package release is pinned in `ops_agent_package_version` (2.71.0;
upstream generator revision `81e4d60b1eb8b6ada14598bee0378532a90ade8c`); rollout
must record the tested release, first-install backfill/cursor behavior, outage
replay/duplicate boundaries, and 72-hour sizing evidence.

First install and an expired cursor are bounded by the retained journal and
the supported Ops Agent checkpoint/buffer state; they do not trigger a full
journal replay. Staging evidence must record the resulting gap boundary.

## Rollout and rollback

Apply the staging root first, inspect the OS Config assignment report and a
real Cloud Logging entry from each serving host and proxy generation, then
repeat the plan to confirm no unexplained drift. Exercise export outage,
agent restart, pressure, retention expiry, and replacement-host convergence
before enabling production roots. Keep the standalone OTel collector healthy
through each exercise. Roll back by selecting the prior
`assignment_revision`/template in version control and applying the same root;
the reconciliation validates that candidate and leaves checkpoints and the
last working configuration intact on failure. Production workflows require an
accepted staging evidence document for the exact `assignment_revision` and
immutable deployment-content digest before they apply a host-logging revision;
expected staging/production identity substitutions are normalized narrowly by
the gate, and no evidence is fabricated by Terraform.
