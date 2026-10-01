# Managed host logging

This module adopts one zonal OS Config policy assignment per environment and
reconciles the Google Ops Agent on existing and replacement serving hosts.
Terraform owns the assignment, package/file/service resources, runtime logging
grant, private versioned configuration artifacts, journald retention, and
rollback revision.

The supported `systemd_journald` receiver is paired with a processor allowlist
(the receiver itself has no unit-filter option) for VMD/proxy, secrets-proxy,
systemd-manager and host/kernel
records. Zerolog `level` is mapped to Cloud Logging severity before
DEBUG/TRACE exclusion. Application parse failures keep trusted journal
metadata but do not export raw VMD/proxy messages, which can contain request,
response, file, or command content. The default syslog-file
pipeline is deliberately absent so each journal record has one steady-state
collection path. Platform identity is rendered from the installed provider
identity at reconciliation time; Terraform descriptors remain rollout/IAM
inputs, and application fields remain subordinate. Journal unit/transport
provenance is copied before JSON parsing so application payloads cannot replace
the source identity used for filtering.

The initial journal budget is 4 GiB with a 10 GiB free-space reserve. The
Ops Agent 2.52.0 uses the documented built-in disk-buffer cap introduced in
2.28; the managed logging and metrics subagents and the actual standalone
`superserve-otel-collector.service` receive explicit CPU/memory limits, with
metrics receiving the smaller share so its existing queue/memory limiter sheds
metrics before log export is constrained. Reconciliation vacuums journald and
expires disposable self-log/syslog files before checking the combined buffer
budget; it never deletes checkpoints and emits an independent error when the
supported buffer itself remains over budget. Staging must measure combined
growth before production.
Candidate configuration and the journald drop-in are validated before atomic
activation. A failed reconciliation keeps the last working configuration and
delivery state. The policy never restarts VMD or mutates identity/admission
files. A managed minute heartbeat supplies a timestamped log-based freshness
signal; the standalone OTel uptime alert remains independent for exporter
failure and never-seen/replacement-host detection.

Each enrolled runtime identity receives only `roles/logging.logWriter` here;
the existing metric-writer and workload grants remain owned by their roots.
Historical permission-denied reports are retained as incident evidence, not
treated as proof of the current exporter failure cause; staging must verify the
active identity and absence of new permission errors.

The selected package release is pinned in `ops_agent_package_version`; rollout
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
last working configuration intact on failure.
