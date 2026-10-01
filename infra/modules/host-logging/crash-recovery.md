# Crash-safe host log recovery

This draft tracks the recovery guarantee intentionally deferred from the
initial managed host-log rollout. The current released OTel journald receiver
can persist its read cursor before records reach the persistent exporter queue.
A crash under queue pressure can therefore leave gaps in Cloud Logging even
while the source records remain in the host journal. Source rotation or disk
loss eventually removes that fallback.

The explicit regression is `python3 scripts/reproduce_host_log_crash_gap.py`.
It uses the pinned released collector, genuine journal files, a failing local
OTLP endpoint, constrained queue capacity, and a forced collector crash. It is
expected to fail against the current implementation; this PR is not a recovery
fix and must remain draft until a supported ingestion path passes the stronger
acceptance cases below.

## Implementation work

Evaluate a supported journal reader feeding OTel, such as rsyslog, or an
upstream released receiver with verified durable handoff. Do not assume adding
a disk queue closes the gap: prove when the source checkpoint advances relative
to downstream durable acceptance and remote acknowledgment. Keep persistent
installation and configuration in Terraform/OS Config and preserve the
independent metrics collector, host identity, source journal, and existing
log delivery state.

## Acceptance

- Establish a healthy acknowledged baseline, then produce uniquely numbered
  records during an export outage. Prove queue and checkpoint state exist
  before injecting failure; a successful full-history replay is not sufficient.
- Saturate the queue with more than one receive batch. Crash during handoff,
  restart while offline, restore export, and reconcile every sequence ID.
- Repeat with uncertain acknowledgments. Allow bounded duplicates, reject
  silent gaps and replay of the entire acknowledged baseline.
- Verify sustained pressure stays within aggregate journal, spool, queue,
  checkpoint, temporary-file, and self-log byte budgets. Keep the host reserve
  and preserve VMD/journald responsiveness; shed metrics first.
- Retain trusted timestamps/identity, INFO+ filtering, generated proxy coverage,
  metadata-only malformed records, and positive field allowlisting.
- Exercise source rotation/expired cursors, interrupted upgrades, rollback,
  replacement hosts, and state compatibility without deleting pending records.
- Run independent scalability, requirements, and testing reviews, then stage
  actual Cloud Logging receipt, outage/restart, and constrained-host behavior
  before production activation.
