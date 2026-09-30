# Managed host logging

This module adopts one zonal OS Config policy assignment per environment and
reconciles the Google Ops Agent on existing and replacement serving hosts.
Terraform owns the assignment, package/file/service resources, runtime logging
grant, private versioned configuration artifacts, journald retention, and
rollback revision.

The supported `systemd_journald` receiver is paired with a processor allowlist
(the receiver itself has no unit-filter option) for VMD/proxy and host/kernel
records. JSON severity is parsed before DEBUG/TRACE exclusion;
malformed records remain eligible host diagnostics. The default syslog-file
pipeline is deliberately absent so each journal record has one steady-state
collection path. Platform identity comes from Terraform host descriptors and
installed host identity, while application fields remain subordinate.

The initial journal budget is 4 GiB with a 10 GiB free-space reserve. The
Ops Agent's built-in checkpoint/retry and disk buffer are separate and bounded
by the managed service resource settings; staging must measure their combined
growth with agent self-logs and retained syslog files before production.
Candidate configuration is validated before atomic activation. A failed
reconciliation keeps the last working configuration and delivery state. The
policy never restarts VMD or mutates identity/admission files.

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
