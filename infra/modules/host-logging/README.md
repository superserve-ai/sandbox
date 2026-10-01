# Managed host logs

This module owns one dedicated OpenTelemetry Collector Contrib logs process
through a regional OS Config assignment. It reads the persistent journald
source, filters the selected VMD/proxy and host units, reconstructs an
allowlisted Cloud Logging payload, and exports asynchronously with persistent
cursor and queue state.

The logs binary, configuration, service unit, reconciliation script, cursor,
queue, and journald retention policy are separate from the existing metrics
collector. Candidate files and the selected release archive are validated
before activation. A failed validation or restart retains the active files and
all delivery state; an unchanged reconciliation does not restart the service.
The exporter queue also has an explicit Terraform byte budget; its record-count
setting is not treated as a disk-capacity guarantee.

The regional roots provide the selector and enrolled-host identity descriptors.
The attached runtime identities receive only the logging writer grant and
artifact read access required by the assignment. Existing legacy delivery in
the east cell remains independent until staging receipt and migration evidence
authorize a cutover.

The release checksum, source compatibility, outage/restart recovery, pressure,
retention, replacement, rollback, and drift evidence are rollout obligations;
Terraform plans and the focused contract tests do not claim those runtime
results.
