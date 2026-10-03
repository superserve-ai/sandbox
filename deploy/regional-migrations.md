# Regional database migrations

Install `scripts/migration-requirements.txt` and use Supabase CLI 2.119.0.
All remote actions go through `scripts/migrate_database.py`; `make migrate-local`
is only for disposable databases. Targets are `staging`, `use4`, and `usw2`.
The wrapper requires the selected project's direct port 5432 endpoint and
PostgreSQL 17+, with startup/reset defaults of 250ms lock timeout and 2s
transaction timeout. Session poolers are not accepted. The hosted runner must
have a working route to the direct endpoint; DNS alone does not prove access.
Never print `DATABASE_URL` or include it in a command transcript.

## Shared Auth history

East also hosts shared Auth. Its existing migration entry
`20261002155220_shared_signup_device_evidence_setup` is a single statement
assembled from three pinned sources. The exact bytes live under
`supabase/shared-auth-history/`, outside the regional migration directory.
The wrapper verifies its version, name, statement count and hash before and
after execution. It adds the unchanged artifact to an isolated CLI workdir
only for East, and refuses a dry run proposing to replay it.

This recognizes completed setup; it cannot initialize shared Auth. Missing or
mismatched East history, or aggregate history in another region, stops execution.
Do not repair history manually, mark versions reverted, use `--include-all`,
or replay Auth setup regionally.

## Coordinated release

Control-changing pushes intentionally stop CD Migrate before database jobs.
The same hold stops applicable automatic application deployment lanes. This
includes mixed SQL/control changes and unverified push ranges. A held CD run
is not successful migration evidence. CI still runs.

After a separately approved merge, verify successful push CI at the exact main
revision. Dispatch CD Migrate with `action=preflight` for a read-only direct
connection/settings check. `action=migrate` is a separate release and requires
a successful same-revision preflight run covering all selected environments.
Staging runs first, then East and West. Each regional action rechecks main after
protected-environment approval, immediately before database access. If main
advances, stop and reassess the release. A code approval does not authorize
merge, database execution, service pause, session termination or activation.

Only after actual successful migrations and a separate application release,
use the coordinated manual API, VMD and Proxy workflows. Their manual paths
retain the operator's responsibility for migration prerequisites. Route held
infrastructure work to its owner. Do not cancel an in-flight deployment as a
substitute for the gates.

## Retained-storage recovery

The fixed `retained-storage-v1` plan handles West before retained migration 01
or at a prefix produced by this recovery. Staging and East must already have
all 24 canonical entries and remain read-only. Source files and applied history
are never rewritten. All 24 new West entries truthfully record a stable
authorization prelude followed by the executed migration body. Bodies 01/03/14
also contain the bounded recovery substitutions below. Earlier intermediate
histories without this prelude are not admitted or rewritten.

The runner first installs nullable host attribution and its stamping trigger
without backfilling old intervals. It builds three indexes concurrently outside
the short metadata transactions and validates the new reason constraint before
swapping it into place. A private database journal binds the exact plan,
predecessor history, preparation state and index table identities. Each phase
checks the expected catalog and ledger under the same session mutex used for
mutation. The approved receipt is rechecked under that mutex, and each next
phase must match this invocation's own progress. Ordinary West migrations
require a completed journal, including on an empty or canonical partial ledger.
Completed recovery
preserves its historical receipts while allowing subsequent ordinary migrations.

Use the distinct `recovery-preflight` and `recover` actions. Production requires
an authenticated evidence run ID described below. Recovery preflight reads the
database without initializing the journal and uploads regional state receipts.
Recover downloads those receipts from the successful same-revision recovery
preflight run. A normal connection preflight cannot authorize recovery.
Fresh evidence may replace an expired collection only when its verified writer
state and inventory match the preflight receipt. Any changed database or writer
state requires a new preflight and release decision.

Each invocation authenticates and caches its immutable evidence artifact once.
Before each mutating phase it refreshes the complete service, revision and host
inventories in parallel and revalidates evidence age afterward. Read-only loop
inspections do not fetch a second inventory before the same CLI mutation. These
checks still depend on cloud latency; local recovery timings use mocked cloud
observations and do not prove a hosted run can finish within the validity window.

Execution retains the 250ms lock acquisition, 2s transaction and 60s command
limits. The complete recovery has a separate 180s deadline, chosen as roughly
three times the 59s disposable full-path regression duration. Evidence still
expires after 120s. The roles hook binds one version, plan, expected phase and
expiry to its backend PID and start time while holding the mutation mutex.
The first statement of the actual migration transaction validates that
authorization, mutex ownership and a full 2s transaction budget before the
migration body. A history-insert trigger repeats the check before committing
SQL and history together. This survives the CLI's intervening session reset;
a reconnect must obtain a new authorization. The checks read private journal
and catalog relations and can themselves acquire locks under the 250ms/2s caps.
Server timeout handling and rollback are subject to scheduling latency; these
are bounded execution controls, not a real-time promise of zero locks or zero
latency. The total deadline does not extend evidence validity or authorize
retries. Standalone concurrent index create/drop operations have a 1.9s
statement limit, strictly below the 2s transaction limit so PostgreSQL keeps
the whole-statement timer active across their internal transactions. Each Python preparation reserves 6s of remaining validity
for its admission command, an idle client gap and the next mutation. The
server arms a 2s idle-session timeout in the admission command, preventing a
suspended client from later starting concurrent index work with stale evidence.
Every mutation requires a new admission. These reduce exposure; they do not guarantee zero customer
latency. Stop on failure. There is no automatic retry or timeout increase.
After a separately authorized new preflight, a recorded invalid concurrent
index may be removed only if its name, definition and table identity match the
owned intent. Removal stops again before rebuilding. Unknown objects, altered
source/history, journal holes, active retained accounting or queued retained
payloads fail closed. Never delete an unrelated index or manually mark a
migration applied.

## Receiver evidence and operational prerequisites

`.github/workflows/recovery-evidence.yml` collects schema 3 provenance evidence using
`scripts/collect_recovery_evidence.py`. It is manual-only and requires the exact
reviewed main revision and an explicit named-operator coordination acknowledgment.
It publishes only `evidence.json` in `retained-recovery-evidence-usw2` on success.
The verifier authenticates the GitHub run and artifact digest. Schema 3 retains
immutable provenance across queue/setup delays; it does not grant a mutation
lease. Inside each consuming West job, a complete new observation brackets guest
reads with matching cloud inventories and workflow checks. Receiver configuration,
secret-version metadata and effective guest state must still match the authenticated
artifact. Changed state requires a new collection and preflight.

Each successful observation authorizes at most 120 seconds from the **start** of
its live reads. Every refresh repeats those checks; failed or overlong observations
issue no lease. Existing SQL admission and total recovery deadlines still apply.
Schema 1/2 artifacts retain their original collector-start expiry. Preflight
identity excludes observation times/run IDs and ordinary connection churn, but
includes authenticated provenance and effective writer state. After partial
committed recovery, obtain a new read-only preflight and approve its exact database
state; the old receipt must fail rather than silently accepting progress.

Schemas 2 and 3 permit audited retained-capable guest publishers only when every
possible receiver is proved incapable of accepting their retained reports and
the separate empty-accounting database guards pass. Sampling need not be disabled
and guest spools need not be empty for this policy. Schema 1's producer-exclusion
checks remain available for existing artifacts; its stricter spool requirements
do not substitute for the receiver proof.

### Coordinated window

`coordinated_assumption` records an operational assumption, not an enforced lock.
Before acknowledging it, the coordinator must obtain the named operator's explicit
agreement to a finite no-change window covering both regions, all receiver paths,
and the recovery target. The window starts before collection and remains in force
until recovery succeeds or is aborted **and** its work and sessions have ended.
It excludes API/worker deploys and rollbacks, guest executable/service/restart
configuration changes, routes/DNS/proxies, database-secret rotations, retained
activation, manual or alternate writers, and already queued or in-flight mutation
automation. The collector checks active workflows on every branch, but that check
and fresh inventory detect changes; they do not prevent them or replace the
operator's acknowledgment. Each production recovery preflight or recovery dispatch
also requires `recovery_coordination_ack=accepted` for that consumer run. An old
collector acknowledgment does not establish the current window. No default or
synthetic acknowledgment is valid.

If this agreement is violated between observations, a newly capable API could
acknowledge a retained report before an older worker discards its unknown payload,
losing the publisher's acknowledged measurement. A capable worker could also
create retained state during recovery. Short SQL lock timeouts and evidence expiry
do not close that race. On any change, stop recovery and coordinate termination;
then review the new state and collect fresh evidence and preflight as required.

### Access and provenance

This implementation does not establish that live access exists. Missing access
must be resolved separately by the deployment owner before an operational run.
Neither collection nor recovery provisions keys, IAM, routes, or guest services.
Do not dispatch either workflow merely to discover whether production access works.

- The collector and production recovery jobs use `RECOVERY_OBSERVER_RUNNER`
  (default `ubuntu-latest`) and `RECOVERY_SSH_USER`. They require an existing
  `~/.ssh/google_compute_engine` identity and verified `~/.ssh/known_hosts` entries
  for aliases `rayai-prod.<zone>.<instance-id>`, IAP tunnel access and noninteractive
  permission to execute the fixed probe with `sudo -n /usr/bin/python3 -`.
  A fresh hosted runner normally lacks this route and fails closed. SSH checks
  host keys strictly and never registers a key or updates metadata.
- The existing `GCP_WORKLOAD_IDENTITY_PROVIDER` and `GCP_SERVICE_ACCOUNT` references
  select an identity; they do not demonstrate its permissions. Read access must
  cover all services and revisions, jobs and active executions, worker pools,
  project instances, DNS/routing components, registry artifacts and complete
  receiver-deletion audit history. GitHub needs `contents:read`, `actions:read`
  and OIDC `id-token:write`. Both jobs need Python, Cloud SDK, `gh`, and SSH.
- Private database binding additionally requires version metadata and payload
  access for only `database-url-usw2` and `database-url`. The helper privately
  checks all versions that could have been loaded since the oldest active
  receiver revision started, including versions since superseded by `latest`.
  Missing version history or an unavailable possibly loaded version blocks
  collection. Outputs contain version identities and project-match booleans,
  never URL values, credentials, or provider error output. No SQL connection is
  made by this collector. Operational payload access requires separate release.
- Every receiver revision needs an authenticated successful main build artifact
  whose image configuration matches its immutable registry image, with source on
  the audited pre-retained first-parent lineage. Tags are lookup hints only.
  Deleted revisions/jobs, unknown images, missing/expired build artifacts, sidecars,
  command overrides and unknown consumers fail closed; elapsed time is not proof
  that an old process or database session drained.
- Guest binaries are reproduced from the exact reviewed source with Go 1.25.0
  and the original build flags. Running and installed binaries, units, normal
  drop-ins and restart guards must match that provenance. A new VMD rollout needs
  source review and updated provenance followed by fresh evidence; changing a
  source pin based only on deployment success is insufficient.

The fixed guest probe reads process/environment and loaded systemd settings
privately, emitting only executable/configuration hashes, process identities,
credential-free control-plane origins, DNS addresses and established peers.
For a separately authorized diagnostic, on each guest run exactly
`sudo -n /usr/bin/python3 - < recovery_guest_probe.py` with the reviewed script
provided through stdin by the existing authenticated route (the collector does
this without copying a file onto the host). Manual output alone is not an
authenticated, fresh hosted artifact.

Existing socket addresses are diagnostics, not TLS hostname attribution. The
audited VMD fixes the retained-report URL from its startup control-plane setting;
persisted reports cannot override it. The audited receiver handlers and middleware
do not redirect those requests. That source proof, effective origin, absence of
report proxies, admitted historical receivers, current DNS/routing and coordinated
window establish receiver exclusion. Normal GCS backup connections do not change
report authority and do not require an IP allowlist or idle backups. Evidence of
an actual alternative historical route requires review of that route; an IP match
alone does not establish which service owns a socket.

## Validation

Regression tests use the actual pinned CLI against disposable Docker PostgreSQL 17.6:
`test_migration_cli.py`, `test_migration_overlay.py`, `test_migration_execution.py`
and `test_migration_recovery.py`. Evidence and release-gate tests exercise missing,
stale and changed observations and the distinction between ordinary and recovery
preflight. They do not establish hosted connectivity or production writer exclusion.
