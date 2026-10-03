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

## Operational evidence prerequisite (currently blocked)

The verifier is an artifact contract, not a collector or an access provisioner.
This repository does not yet supply `.github/workflows/recovery-evidence.yml`.
Consequently production recovery cannot pass its evidence gate until a separately
reviewed collector and existing authenticated host-observation route are available.
Do not replace that requirement with an operator-authored JSON assertion.

The collector must run from the exact approved main revision, using
`workflow_dispatch`, and publish the unique artifact
`retained-recovery-evidence-usw2` containing only `evidence.json`. The verifier
checks the authenticated GitHub run, artifact digest, plan/database identity,
full cloud inventory and an observation at most 120 seconds old before each
phase. Test fixtures in `scripts/test_recovery_evidence.py` illustrate the schema;
they are synthetic data, not acceptable operational evidence.

The existing deployment identity is selected by `GCP_WORKLOAD_IDENTITY_PROVIDER`
and `GCP_SERVICE_ACCOUNT`. Reusing those secret references does not establish
that the identity has the needed permissions. An operator must establish these
specific prerequisites without changing live configuration as part of recovery:

- GitHub `contents:read` and `actions:read` for the exact run/artifact, plus OIDC
  `id-token:write` to use the existing GCP workload identity.
- Existing cloud permissions for service metadata, all service revisions, all
  project VM instances, and complete revision-deletion audit logs. The relevant
  reads are `run.services.get`, `run.revisions.list`, `compute.instances.list`
  and `logging.logEntries.list`. The verifier uses `gh`, Cloud SDK and Python.
- An already authenticated, non-provisioning route to read every relevant host's
  process inventory, executable hashes, installed restart units/drop-ins and
  effective configuration, process start/incarnation/destination, and all report
  spools. Do not invoke deployment scripts or let SSH register keys or metadata.
  Configuration evidence must be hashed/redacted without exporting secrets.
- Authenticated binary-to-source provenance. API build image archives can be
  digest-compared with the observed image. Existing VMD deployment builds upload
  binaries without a retained provenance artifact; those installed binaries need
  authenticated historical build evidence or a verified reproducible build.

Coverage includes serving, tagged, zero-traffic/background and draining revisions,
all project instances including standby hosts, installed restart executables and
alternate producers. Sidecars, command overrides, unaudited builds, automatic
binary downloads or unfinished rollouts prevent admission. Recent revision deletion
must be excluded through complete audit coverage spanning at least ten minutes
before collection. The admitted source is pinned in the verifier and was audited
for both retained production and persisted replay behavior. A newer build with
retained-report production or replay capability does not satisfy this policy,
even with sampling disabled. It requires a separately reviewed exclusion policy
and complete fresh evidence; do not add a source revision based on deploy success.

Sampling disabled is insufficient: publishers can replay persisted payloads.
Inspect `.storage-report-queue`, `.storage-report-queue.v2` and
`.storage-report-queue.migrating/state.json`, plus both database report queues.
Require an independently coordinated deployment/configuration hold for the whole
recovery. Observe effective runtime and restart sources; a source label or a
configuration checkbox is not evidence. Missing access or provenance blocks
operations and must be routed to the deployment owner; this change grants no IAM,
creates no observer, provisions no SSH access and performs no production trial.

## Validation

Regression tests use the actual pinned CLI against disposable Docker PostgreSQL 17.6:
`test_migration_cli.py`, `test_migration_overlay.py`, `test_migration_execution.py`
and `test_migration_recovery.py`. Evidence and release-gate tests exercise missing,
stale and changed observations and the distinction between ordinary and recovery
preflight. They do not establish hosted connectivity or production writer exclusion.
