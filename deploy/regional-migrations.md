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
Before mutation it obtains a bracketed live observation. Subsequent phases reuse
that fixed 120-second lease while checking artifact/plan/consumer identity, wall
and monotonic clocks, and at least six seconds of remaining validity. Reuse never
extends expiry. Renewal repeats the complete mutable inventories and workflow
checks, revoking the previous lease before any reads. Database inspection and
admission still run for every phase. Cloud latency can still stop a renewal;
synthetic timings do not prove hosted runtime.

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
its live reads. Phase boundaries may reuse the unexpired lease under the explicit
coordination hold; this does not detect external changes immediately. Every renewal
repeats mutable checks; failed or overlong observations issue no lease. Existing SQL admission and total recovery deadlines still apply.
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

Deletion history admits only the reviewed metadata catalog in
`scripts/recovery_retired_receivers.json`, predating the October 2 retained
producer, receiver, and schema introduction on main. Job deletion terminates
executions; service deletion removes its revisions and remains listed until
complete. The single cataloged NotFound failure performed no deletion. Recreated
objects require later creation timestamps and current identities, then pass the
full current source/configuration policy. Unknown events still reject. This is a
source/deployment and termination argument, not proof against arbitrary
out-of-band historical code. The collector reads full history once and binds its
original lower bound, rows, catalog digest and pre-query cutoff into the artifact.
Each observation runs one mandatory delta query concurrently with opening mutable
inventory and guest work, awaits it, then takes the closing inventory and workflow
checks. The delta query uses `(timestamp >= cutoff OR receiveTimestamp >= cutoff)`
within that original history range; unknown or changed rows stop recovery. The
cutoff never advances, so delayed older events remain eligible. Cloud Logging has
no assumed ingestion watermark: absence of a delivered event is not proof that no
transient change occurred. The coordination hold covers that gap. See [jobs](https://docs.cloud.google.com/run/docs/managing/jobs)
and [services](https://docs.cloud.google.com/run/docs/managing/services).

Guest configuration checks require all five deployment guards and exact hashes
for reviewed optional drop-ins. The observed West mount dependency is matched by
exact content; the other recipes derive from the audited source. Inline flags and
the duplicated identity environment-file entry must match the admitted files.
Ordinary pasted probe output is diagnostic. The explicit manual mode below accepts
a hash-bound, attributed capture under a finite operator continuity assumption;
it still requires authenticated hosted cloud collection and private binding checks.

### Operator-supplied host capture

Manual mode reuses the existing hosted production identity. It needs no observer
runner or new SSH access. Its authority is the named operator's explicit continuity
acknowledgment, **not** workflow authentication of the earlier SSH session. The
operator who captured the hosts must dispatch collection. Release approval must
explicitly accept this evidence policy, including the 30-minute maximum age from
original capture start through the last mutation. Approval, fresh cloud reads and
lease renewal never reset that clock. Do not reuse an old conversation attachment
by inventing its capture time or immutable instance identity.

The capture binds both immutable instance IDs, full instance metadata hashes,
original start/end times, probe hash, revision, plan and operator. Current cloud
observations must still match, with both instances RUNNING and lastStartTimestamp
no later than capture start. A full VM reboot invalidates the capture: audited
boot/startup scripts can rewrite unit/drop-in configuration even without an Actions
deployment. Normal service restarts into unchanged installed configuration and
credential-refresh/maintenance-notice timers do not invalidate the routing argument.
The hold must also cover relevant external OS Config/patch jobs and already queued
configuration changes; an empty Actions queue alone does not establish that hold.

After code approval, merge, successful main CI and explicit operational release,
run this single capture from the clean approved checkout using the operator's
**already working** gcloud SSH route, with `RECOVERY_SSH_USER` set to its existing
Linux username (the verified current operator uses `alejandro_superserve_ai`). `--plain` suppresses gcloud key creation/registration; explicit
SSH flags require the existing key and verified host entry. It neither dispatches collection nor reads
database secret payloads. If the route needs key registration or new access, stop.
Do not accept an interactive key-registration/host-key prompt. The timestamps and
identity envelope are captured here, not reconstructed afterward:

```sh
python3 - <<'CAPTURE'
import datetime, hashlib, json, os, re, subprocess, sys
from pathlib import Path
sys.path.insert(0, 'scripts')
import recovery_evidence as evidence

def read(args, source=None, metadata=False):
    result = subprocess.run(args, input=source, capture_output=True, text=True, timeout=60)
    if result.returncode or metadata and result.stderr:
        raise SystemExit('Capture failed; no input issued. Inspect the existing route privately.')
    return result.stdout

def inventory():
    rows = json.loads(read(['gcloud', 'compute', 'instances', 'list', '--project=rayai-prod',
                            '--limit=1000', '--format=json', '--quiet', '--verbosity=warning'], metadata=True))
    if len(rows) != 2:
        raise SystemExit('Expected exactly the two reviewed production hosts')
    return sorted(rows, key=lambda row: str(row['id']))

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

revision = read(['git', 'rev-parse', 'HEAD']).strip()
operator = json.loads(read(['gh', 'api', 'user']))['login']
probe = Path('scripts/recovery_guest_probe.py').read_text()
ssh_user = os.environ.get('RECOVERY_SSH_USER', '')
key, known = Path.home()/'.ssh/google_compute_engine', Path.home()/'.ssh/google_compute_known_hosts'
if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', ssh_user) or not key.is_file() or not known.is_file():
    raise SystemExit('Set the existing Linux SSH username; existing key and gcloud known-host file are required')
started = now()
before = inventory()
hosts = []
for host in before:
    observed = json.loads(read(['gcloud', 'compute', 'ssh', ssh_user+'@'+host['name'], '--project=rayai-prod',
        '--zone='+host['zone'].rsplit('/', 1)[-1], '--tunnel-through-iap', '--quiet', '--plain',
        '--ssh-flag=-F/dev/null', '--ssh-flag=-i'+str(key), '--ssh-flag=-oIdentitiesOnly=yes',
        '--ssh-flag=-oBatchMode=yes', '--ssh-flag=-oStrictHostKeyChecking=yes',
        '--ssh-flag=-oUpdateHostKeys=no', '--ssh-flag=-oControlMaster=no',
        '--ssh-flag=-oUserKnownHostsFile='+str(known), '--ssh-flag=-oHostKeyAlias=compute.'+str(host['id']),
        '--command=sudo -n /usr/bin/python3 -'], source=probe))
    if 'error' in observed:
        raise SystemExit('Guest probe incomplete; no input issued')
    hosts.append(evidence.stable_guest(dict(instance_id=str(host['id']), instance_name=host['name'],
        zone=host['zone'], instance_sha256=evidence.sha(host), route='operator-supplied',
        probe_sha256=hashlib.sha256(probe.encode()).hexdigest(), observation=observed)))
if inventory() != before:
    raise SystemExit('Host identity or metadata changed during capture')
manual = dict(authority='operator-supplied-coordinated-window', revision=revision,
    plan_hash=evidence.sha(json.loads(Path('supabase/recovery/retained-storage-v1.json').read_text())),
    project='rayai-prod', target='usw2', operator=operator, acknowledgment='accepted',
    scope=evidence.COORDINATION_SCOPE, started_at=started, completed_at=now(), hosts=hosts)
evidence.validate_manual_guests(manual, revision, manual['plan_hash'], {'instances': before},
                                datetime.datetime.now(datetime.timezone.utc).timestamp())
raw = json.dumps(manual, sort_keys=True, separators=(',', ':'))
if len(raw.encode()) > 60000:
    raise SystemExit('Capture exceeds the workflow input bound')
Path('/tmp/recovery-manual-guests.json').write_text(raw)
print('Input SHA256:', hashlib.sha256(raw.encode()).hexdigest())
CAPTURE
```

Review that input and its printed digest, then pass its **exact bytes** as
`manual_guests_json` and the digest as `manual_guests_sha256` to the existing
collection workflow with the approved revision and `coordination_ack=accepted`.
Use structured JSON input to dispatch; never interpolate capture text into shell
code. This selects `ubuntu-latest` and bypasses only automated guest SSH.
The workflow authenticates and records the supplied authority alongside its fresh
cloud evidence. Then use the resulting evidence run ID for recovery preflight and
recover, both with `recovery_guest_mode=manual` and a fresh consumer acknowledgment.
Both use the existing hosted production identity and retain the database/receipt
checks. Finish inside the original capture's 30 minutes or abort and coordinate a
fresh capture/preflight. No private binding or migration run is authorized merely
by preparing this input.

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

- In automated guest mode, the collector and production recovery jobs use `RECOVERY_OBSERVER_RUNNER`
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
