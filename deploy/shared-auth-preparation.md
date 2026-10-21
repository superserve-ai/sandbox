# Preparing shared Auth for accepted offers

The general deployment prerequisite applies company authority, claims and staff
approvals. Acceptance migration `20261021135531` is an explicit prerequisite for
releasing accepted-offer consumers, including preferred claim lookup, staff
review and financial invalidation workers. Admission flags do not disable all
these consumers. An unprepared target can return YC errors while general API
health remains successful.

## Compatibility before preparation

Release the acceptance-aware migration inspector before preparing any shared
database: [recognition-only compatibility PR #771](https://github.com/superserve-ai/sandbox/pull/771),
source `9b2be50116e9c4e8209898dc3cd7672e059b6711`. Record its actual merge/release
revision and verify the deployed executor retains that implementation before
preparation; the PR's existence alone does not prove release. It recognizes the
exact optional acceptance receipt and its permitted
predecessor catalog changes, while retaining all previous receipt checks. The initial
compatibility release does not expose acceptance apply through the CLI or add it
to the general deployment prerequisite. The pinned SQL file is the reference
artifact for receipt and catalog validation, not an automatic migration.

Immediately before preparation, inventory active, waiting and queued deployment
executions and their pinned migration-tool revisions. Older tools reject the
acceptance receipt as unknown history. Account for affected executions before
changing their target; do not rerun an older incompatible executor afterward.
Keep the compatible tool for subsequent application rollback deployments. This
does not establish that an older application binary can safely manage already
activated financial work; that needs its own release assessment.

## Target-specific release prerequisite

The release owner must retain a candidate-target manifest and review it before
authorizing the affected release. This is an operator-controlled prerequisite;
the general CI and health endpoints do not validate this manifest. Record:

- Candidate and preparation-tool commit, immutable SQL SHA-256, and compatible
  general deployment executor revision.
- Each actual shared Auth database project/cluster and database identity, the
  deployed application's actual role, and every regional consumer using it.
  A secret name or environment label does not prove this mapping. Never retain
  connection strings or passwords in the manifest.
- Successful exact-target inspection, explicit application if pending, and
  post-application inspection evidence, including tool revision and time.
- Regional schema preparation evidence and the release owner's disposition of
  affected older executions and application rollback compatibility.

The acceptance-capable preparation tool is a separate release artifact: see
[the accepted-offer change](https://github.com/superserve-ai/sandbox/pull/763),
reviewed at `f8f51488a4bb04380b1a916b9c43f8f8fdb2a1eb`. That artifact's migration
script supports acceptance inspection and application; the recognition-only compatibility
checkout intentionally does not. The release remains blocked until the owner
has an approved, accessible preparation artifact and an authorized execution
path for the actual target. The current main-only hosted workflow cannot select
acceptances from the recognition-only compatibility revision. Use the separately authorized
exact-artifact CLI path, or release a reviewed preparation-only workflow first;
do not merge or deploy the consumer stack merely to obtain its migration tool.

Use the preparation checkout's `migrate_shared_auth.py TARGET inspect|apply --migration
acceptances --revision COMMIT --runtime-project VERIFIED_PROJECT` commands
verify source/history, catalog, permissions and financial writer triggers.
Supply the existing migration credential through the authorized secret
environment mechanism. Run inspect, separately authorized apply if pending,
then inspect again, retaining the sanitized results. An apply fast-path receipt
alone is not a full catalog audit. A pending or failed result does not authorize
consumer release. Do not rewrite history, fabricate receipts or bypass project
guards. This document grants no database execution authority.

Current workflow aliases cover staging and the primary production Auth database;
the latter is shared by both production regions. Verify actual runtime routing
and role on every release target instead of assuming those aliases are complete.
Every new environment, restored database, changed Auth connection or bootstrap
must satisfy the same prerequisite before serving these consumers. A disposable
devbox additionally requires its dedicated identity-bound initializer and lease.

After activation, keep live authority checks and revocation processing operating
when new admissions are disabled. Missing shared authority must continue to deny
financial effects and readiness, retain unresolved deliveries, and avoid false
acknowledgements. Preparation failures stop the affected YC release; they do not
authorize a repository-wide deployment hold.
