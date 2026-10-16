# Staging candidate validation

This manual workflow permits a reviewed candidate with a new regional migration
to undergo staging acceptance before the normal production release. It does not
change the existing main release or compatible-branch deployment gates. Merging
these workflow files alone neither deploys an API nor runs migrations.

A manifest in `deploy/staging-candidates` binds an open same-repository PR, exact
head, baseline, successful PR CI run, exact-head approval and added migration
hashes. The workflow and validator must first land on main and pass that exact
revision's push CI. Changing the candidate requires a reviewed manifest update.
The separate credentials-free candidate source check must also pass for that
exact main revision. It installs the pinned PostgreSQL parser used to compare
stored migration statement trees with the reviewed files, ignoring source
positions and comments while preserving executable statements and literal bodies.
Main's migration inputs must still match the baseline. A branch dispatch, fork,
stale review, changed CI, unrelated pending migration, different remote history,
or missing index preparation fails closed. No history repair is performed.

The credit-recovery manifest additionally pins a staging historical baseline to
its exact candidate revision and migration hashes. Five previously applied SQL
variants match earlier repository revisions: template alias constraint handling,
a preview-access migration whose version was also used for template limits,
dashboard-role creation race handling, superseded trial eligibility, and snapshot
DDL lock handling. `yc-credit-history.json` records their historical sources,
exact ordered statement and syntax-tree hashes, and current source hashes.
Only those exact variants are accepted; all other history remains strict.

The validator also requires the relevant current template constraints, legacy
preview columns, role/grants, snapshot index/foreign key, and billing/snapshot
function and trigger definitions. Later migrations already supply the current
effects, so replaying the old SQL is neither necessary nor permitted. Catalog
evidence is read in one bounded read-only query; parsing happens after the
transaction. Policy and catalog hashes enter the approved receipt and are checked
again before apply. After apply, only the reviewed enqueue-function transition is
accepted and every preexisting history row must remain unchanged. A changed
candidate, baseline source, variant or catalog requires fresh review; this policy
does not authorize production exceptions or database repair.

## Preflight

Dispatch **Staging candidate validation** on main with the reviewed manifest name
and `mode=preflight`. Candidate Docker builds run in a separate hosted job without
cloud credentials. The staging job executes only trusted-main tooling, composes
main's migration inputs with the allowlisted additions, and invokes the existing
pinned migration runner for connection preflight, list and dry-run.

Targets are fixed to the staging GCP project/service, staging regional Supabase
database and Stripe test account. Secret values remain in process memory. The
preflight artifact contains only source, image, runtime, history and cohort hashes,
secret version numbers, and counts. Customer IDs and credentials are not published.
The image archive and receipt are retained for seven days.

Review the run's receipt SHA256 and the affected staging cohort through authorized
read-only access. The inventory covers active Pro/YC contracts, current missing
allowances, unresolved entitlements and non-ended YC operations including frozen
resource terms. This workflow does not select, create or activate a test fixture.

## Execution

After explicit approval of that concrete scope, dispatch on the **same main
revision** with `mode=apply`, the successful preflight run ID, its receipt SHA256,
and `accept_concurrent_staging=true`. This acknowledgement covers normal concurrent
staging processing in addition to the snapshot: existing workers remain live and
new activations may occur. A revision with no traffic still starts workers.

The validator authenticates the original successful preflight run and artifact,
rechecks provenance and all receipt inputs, pushes the verified image under a
run-specific staging tag, rechecks state, then uses the existing runner to apply
only the approved pending migration. It verifies preserved history and installed
schema before deploying the immutable image digest. The candidate revision pins
the validated numeric database, Stripe and operator secret versions, preventing
`latest` rotation from changing its startup credentials. It checks those references,
the ready revision, digest, 100% traffic and health.

The workflow holds the existing control-plane lock followed by the database lock.
The migration runner retains its database advisory lock and execution limits.
These locks serialize participating releases; they do not freeze application
workers or prevent out-of-band administrative changes.

Stop on any mismatch or partial failure. Do not rerun an apply attempt: create a
fresh preflight only after reviewing actual effects. An applied migration changes
the expected baseline inventory, so a partial apply deliberately requires a
separately reviewed recovery decision. There is no automatic rollback, repair,
production fallback or promotion. Pinning the three runtime secret versions is
part of this candidate deployment; subsequent normal release/configuration work
must deliberately reconcile those pins with its intended rotation policy.

A green workflow establishes migration and deployment only. Actual Stripe grant
issuance, duplicate-free replay, invoice consumption and authenticated application
access require separate controlled acceptance. Keep the candidate PR unmerged
until its acceptance requirements are satisfied. Provisioning fixtures, changing
terms or subscriptions, and resetting anniversaries are not part of this workflow.

## Local checks

Run the existing workflow test discovery:

```sh
python3 -m pip install -r deploy/staging-candidates/requirements.txt -r scripts/migration-requirements.txt
python3 -m unittest discover -s .github/workflows/scripts -p 'test_*.py'
```

The dedicated candidate source workflow requires the parser and tests the catalog
query against disposable PostgreSQL on every PR and main push. Local catalog-query
testing requires `STAGING_CATALOG_DATABASE_URL` pointing to a fresh disposable
`staging_catalog_test` database on `127.0.0.1`; never use staging credentials.
Without that URL the catalog-query test is skipped locally. Parser tests also
skip when the optional local parser dependency is absent.
