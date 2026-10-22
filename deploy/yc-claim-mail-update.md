# Correct the YC confirmation-mail lease function

The `claim-mail` shared Auth migration changes only the two table aliases in
`yc_claim_rpc`'s mail-lease branch. It preserves the original migration, all
existing data and receipts, the function identity, privileges, and settings,
including acceptance's hardened search path. It does not send mail itself.

Apply the correction through the reviewed shared migration helper, never by
replaying the original authority migration or executing the SQL file directly.
The helper verifies the known predecessor function against its receipt, applies
the correction, and inserts a new receipt in one transaction under the existing
shared migration lock. An unfamiliar body, permission, setting, or history must
be investigated rather than adopted. Failed updates roll back both the function
and receipt. A recorded retry performs no replacement.

## Ordering and compatibility

Deploy the helper's recognition support to migration executors before adding the
new receipt to a database those executors use. Older helpers reject an unknown
receipt. This update is optional and is not added to normal deployment gates.

Authority and claims must already be installed. Approval and acceptance may be
installed before or after this correction; inspection handles both orders
without rewriting their receipts. This change does not enable acceptance
preparation in the production CLI or change a fresh-database initializer.

For a verified production or staging authority target, use the existing CLI and
its runtime-project/connection guards, selecting `--migration claim-mail` for
`inspect`, then `apply`, then `inspect`. Use the same reviewed revision for all
three steps. Do not route a disposable target through the staging CLI.
The existing `Apply shared Auth migration` manual workflow also offers
`claim-mail` for staging and use4. Its normal revision and runtime-project guards
still apply; selecting the repair does not add it to automatic deployments.

## Already-initialized disposable target

The existing fresh-database initializer is not an upgrade tool. Do not extend its
migration tuple, relax its empty-Auth guard, or reset an initialized database.

The execution owner must first revalidate the host/instance/runtime identity,
lease, candidate revision, and database binding using the existing protected
operator procedure. Saved identity values alone are not current proof. Load
`migrate_shared_auth` from the pinned reviewed source and use the already-verified
PostgreSQL connection with literal loopback host `127.0.0.1` or `::1`,
`autocommit=True`, and no open transaction. Hostnames such as `localhost` are
not accepted, matching the existing operator connection guard.
Both the configured host and libpq's active peer address must be loopback;
a remote `hostaddr` cannot override a loopback host.
The entry rejects other connection modes before querying or changing the database.
Keep credentials out of command arguments and
output. The supported additive entry point is:

```python
result = shared.apply_bound_devbox_claim_mail(
    conn,
    reviewed_revision,
    system_identifier=verified_binding["database_system_identifier"],
    database_oid=verified_binding["database_oid"],
    server_port=verified_binding["database"]["port"],
    database_name=verified_binding["database"]["name"],
    execute=False,
)
```

This call verifies the actual server system identifier, current database OID,
server port and database name, administrator identity and PostgreSQL version. It can only select
this repair. It does not replace the operator's outer host and connection checks.
Every call also verifies the exact ordered signup-evidence baseline written by
the pinned installer CLI. Missing, changed, or reordered baseline statements are
rejected on inspection, application, and replay; staging and production history
rules remain unchanged.
The first write repeats this verification inside the migration transaction after
acquiring the advisory lock, so history changed after the initial check is rejected.

1. Inspect with `execute=False`; require `pending` or `applied`. Stop on drift.
2. On the same verified connection/source/binding, call with `execute=True`.
3. Inspect again with `execute=False`; require `applied`. Record the new receipt
   and confirm that the original receipts and regional history are unchanged.
4. An exact `execute=True` retry is idempotent. Do not retry an unexpected error
   without inspection. Allow the normal worker to retry only after the execution
   owner confirms the target and update; the fixture owner controls any further
   customer-flow testing.

The update admits existing Auth and claim rows. It performs no fixture reset,
provider operation, application deployment, or mail submission. The execution
owner must supply the concrete host-binding harness and source-loading command
for the selected environment before live execution.

## Local regression

Use a disposable local PostgreSQL 17+ administrator URL. The suite creates its
own uniquely named databases and drops only those databases when finished:

```sh
YC_CLAIM_TEST_DATABASE_URL=postgresql://postgres@127.0.0.1:61539/postgres \
  python -m unittest discover -s scripts -p test_yc_claim_mail_migration.py -v
```

Coverage includes both original ambiguity failures, expiry scrubbing, eligible
leasing, row-lock skipping, initialized Auth preservation, both acceptance
orderings, immutable receipts, replay, wrong database binding, unexpected
predecessor/history rejection, and transaction rollback after a snapshot failure.
