# Shared Auth on an isolated devbox

The normal devbox installer applies regional migrations and the canonical
`20261002155220_shared_signup_device_evidence_setup` baseline. It does not
apply the later shared company, claim, staff-approval and acceptance migrations.
Use `scripts/migrate_devbox_shared_auth.py` for those four migrations, before
creating any Auth users. The staging/use4 CLI and its remote project guards
remain unchanged.

The deployment executor prepares a root-owned, non-writable-by-group/others JSON
binding from the devbox lease, provider identity and read-only database snapshot:

```json
{
  "purpose": "disposable-shared-auth-bootstrap",
  "project": "PROJECT",
  "zone": "ZONE",
  "instance": "devbox-NAME",
  "instance_id": "NUMERIC_INSTANCE_ID",
  "devbox_id": "TWELVE_HEX_DIGITS",
  "run_id": "NUMERIC_RUN_ID",
  "expires_at": "LEASE_EXPIRY_UTC",
  "candidate_revision": "FORTY_CHARACTER_CANDIDATE_COMMIT",
  "database": {"host": "127.0.0.1", "port": 54322, "name": "postgres"},
  "database_system_identifier": "READ_FROM_PG_CONTROL_SYSTEM",
  "database_oid": "READ_FROM_PG_DATABASE",
  "source_sha256": {
    "authority": "CANDIDATE_COMPANY_SQL_SHA256",
    "claims": "CANDIDATE_CLAIM_SQL_SHA256",
    "approvals": "CANDIDATE_APPROVAL_SQL_SHA256",
    "acceptances": "CANDIDATE_ACCEPTANCE_SQL_SHA256"
  }
}
```

Populate hashes from the exact selected candidate's four files in
`supabase/shared-auth-migrations`, not from a branch name. The script also
checks each source against the migration engine's pinned hashes. The tool
checkout may be a separately reviewed follow-up commit; its four migration
sources must match the candidate binding exactly.

Run from the reviewed tool checkout on the assigned VM as root. Install the
repository's pinned `scripts/migration-requirements.txt` in an isolated Python
environment, and use that exact interpreter for all subsequent commands:

```sh
python3 -m venv /opt/superserve-devbox/shared-auth-venv
/opt/superserve-devbox/shared-auth-venv/bin/python -m pip install -r scripts/migration-requirements.txt
/opt/superserve-devbox/shared-auth-venv/bin/python -I -c 'import psycopg'
```

Supply the existing local **postgres migration** connection in
`DATABASE_URL` through the executor's secret environment mechanism; do not use
the runtime `promotion_evidence_proxy` connection or print either URL. Unset
libpq service configuration (`PGSERVICE`, `PGSERVICEFILE`, `PGSYSCONFDIR`).

```sh
/opt/superserve-devbox/shared-auth-venv/bin/python -I scripts/migrate_devbox_shared_auth.py inspect \
  --binding /etc/superserve-devbox/shared-auth-binding.json \
  --revision TOOL_COMMIT
/opt/superserve-devbox/shared-auth-venv/bin/python -I scripts/migrate_devbox_shared_auth.py apply \
  --binding /etc/superserve-devbox/shared-auth-binding.json \
  --revision TOOL_COMMIT
/opt/superserve-devbox/shared-auth-venv/bin/python -I scripts/migrate_devbox_shared_auth.py inspect \
  --binding /etc/superserve-devbox/shared-auth-binding.json \
  --revision TOOL_COMMIT
```

Use the literal full tool commit. Save all three JSON results with the candidate
build and deployment receipts. No output contains connection credentials.
The `-I` option is required: repository helpers load directly from the selected
Git commit, while other imports come from the isolated Python environment.
Git reads use `/usr/bin/git` with a restricted environment, executable hooks and
network transports disabled. Source comparison uses raw file bytes, avoiding
worktree content filters. The four SQL files retain their pinned SHA-256 checks.

The guard compares Google metadata with the lease binding and installed
`/var/lib/superserve-devbox/runtime.json`, and checks `DEVBOX_ID` in
`/etc/superserve-devbox/devbox.env`. The database connection is restricted to
the local port contract, the bound PostgreSQL cluster identifier/database OID,
and an un-switched `postgres` session on PostgreSQL 17 or newer.

The existing Auth schema, signup evidence, four required roles and exact
canonical baseline history must already exist.
The baseline receipt must be the exact ordered statement array written by the
installer's pinned Supabase CLI 2.119.0; the historical use4 receipt is different.
The proxy role must retain its restricted attributes and have no memberships
except the `postgres` creator's administrative grant with inheritance and
role switching both disabled. Missing or drifted
prerequisites are errors; this tool does not invent history, create Auth users,
set passwords, reset schemas, repair roles, enable billing flags or start the API.

Apply holds the shared migration mutex and an Auth-user table lock, verifies
there are no users, and applies all pending shared migrations in one outer
transaction. Each schema change keeps its existing immutable receipt, source
hash, catalog and permission validation. Any failure rolls back this invocation;
regional migration history stays unchanged. An interrupted acknowledgement can
be inspected and replayed while the database is still empty. After fixture
signup begins, use read-only `inspect`; `apply` intentionally refuses a nonempty
Auth database, even if the migrations already exist.

The deployment executor alone runs these commands after reviewing the exact
target binding. Integration-test schema reset helpers and staging/use4 target
aliases are not substitutes for this procedure.
