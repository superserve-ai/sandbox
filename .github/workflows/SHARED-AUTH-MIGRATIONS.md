# Shared Auth authority migration

The manual **Apply shared Auth migration** workflow owns the new company authority
schema. Normal deployments continue to apply only regional migrations and preserve
the historical shared Auth aggregate. Do not add new shared versions to
`supabase_migrations.schema_migrations`: the ordinary runner has no matching input
and will refuse subsequent deployments.

Before dispatch, verify the actual project used by each deployed regional
`PROMOTION_AUTH_DATABASE_URL` through the approved secret-safe operational path.
Record only nonsecret target evidence. A staging-named secret does not prove an
isolated staging database. If staging points to production Auth, stop and establish
an explicitly approved scope or isolated staging target before any writes or
activation tests. This workflow does not change runtime configuration.

Select `main`, action `inspect`, the verified target (`staging` or `use4`), and its
verified runtime project. The workflow requires successful push CI for its exact
revision. It selects the existing privileged database connection for that target,
validates the connection's project, and checks existing Auth setup, roles, history,
and catalog. West is not a supported authority target.

After reviewing that result and confirming the target authorization, dispatch
`apply` at the same reviewed revision. GitHub environment approvals and the normal
`database-migrations` queue apply. The executor accepts only the pinned authority
SQL; it has no arbitrary file or SQL input. A short transaction locks the shared
executor, applies the schema, narrows inherited `service_role` grants to the
source's intended SELECT/INSERT/UPDATE access, and verifies RPC permissions. It
stores both original SQL and exact executed SQL (including the fixed ACL
normalization), SHA-256 of the original, source revision, and catalog in the private
`shared_auth_migrations.schema_migrations` ledger. It does not create an approval,
enroll a customer, or modify Stripe.

An identical retry verifies and skips the applied migration. Source/history/catalog
mismatch, an unrecorded existing schema, or an unknown ledger version stops the
executor without repair. After a timeout or uncertain commit, run `inspect` before
retrying. Never infer failure from a missing acknowledgement and replay SQL manually.
Future shared migrations require an explicit executor extension and review; they
must not run through this fixed authority-only operation. SQL containing its own
transaction wrapper needs separate atomicity handling before it can be supported.

Verify `inspect` reports `applied`, regional history is unchanged, and all deployed
regions use the verified RPC authority. Then perform the
[deployed staging activation checks](../../docs/billing/yc-annual-activation.md#recovery-and-validation).
Local database tests establish atomicity, privilege checks and regional-runner
compatibility; they do not establish staging card setup, product access, grants or
overage invoice behavior. Production customer activation remains a separate action.
