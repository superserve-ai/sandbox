# Regional database migrations

Use the deployment wrapper for the configured remote databases:

```sh
# DATABASE_URL is supplied by the environment; never print it.
python3 scripts/migrate_database.py use4 dry-run
python3 scripts/migrate_database.py use4 list
python3 scripts/migrate_database.py use4 push
```

Targets are `staging`, `use4`, and `usw2`. The wrapper verifies that the
connection identifies the selected Supabase project, including the project
suffix in pooled connection usernames. All CD migration steps, including
manual workflow dispatches, use this same path. `make migrate-local` remains
for disposable local databases only.

The East project also hosts shared Auth. Its migration history includes
`20261002155220_shared_signup_device_evidence_setup`, originally applied as
one statement assembled from three shared-Auth scripts. The exact historical
SQL is retained under `supabase/shared-auth-history/`, outside the ordinary
regional migration directory. Its source comments and whitespace are part of
the recorded fingerprint; do not regenerate or edit it casually.

For East only, the wrapper checks the existing history version, name,
single-statement count and SHA-256 before adding that artifact to an isolated
temporary migration workdir. It verifies the canonical source hashes and
rejects collisions. A CLI dry run must not propose applying the aggregate.
The subsequent push uses the same files and preserves the existing history.
This recognizes an already completed setup; it cannot initialize shared Auth.

Staging and West use only the ordinary regional chain. Existing Auth tables
do not select an overlay. Missing or mismatched East history, or unexpected
aggregate history in another target, stops migration without changing history.
Route such failures to the database owner; do not mark versions reverted, add
placeholder migrations, use `--include-all`, or replay Auth setup regionally.

Regression coverage uses the actual deployment CLI and disposable Docker
PostgreSQL: `python3 scripts/test_migration_overlay.py`. No live database is
used by these tests.

## Coordinated release

Automatic API, Proxy, and Terraform rollout jobs intentionally stop before
deployment or infrastructure apply when the complete push changes migration
composition, shared-Auth history, or their deployment controls. Mixed changes
also stop, and an unverifiable push range fails closed. CI and CD Migrate remain
independent and can finish. Other automatic releases require successful push CI
at the exact revision in addition to their migration gate.

After verifying successful CI and every target's migrations at the approved
revision, use the normal coordinated manual API, VMD, and Proxy workflows.
Manual dispatch retains the operator's responsibility for those prerequisites.
A held Terraform rollout is not permission to apply infrastructure manually;
route any infrastructure release to its owner. Never race to cancel an already
running deployment as a substitute for the gate.
