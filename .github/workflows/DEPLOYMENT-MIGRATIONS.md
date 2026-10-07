# Deployment migration prerequisites

API, Proxy and Terraform deployments depend on `deployment-migrations.yml`
through native GitHub Actions `needs`. Every invocation applies the complete
migration bundle for its selected revision, including migrations inherited from
earlier commits. There is no current-diff skip or search of migration run history.

The prerequisite requires successful push CI for the migration revision, then
runs staging followed by primary and west production when production is requested.
Environment approvals remain in place. A failed or cancelled prerequisite prevents
deployment. The database concurrency group serializes these calls with manual
migration and recovery operations; callers retain their separate deployment locks.
Overlapping service deployments can run the prerequisite more than once. The
pinned CLI checks existing history and leaves already-applied migrations unchanged.
Setup and database checks still take time on an up-to-date database.

Migration-only pushes enter through Deploy API, or Terraform when infrastructure
also changes. CD Migrate remains a manual workflow for explicit preflight,
migration and recovery operations. Ordinary deployment prerequisites never invoke
recovery or repair migration history.

Explicit branch-only API staging and legacy Proxy staging remain available when
the branch's migration inputs exactly match current main. These calls check main's
push CI and execute main's migration bundle, never branch SQL. A differing bundle
must first be reconciled with main. Production cannot use this exception.

Proxy resumes retain their authenticated original deployment and migration
revision. If the database contains a later migration absent from that bundle, the
CLI refuses the resume without repairing history or rolling back schema. This can
also reject additive newer migrations; refusal does not establish that the schema
is incompatible with the older binary.

Workflow tests exercise dependency failure propagation and revision selection
without cloud access. Disposable PostgreSQL tests verify repeated invocation and
refusal of newer remote history. They do not replace a separately authorized
staging rollout that exercises GitHub environment approvals and deployed secrets.
