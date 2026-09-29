# Authenticated team creation rollout

`POST /internal/teams` requires the existing internal API credential and a
separate, short-lived Console Ed25519 assertion. Set `TEAM_CREATION_REGION` to
the receiving cell (`use` or `usw`) and `TEAM_CREATION_PUBLIC_KEYS` to a JSON
map of key IDs to base64-encoded Ed25519 public keys. The Terraform API roots
for staging `us-central1` and production `us-east4` and `us-west2` expose the
`team_creation_public_keys` input. Its default `{}` keeps this endpoint closed
while leaving legacy provisioning available. Never place a private signing key
in a control plane or Terraform configuration.

Apply the compatible promotion expansion migrations
`20260925195213_promotion_redemption_limits.sql`,
`20260925195235_canonical_promotion_identity.sql`, and
`20260925195248_canonical_stripe_promotion_fences.sql`, plus the additive
`20260928233535_team_creation_requests.sql` and
`20260928233536_team_creation_signup_policy.sql` migrations, in that order,
before enabling API creation. The signup-policy migration defines the
four-argument `create_team_with_signup_trial` function required by the API.
The API writes signed Auth evidence through
`upsert_profile_with_promotion_identity` in the same transaction as creation,
claim, legacy membership, active membership, owner role and completed result.
A missing authority or invalid/stale first-create evidence rolls everything back
and returns `503 provisioning_unavailable`. It never invents a fallback email.

Canonical enforcement starts off and is not an API deployment prerequisite.
The authority decides outcomes under the current gate, including compatible
UUID-based claims during expansion. Alias uniqueness is enforced after activation;
do not claim it is active merely because this endpoint is deployed. All-cell
trusted producer rollout, historical reconciliation and rollback readiness gate
activation separately, as specified by the
[promotion authority](../deploy/promotion-identity-authority.md).
Keep legacy Console provisioning and compatible triggers during expansion.
Trigger removal requires verified API/Console adoption in every affected cell
and a separate contract migration. This change performs no deployment or
activation and does not remove a trigger.

Publish each new public key to all receiving cells before Console signs with it.
During rotation, retain the previous key for at least 150 seconds after the last
old-key assertion, plus deployment propagation time. An empty/invalid key map
closes only this operation. Before switching callers, record each cell's API
revision, migration versions, configured receiving region and accepted key IDs,
then exercise legacy creation, API creation, lost-response recovery and rotation.
No all-cell deployment evidence is supplied by local tests.

Retry uncertain outcomes with the same actor/request/name/region and selected
cell. Recovery only reads actor-owned completed results. Completed create replays
also return the original snapshot without refreshing evidence. Completed records
have no TTL; administrative team deletion leaves a tombstone returning 410.

A name already used by another team returns HTTP 409 with
`{"error":{"code":"team_name_conflict","message":"Team name is already in use"}}`.
The failed creation rolls back all writes and leaves no completed request result.
Do not automatically retry this conflict unchanged. Choosing a different name is
a new explicit intent with a fresh request ID and matching signed assertion.

## Signed identity timestamps and shared fixtures

Create assertions require the exact identity object:

```json
{"email":"user@example.com","email_verified":true,"auth_updated_at":"2026-09-28T12:34:56.123456Z","observed_at":"2026-09-28T12:35:00.000000Z"}
```

Email (string or null), verification and `auth_updated_at` come from the full
trusted authenticated Auth record. Console records `observed_at` when retrieving
that record. Neither browser metadata nor the regional profile is an authority.
Use UTC, exactly six fractional digits, uppercase `T`/`Z`, and years 1970–9999:
`YYYY-MM-DDTHH:mm:ss.ffffffZ`. Pad shorter fractions with zeros. Preserve all six
Auth revision digits; JavaScript `Date` alone loses sub-millisecond precision.
Reject source precision beyond microseconds rather than silently round a revision.
For a millisecond observation clock, convert `.sssZ` to `.sss000Z`.
Offsets, missing fractions, extra precision, null, numeric and infinite values
are invalid. The database authority enforces freshness and source revision
ordering for a new creation; stale evidence cannot prevent completed replay.
Recover assertions omit both `identity` and `policy`.

The shared [protocol vectors](../internal/api/testdata/team_creation_protocol.json)
contain a disposable Ed25519 seed/public key, exact signed claim strings, compact
JWS assertions, request bodies, fixed verifier time, expected verification errors
and prewrite HTTP results. Console must consume the same vectors. `test` and
`next` are overlapping fixture key IDs only. Successful prewrite vectors return
503 in the fixture harness because it has no database; the database suite checks
actual 200 create/recover snapshots, 404 misses, 409 conflicts and 410 tombstones.
`response_shapes` pins the public JSON shapes; promotion outcomes never appear
in successful API responses. Never use the disposable seed in a deployment.
