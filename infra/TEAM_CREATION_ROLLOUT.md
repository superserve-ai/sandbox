# Authenticated team creation rollout

`POST /internal/teams` requires the existing internal API credential and a
separate, short-lived Console Ed25519 assertion. Set `TEAM_CREATION_REGION` to
the receiving cell (`use` or `usw`) and `TEAM_CREATION_PUBLIC_KEYS` to a JSON
map of key IDs to base64-encoded Ed25519 public keys. The Terraform API roots
for staging `us-central1` and production `us-east4` and `us-west2` expose the
`team_creation_public_keys` input. Its default `{}` keeps this endpoint closed
while leaving legacy provisioning available. Never place a private signing key
in a control plane or Terraform configuration.

Apply the compatible promotion expansion and canonical identity migrations,
configure the global Auth identity bridge, and reconcile historical promotion
identities before enabling a signer. The API checks for a canonical promotion
outcome in the same transaction; an older claim function without that outcome
causes creation to roll back. Keep the legacy Console path and its compatible
triggers during expansion. Removal requires verified Console adoption in every
affected cell and a separate contract migration.

Publish each new public key to all receiving cells before the Console signs
with it. During rotation, retain the previous key for at least 150 seconds
after the last old-key assertion, plus deployment propagation time. A missing
key map disables only this operation. Inspect per-cell deployment configuration,
database migrations, bridge availability, and both legacy and API provisioning
before switching callers. Retry uncertain outcomes with the same request ID and
selected cell; recovery authority only reads completed results.
