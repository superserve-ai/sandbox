# Restricted YC capture validation

The ordinary image cannot synthesize YC evidence. A separately reviewed staging
artifact can validate one mismatch capture without consuming another real
company proof. It does not isolate background workers or authorize deployment.

Build the exact reviewed revision with
`docker build -f deploy/yc-staging-validation.Dockerfile -t yc-staging-validation:<revision> .`.
Keep this artifact out of ordinary release/latest tags and the shared
staging-then-production workflow. Do not combine its build tag with the
disposable `yc_verifier_fixture` tag.

Activation requires the existing `superserve-api` Cloud Run service in
`rayai-dev`. The configured validation build checks the actual project through
the metadata server once at startup, with a two-second deadline, and checks
the reserved `K_SERVICE`. No binding means no metadata call. Invalid bindings,
wrong targets or unavailable metadata disable synthetic verification while
normal capture continues using the real verifier.

Any present validation setting, even an empty or unsupported setting in an
ordinary build, disables ordinary broad YC mail startup. A nil/disabled
fixture factory is never permission to start ordinary mail.

Configure one cryptographically random 16-byte lowercase hex run ID in
`YC_STAGING_VALIDATION_RUN_ID`, a normalized controlled customer address in
`YC_STAGING_VALIDATION_EMAIL`, and an RFC3339
`YC_STAGING_VALIDATION_EXPIRES_AT` no more than one hour after startup. The
existing capture credential remains required. Never log that credential or
private proof URLs. The exact fixture URL is
`https://www.ycombinator.com/verify/staging-<run-id>`; its company is
`https://www.ycombinator.com/companies/staging-<run-id>` and its founder address
is `staging-<run-id>@example.test`. The submitted address must differ from that
founder address, producing the normal manual-review path. The same submitted
address must subsequently complete ordinary account email verification.

After capture, record the returned claim UUID. Approval delivery requires
separate activation with `YC_STAGING_VALIDATION_CLAIM_ID` and the still-valid
binding. This starts only approval delivery, using the additive
`yc_claim_approval_mail_rpc('lease-for-claim', ...)` capability with mandatory
`claim_id` and `lease_id`. An old database rejects that operation; never fall
back to broad `lease`. Confirmation delivery and expired-token maintenance
remain off. Check expiry before each lease, but finish an already leased
message using the existing exact claim/message/lease acknowledgement.

The selector accepts only the exact canonical URL and submitted address before
expiry. Other verification URLs retain real provider verification; no request
can supply trusted evidence or change the provider host. Expiry stops new
synthetic verification, not persisted history or credit validity.

Capture precedes fresh account/team creation. Use genuine Google staff login
and normal permission/reauthentication checks. Before sending the decision,
verify the exact claim, company, user, team and current revision; omit company
override. Read back the same binding before customer acceptance. This is an
operational restriction, not a new immutable-company policy. The legacy
operator approval API does not prove approval-email delivery.

Before activation, separately resolve pre-lease mail/expiry-maintenance scope,
the ordinary worker rollout, sender/callback settings, TEST merchant/catalog
and webhook binding, and test-team admission. An empty queue or filtering a
leased job afterward does not establish isolation. Do not enable global
billing flags or change shared data merely to run this fixture. Retain audit
and normal idempotency; never reset a claim/company to repeat validation.

Release the scoped SQL capability before activating delivery. An older binary
ignores these validation settings and may poll broadly if given sender
credentials. A rollback must restore a compatible image/configuration pair or
remove only the test-delivery activation before switching to that old image.
Rollback and sender activation require their own release authority; this
artifact does not grant either.
