# Durable YC claims

Claims live in shared Auth, independently of account creation. Regional billing
owns commercial activation. Eligibility approval alone never grants resources,
starts a subscription, or issues credits.

## Deployment

1. Apply `supabase/shared-auth-migrations/20261016174553_yc_claim_authority.sql`
   to shared Auth with its existing `promotion_evidence_proxy` role. Do not apply
   it to regional databases. The role receives only the claim RPC, never tables.
   Use the separately approved shared-Auth executor and its history contract.
   The regional runner does not apply new shared migrations; manually adding
   their versions to its Supabase ledger can block later regional deployments.
2. Apply `supabase/migrations/20261016174554_yc_claim_team_intent.sql` to each
   regional database before deploying claim-binding handlers. It fences plan
   selection and legacy checkout while a claim is being attached.
3. Deploy the billing-owned company authority migration/RPCs before enabling team
   binding. Claim capture and confirmation can deploy first; binding fails closed
   until `reserve_yc_activation_authority` is available. Existing operator approvals
   remain authoritative and are adopted by company/team/region without changing terms.
4. Configure the control plane's existing `PROMOTION_AUTH_DATABASE_URL`. Terraform
   `yc_claims_enabled` defaults off and requires `promotion_evidence_enabled`, an
   HTTPS `yc_claim_console_url`, and a verified `yc_claim_email_from`. Publish
   separate random values of at least 32 bytes for `YC_CLAIM_CAPTURE_TOKEN` and
   `YC_CLAIM_CONSOLE_TOKEN`; neither may reuse internal/operator credentials.
   Populate the dedicated `YC_EMAIL_API_KEY` with a Resend sending credential.
   Terraform creates the dedicated empty containers independently of enablement. Populate their values before enabling claims; the enable flag controls runtime bindings and access, and disabling it preserves the containers. Terraform never manages secret values.
5. Configure the website with `YC_CLAIM_API_URL` (HTTPS control-plane origin) and
   the capture credential. Configure Console with the console credential in every
   serving environment. Both are server-only. Enable the website only after mail
   delivery and Console confirmation have passed the staging test below.
6. Keep the existing-account exception disabled by default. For the single
   separately authorized case, set the exact `YC_EXISTING_EXCEPTION_USER_ID` and
   `YC_EXISTING_EXCEPTION_TEAM_ID` through deployment configuration. Do not put
   customer identities into this repository. Remove the configuration after use.

The website posts its existing verified-claim Slack notification after durable
persistence. A Slack outage does not lose the claim; resubmission retries the
notification and may repeat it. No raw YC verification URL or confirmation token
is included. The mail queue retries with a stable provider idempotency key, a
one-minute lease, bounded exponential delay, and at most eight attempts. Raw
confirmation tokens are restricted to the outbox and cleared after delivery,
confirmation, rejection, revocation, or expiry. Email delivery failures are visible
as `confirmation_status=delivery_failed`; queued delivery is never reported as sent.

## Operator actions

Use `OPERATOR_API_TOKEN` and `X-Actor-User-Id` against the intended home region.
Do not put credentials or confirmation URLs into shell history or audit references.

- `GET /internal/yc/claims/:claim_id` returns evidence, both emails, decisions,
  binding, confirmation status and the last observed billing contract/status.
- `GET /internal/yc/claims?after_id=<last UUID>` returns at most 100 bound claims
  ordered by UUID. Scan all pages on each recovery pass; this is durable discovery,
  not a destructive queue. Each entry includes claim/approval ID, company, user,
  team/region, offer/version, evidence reference, approval method/time and revision.
- `POST /internal/yc/claims/decision` takes `id`, `decision`, `reason` and
  `evidence_reference`. Decisions are `approve`, `reject`, `revoke`, `retry-email`.
  Approval also takes `user_id`, `team_id`, and optionally a canonical
  `company_identity` from current trusted YC directory evidence. Record how both
  possession and company ownership were checked in the reason/reference.
  The authenticated account must have a verified matching submitted email and
  billing permission on the target team's authoritative home region.
- Approving a user that predates the claim additionally requires
  `existing_customer_exception=true` and an exact deployment allowlist match.
  A separately audited attachment to an existing unrevoked operator approval
  for that same company/team/region is also allowed; it preserves the original
  approval and is not a new migration. This does not migrate other prior PAYG/Pro customers. Mismatch evidence and
  original founder email remain immutable.
- `retry-email` only retries an unexpired pending confirmation. Expired claims,
  changed emails, deleted/recreated identities, rejected/revoked approvals and
  uncertain eligibility require manual investigation. Rejected/revoked claims
  cannot be reopened through automatic completion or approval.

For old Slack-only submissions, re-submit the current YC verification through the
normal capture endpoint, then record the original private case reference during
operator approval. A Slack notification alone is never approval evidence.

## Billing handoff and recovery

Admission locks the regional team, billing account and signup choice. It requires
an eligible new team without a committed plan or prior billing state, except for
the explicit operator exception or adoption of an existing operator approval.
Shared preparation pins the exact account/team/region; a regional intent then
commits before the global company reservation. Unknown outcomes retain the local
checkout fence and resume only that exact target. Audited rejection/revocation
uses the returned shared intent and waits for any regional insertion before
releasing plan selection. A successfully rejected claim cannot leave a late fence.

Approval atomically reserves the billing-owned global company/team identity and
stores its stable approval ID with the claim. The normal billing operator approval
adopts that reservation with the same company/team/region. Supply the durable
claim ID and evidence reference; preserve all existing customer/subscription and
commercial terms. A regional failure is retried against the same global approval.
Never create an alternate customer or reset the annual term to recover a claim.

The Console status wrapper checks account ownership and current team billing
permission, then reads `billing_yc_operation` from the home region. It records the
original contract reference and status observation in shared claim storage. Missing
billing code/rows remain pending; outages show unavailable rather than cached active
access. Active access requires active billing state, an unexpired term and the
billing-owned fresh payment-method gate. Payment readiness older than five minutes
is treated as pending. Provider errors are reduced to a review-required state;
provider identifiers, raw errors and billing requests are not exposed to users.

Rejection/revocation calls the shared billing revocation RPC in the same claim
transaction. The global authority lock fences future provider dispatch. An already
in-flight dispatch may finish before revocation returns. Billing owns recovery of
those outcomes and any active-contract consequences; claims never erase history.

Auth email changes and deletions record restricted email-hash tombstones. Binding
holds the current Auth row and checks those facts; account recreation cannot
turn an old customer into automatic eligibility. The Auth trigger never locks a
claim row, keeping lock order compatible with binding.

## Validation before launch

Use synthetic accounts and a disposable local PostgreSQL instance:

```sh
YC_CLAIM_TEST_DATABASE_URL=postgres://postgres@127.0.0.1:62225/postgres \
YC_AUTHORITY_TEST_MIGRATION=/path/to/billing-authority-migration.sql \
go test ./internal/ycclaims ./internal/api -run 'TestYC|TestClaim|TestProvider|TestVerification'
```

Tests create/drop their own database, never reset the supplied database. The billing
migration path deliberately uses the real separately owned authority contract.
Run website submission tests and Console confirmation/auth-callback tests too.

Before enabling production capture, staging must exercise matching confirmation,
normal signup/login, explicit team selection, operator mismatch approval, duplicate
company rejection across regions, email retry, billing outage/recovery, previous
operator approval adoption, and revocation during dispatch. Complete the billing
activation and verify the actual payment gate and product access. Local claim tests
alone do not prove provider activation. This change does not execute that rollout.

Teams with any YC claim intent, including released history, are blocked by migrate-team before cutover. Moving them requires a coordinated shared company authority transfer, which is outside this rollout. A migration already fenced in the source rejects new YC binds.
