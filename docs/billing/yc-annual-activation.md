# YC annual activation

An operator approval reserves a company globally, then records immutable commercial terms in its team's home region. Approval alone does not permit usage. The worker verifies an effective, customer-owned default card before activating billing. It preserves the subscription's original activation anniversary, including when card completion is delayed.

The annual list price remains $12,000. A separate bounded waiver covers the first year's base fee; no payment receipt is fabricated. Monthly allowances are $30,000 for periods 1–3 and $1,000 for periods 4–12. They expire without rollover. CPU, memory, storage and rounding retain full usage exports and their existing invoice reconciliation. Overages remain payable.

## Rollout

1. Apply `supabase/shared-auth-migrations/20261016070000_yc_company_activation_authority.sql` to the shared Auth database using its privileged migration connection. This is a new shared migration, not part of the historical regional aggregate. Record its application in the shared migration ledger. The regional `promotion_evidence_proxy` role receives only the named approval and dispatch-lock RPCs, never table access.
2. Apply `20261016170940_yc_annual_activation.sql` to every billing region before deploying the new API and workers. Existing receipts retain their authority; existing entitlement rows continue referencing payments. No customer backfill is required.
3. Drain older billing workers before approving any YC operation. Old readers cannot deserialize nullable payment authority for YC rows and do not implement waiver recovery. The database fence prevents legacy checkout/promotion activation of an approved YC team, but it does not make old workers YC-capable.
4. Configure `PROMOTION_AUTH_DATABASE_URL` in each region and verify the RPC role. Keep the established invoice-export and usage-entitlement release gates. Deploy all regional workers before enabling YC onboarding; a merged change is not activation readiness.
5. Run the staging checks below. Refresh production preflight immediately before separately authorized production activation. Update the private operator runbook with deployed evidence before removing its activation blocker.

Do not roll back binaries to versions without waiver support after admitting YC teams. Pause new approvals and investigate pending operations while retaining the schema and history.

## Operator procedure

Use the internal operator credential and `X-Actor-User-Id` containing the approving operator UUID. Host credentials and ordinary customer credentials do not authorize these routes. Keep customer IDs, eligibility evidence and responses out of public logs and issue text.

All routes are under `/internal/teams/:team_id/billing/yc/`:

- `POST preflight`: read-only validation of the request below.
- `POST approve`: reserve the canonical company in shared Auth and persist the regional operation. The identical request is repeatable. Commercial terms cannot be changed by retrying approval.
- `POST activate` or `POST reconcile`: drive the saved operation. A pending response includes the failure to resolve; the bounded background worker also retries.
- `GET status`: operation/contract identities, state, customer/subscription, original term, first invoice, payment-method readiness, revocation, last error and next check.
- `POST revoke`: audit global revocation and project it regionally. Stops new YC grants; retains issued credit and historical authority. It does not cancel the annual subscription or erase overages.

Example approval body with synthetic identifiers:

```json
{
  "company_identity": "https://www.ycombinator.com/companies/example-company",
  "merchant_account": "acct_example",
  "live_mode": false,
  "home_region": "test-region",
  "customer_id": "cus_example",
  "subscription_id": "sub_example",
  "existing_subscription_approved": true,
  "eligibility_reference": "operator-evidence-reference",
  "signup_email": "founder@example.com",
  "founder_email": "founder@example.com",
  "email_mismatch_approved": false
}
```

For a new signup omit the customer and subscription values (or use empty strings) and set `existing_subscription_approved` false. Existing subscription conversion is an explicit operator exception, not a general migration option. An email mismatch requires the recorded override and evidence. A company identity is the canonical YC directory URL, never its website, display name or a shared verification link.

Preflight rejects customer/region/account/mode conflicts, concurrent checkout or promotion state, incompatible annual/resource terms, additional subscriptions and unbound live grants. It verifies a genuine zero-dollar discounted annual invoice for an existing subscription. Approval must remain separate from card collection. A mapped YC customer can use an exact-customer portal session before subscription activation; the summary exposes `payment_method_required`. A new operation may need one reconciliation pass to create its customer before this portal is available.

Annual-only adoption adds monthly metered resources with no proration and no reset of the annual anchor. Existing owned grants are discovered and adopted through the shared entitlement machinery rather than topped up. An existing grant may be selected with `existing_grant_id`; preflight verifies its exact customer, current period, full amount and four-price scope and saves its evidence. A depleted grant is adopted without a top-up. If it expires before activation completes, that evidence remains historical and the new period can proceed. An unexpected grant stops adoption for operator reconciliation. Do not delete it or create another grant to bypass this check.

Term-end cancellation is normalized to the original absolute annual boundary so monthly usage items cannot shorten the covered year. Access and eligible monthly grants continue within that term while billing remains current. Revocation preserves already-issued credit until expiry, then usage is payable without new YC allowances. At year end, a continuing subscription must supply a freshly verified paid annual receipt before the separate normal Pro Annual contract becomes active. Stripe owns collection; the transition never creates a second subscription or a duplicate charge.

## Recovery and validation

Inspect `last_error` and the `yc_reconciliation` work metric. For provider timeouts rerun reconciliation using the same operation. Customer/subscription creation retries retain their idempotency keys; unknown outcomes beyond 23 hours stop for operator reconciliation. Grant recovery uses the existing durable uncertain state and inventory scanner. Do not replace operation IDs, immutable evidence, or saved provider requests.

Before live activation, reproduce the annual-only existing customer with a discounted $0 first invoice and no card in staging. Confirm approval succeeds while an actual product create/resume remains blocked. Complete card setup, reconcile, then verify the same subscription/annual anniversary, Pro limits, one correctly scoped grant and successful product usage. Confirm measured usage exports and an overage invoice reconcile. Also validate Accounts v2-backed customer compatibility through its mapped `cus_` representation and the effective payment-method override; never impersonate the customer account as the merchant.

Local tests cover waiver-backed monthly boundaries, no-card gating, grant timeout recovery, revocation and shared-auth RPC permissions. These tests do not replace deployed staging product-action and provider-invoice validation.
