# Billing activation recovery

`billing-recovery` is a read-only audit by default. It looks up the current
Stripe subscription and credit grants, then reports candidates, exclusions,
and unresolved evidence. A processed webhook row is not replayed and normal
webhook deduplication is unchanged.

Audit all incomplete active accounts:

```sh
go run ./cmd/billing-recovery
```

Audit one team without mutating it:

```sh
go run ./cmd/billing-recovery -team <team-uuid>
```

Apply one explicitly targeted repair only after reviewing its dry-run result:

```sh
go run ./cmd/billing-recovery -team <team-uuid> -apply
```

`-apply` rechecks Stripe ownership, current activating status (`active`,
`trialing`, or `past_due`), and grant
ownership, then re-locks and revalidates the local association before writing.
The repair records a subscription-event watermark while holding that lock, so
older delayed webhook deliveries cannot overwrite the recovered projection.
Canceled, replaced, excluded, or uncertain accounts are reported and skipped.
The command is repeatable: an existing verified $95 grant is reconciled
locally, and a missing grant uses the same team-scoped Stripe idempotency key.
Grant evidence must also declare metered applicability. When the local grant ID
is absent, recovery requires the team-scoped activation identity marker; a
category/amount-only grant is reported unresolved rather than guessed.
Production execution remains an operational decision; this command does not
resume sandboxes.

When a subscription-created webhook arrives before its checkout association is
known, the webhook remains unprocessed and returns a retryable error. A
matching checkout completion then reconciles that retained delivery; normal
event-ID deduplication is unchanged.

Recovery requires an existing local customer/subscription association; it does
not import a missing subscription association from Checkout.

A retained checkout reservation is recoverable only when Stripe confirms the
exact session is complete for the current team, customer, and subscription.
Recovery rechecks that proof under the billing-account lock and clears the
reservation in the same transaction as activation. Open, expired, mismatched,
and unproven pending sessions remain skipped. An expired session ID retained
after its reservation was cleared does not block recovery of the existing
subscription and is preserved. Stripe lookup failures are reported as unresolved.

For an explicitly approved custom credit, use `-team <team-uuid>
-activation-credit-cents <positive-usd-cents>` for both dry-run and apply.
The default remains 9500 cents. A custom amount cannot be used for a fleet scan.
Existing grants must match the requested amount and established identity;
unverified promotional USD grants block creation rather than being ignored.
