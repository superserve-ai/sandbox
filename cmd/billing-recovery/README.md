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

`-apply` rechecks Stripe ownership, current active status, and grant
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
