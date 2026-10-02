# Recovery-only Stripe Checkout

`POST /stripe/checkout-session/recover` retrieves an existing Checkout without
creating a customer, session, subscription, or replacement Checkout generation.
It uses the same authenticated team, authenticated billing actor, `billing:write`
authorization and live-billing gate as `POST /stripe/checkout-session`.

## Request

Send `{}` (an empty body is also accepted). To restrict recovery to a generation
the caller already knows, send its exact timestamp:

```json
{"checkout_generation":"2026-09-24T18:00:00.123456Z"}
```

The optional timestamp uses RFC 3339, including fractional seconds. Unknown
fields, null bodies, invalid timestamps, trailing JSON values and bodies over 4 KiB are
rejected. Neither actor, team, email nor evidence may be supplied in the body.
When the timestamp is omitted, the backend captures the current generation at
the first read and may recover only that same generation, never a later one.
An explicit null timestamp is equivalent to omission.

## Success

HTTP 200:

```json
{
  "outcome":"recovered",
  "id":"cs_test_example",
  "url":"https://checkout.stripe.com/c/pay/cs_test_example",
  "checkout_generation":"2026-09-24T18:00:00.123456Z"
}
```

Only an open, unexpired subscription-mode session with the original customer,
team reference, actor and generation metadata is recoverable. The local account
must still hold the matching live generation, session ID and immutable evidence
pin. Recovery never substitutes the requesting administrator for the original
actor or changes an entitlement, reservation, evidence pointer or attempt fence.

The Stripe request is a GET of the recorded session ID. After that request, the
backend acquires the promotion gate/user locks and the account row lock, then
revalidates the original tuple and usable state. Completion, abandonment,
expiration or replacement that wins that race makes recovery unavailable.
There is no creation fallback and no replay of a Stripe POST idempotency key.

## Unavailable recovery and errors

An unavailable generation returns HTTP 409:

```json
{"error":{"code":"checkout_recovery_unavailable","message":"no matching recoverable checkout"}}
```

This includes no account/session, an ambiguous create with no durably recorded
session ID, actor/generation mismatch, completed/abandoned/replaced generations,
an expired or mismatched provider session, and a provider 404. It does **not**
prove an ambiguous create never succeeded or authorize clearing its fence.

Other errors remain distinct:

| HTTP | Code | Meaning |
| --- | --- | --- |
| 400 | `bad_request` | Malformed or unsupported request |
| 401/403 | Existing authentication/authorization codes, including `auth_failed` and `forbidden` | Same access requirements as creation |
| 403 | `forbidden` | Billing remains in shadow mode |
| 503 | `service_unavailable` | Recovery transport or captured identity authority unavailable |
| 502 | `bad_gateway` | Provider transport, timeout or response failure other than 404 |
| 500 | `internal_error` | Database/transaction failure |

Do not treat infrastructure failures as a missing generation. A caller that
receives recovery-unavailable must successfully publish fresh trusted evidence
before trying the existing create endpoint. Creation still enforces its own
lease and ambiguity fences and may reject replacement even after publication.

## Identity and rollout

Recovery validates the immutable captured version and its original actor, not
the current evidence pointer or the five-minute observation freshness window.
It therefore remains available after evidence-refresh failure and for aged
pins. A known unverified email does not prevent paid Checkout recovery; promotion
eligibility remains the webhook/claim authority's responsibility.

While canonical enforcement is off, an existing generation with no evidence
pin can be recovered under the same actor/session/generation checks. Once it is
on, a missing or invalid pin fails closed with 503. Recovery never captures new
evidence or enables enforcement.

Deploy this route before consumers use recovery-only behavior. Older API cells
return 404 for the additive route; clients must not fall back to the combined
create endpoint when required evidence publication failed. No migration, Console
switch or production activation is performed by this endpoint.
