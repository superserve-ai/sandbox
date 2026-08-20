# Implementation packet: dual Stripe webhook signing secrets

## Goal

Support the two Stripe event destinations used by billing:

1. **Snapshot lifecycle destination** for Checkout, subscription, and invoice events.
2. **Thin meter-error destination** for `v1.billing.meter.error_report_triggered`.

Stripe assigns each destination a different `whsec_...` signing secret. Both destinations post to the same Superserve `/stripe/webhook` handler, so the handler must authenticate requests against both configured destination secrets while preserving existing webhook idempotency and processing behavior.

## Branch

The feature branch used for this implementation.

Started from `main` at `cbfd7b5e8673027f43378520e36f31d3cd27bc16`.

## Implemented on this branch

### Configuration

`internal/config/config.go`

Added:

```go
StripeMeterErrorWebhookSecret string // STRIPE_METER_ERROR_WEBHOOK_SECRET
```

and load it from:

```text
STRIPE_METER_ERROR_WEBHOOK_SECRET
```

Existing `STRIPE_WEBHOOK_SECRET` remains the snapshot/lifecycle destination secret for backwards-compatible naming.

`.env.example` documents both values and their roles.

### Signature helper

Added `internal/api/stripe_webhook_secrets.go` with `verifyStripeWebhookSignatureWithSecrets`.

The helper:

- ignores empty values;
- accepts a signature valid for either configured Stripe destination;
- fails closed when neither secret is configured;
- fails when the signature matches neither configured secret;
- delegates the actual timestamp/HMAC validation to the existing `verifyStripeWebhookSignature`, so existing tolerance and parsing semantics stay unchanged.

### Unit tests

Added `internal/api/stripe_webhook_secrets_test.go` covering:

- snapshot secret accepted;
- thin secret accepted;
- unknown secret rejected;
- no configured secrets fails closed.

These tests provide focused coverage for both destination credentials and
fail-closed behavior when no credential is configured.

## Handler behavior

`internal/api/handlers_billing_stripe.go` accepts either configured destination
secret before parsing or processing the event. It retains the existing body
limits, event validation, idempotency, processing, and response semantics.

Conceptually:

```go
func (h *Handlers) HandleStripeWebhook(c *gin.Context) {
    if h.Config == nil ||
        (strings.TrimSpace(h.Config.StripeWebhookSecret) == "" &&
            strings.TrimSpace(h.Config.StripeMeterErrorWebhookSecret) == "") {
        respondErrorMsg(c, "service_unavailable", "Stripe webhook secrets are not configured", http.StatusServiceUnavailable)
        return
    }

    // existing body-size/read logic stays unchanged

    if err := verifyStripeWebhookSignatureWithSecrets(
        payload,
        c.GetHeader("Stripe-Signature"),
        h.nowUTC(),
        h.Config.StripeWebhookSecret,
        h.Config.StripeMeterErrorWebhookSecret,
    ); err != nil {
        respondErrorMsg(c, "unauthorized", "invalid Stripe webhook signature", http.StatusUnauthorized)
        return
    }

    // all existing event parsing/idempotency/processing remains unchanged
}
```

Do **not** change `expandStripeThinMeterEvent`: it already recognizes `billing.meter.error_report_triggered` / `v1.billing.meter.error_report_triggered` and retrieves the full V2 event when the thin payload has no embedded `data.object`.

## Integration coverage

`internal/integration/billing_stripe_integration_test.go` defines separate
snapshot and thin fixture secrets and supplies both fields to `config.Config`.

The integration fixtures configure separate snapshot and thin secrets, sign
each destination's events with its corresponding fixture, and assert that an
unknown signature receives HTTP 401. Snapshot lifecycle behavior and thin-event
expansion remain covered through the real HTTP handler.

## Terraform / Secret Manager wiring

### Staging

`infra/envs/staging/us-central1/main.tf` creates and mounts:

- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`

The second Secret Manager secret for the thin destination uses the existing
naming pattern:

```text
stripe-meter-error-webhook-secret-${local.resource_suffix}
```

It is wired to the API runtime by:

- grant the API service account `roles/secretmanager.secretAccessor`;
- mount it into the API module as `STRIPE_METER_ERROR_WEBHOOK_SECRET`;
- add the IAM resource to the API module `depends_on` alongside the existing Stripe secret dependencies.

Do not replace the existing `STRIPE_WEBHOOK_SECRET`; it remains the snapshot secret.

### Production USE and USW

Production billing is cell-scoped. Stripe has four production webhook destinations:

- USE snapshot
- USE thin meter-error
- USW snapshot
- USW thin meter-error

Therefore production requires **four webhook secret values**, two per cell. Stripe does not route customers to a cell: both cell destinations can receive matching account events, and each cell's application/database must ignore customers it does not own as it does today.

Production API module blocks mount the cell-specific snapshot and thin secret
references. Secret values remain provisioned out-of-band in Secret Manager.

The production Terraform modules reference these exact Secret Manager names:

```text
# USE cell
stripe-webhook-secret-use
stripe-meter-error-webhook-secret-use

# USW cell
stripe-webhook-secret-usw
stripe-meter-error-webhook-secret-usw
```

The actual `whsec_...` **values are intentionally not in this branch or packet**;
they are provisioned as Secret Manager versions out-of-band and never committed
to Git.

## Production secret provisioning

Provision the four production webhook signing secrets out-of-band, two per
cell (snapshot and thin). Do not commit secret values or infer unrelated Stripe
price or meter identifiers from rollout notes.

```text
USE snapshot whsec
USE thin whsec
USW snapshot whsec
USW thin whsec
```

## Validation

The implementation was formatted and validated with:

```text
gofmt -w internal/config/config.go internal/api/stripe_webhook_secrets.go internal/api/stripe_webhook_secrets_test.go internal/api/handlers_billing_stripe.go internal/integration/billing_stripe_integration_test.go

go test ./internal/api/...
make test-integration
terraform fmt -check -recursive infra
```

After deployment, verify from Stripe:

1. Snapshot `customer.subscription.updated` receives HTTP 200.
2. Thin `v1.billing.meter.error_report_triggered` receives HTTP 200 and the handler retrieves the full V2 event.
3. A bad signature receives HTTP 401.
4. Duplicate webhook IDs preserve existing idempotent `duplicate` behavior.
5. Existing subscription/invoice state transitions are unchanged.

## Important design constraints

- Do not combine the two `whsec` strings into one comma-delimited secret. Keep them as independently rotatable configuration values.
- Do not persist signing secrets in the database.
- Do not branch business logic based on which secret matched; the secret authenticates the Stripe destination, while event type continues to determine processing.
- Do not alter existing webhook-event idempotency/retry semantics as part of this change.
- Do not add the production `whsec_...` values to Terraform source, `.tfvars`, tests, docs, or the implementation packet.

## Current completion state

Configuration, dual-secret verification, handler integration, unit and
integration coverage, and staging/production Secret Manager wiring are
implemented. Live secret population and post-deploy Stripe checks remain
operational steps and are intentionally not represented by values in this
repository.
