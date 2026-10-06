# Prospective storage billing

Storage activation is separate from Stripe subscription provisioning. Deploy the
migration and all cutoff-aware readers before activating any team. Legacy flag
values alone do not enable charges. After activation, do not roll back to a
binary that reads the storage flag without the durable cutoff.

## Preload

Use the [repeatable Stripe catalog setup](storage-stripe-catalog.md) to preview,
create, and verify the shared storage definitions in staging and production.

Use the existing Stripe account and environment. Create or verify one active
Billing Meter with event name `storage_gib_hours`, `sum` aggregation,
`customer_mapping[type]=by_id`, `customer_mapping[event_payload_key]=stripe_customer_id`,
and `value_settings[event_payload_key]=value`. Check the account's full meter
inventory before creating a meter. The meter must use raw ingestion with no
`event_time_window`; hourly or daily pre-aggregation overwrites additive
correction events. This setup is shared across teams.

Create or verify a recurring monthly USD metered price on that meter. Use
`per_unit`, no quantity transformation, and the canonical active `storage_gib`
per-second rate multiplied by 3600 for USD per GiB-hour (multiply by another 100
for Stripe's `unit_amount_decimal` in cents). For example, a rate of
`0.000000030000` USD/GiB-second is `0.000108` USD/GiB-hour, or `0.0108` cents.
Creating a price does not attach it to existing subscriptions.

Configure `stripe_price_id` for the storage entry in `BILLING_RESOURCE_CONFIG`:
`tracked=true`, `subscription_enabled=true`, `billable=false` and
`stripe_event_name=storage_gib_hours`. The legacy `checkout_enabled` spelling is
used if `subscription_enabled` is absent. A legacy two-price installation keeps
compute Checkout available until the storage price is configured. Once configured,
new Checkout sessions include storage even before activation. Do not disable
subscription inclusion after starting preload.

Using the operator token and a platform administrator actor, call the existing
operator-authenticated API for each subscribed team:

```sh
curl --fail-with-body "$API_URL/internal/teams/$TEAM_ID/billing/storage" \
  -H "Authorization: Bearer $OPERATOR_API_TOKEN" \
  -H "X-Actor-User-Id: $ACTOR_ID" -H 'Content-Type: application/json' \
  --data '{"mode":"reconcile"}'
```

Use `mode=verify` for a read-only provider check. The endpoint requires `platform:billing:write` and the normal administrator session checks.

Reconciliation serializes against the current billing-account association and
adds only a missing storage item, with a stable idempotency key and
`proration_behavior=none`. It never creates another subscription or changes the
commercial anchor. Retries inventory items before writing. Missing items in
verify mode, conflicting prices, duplicate items, incompatible intervals, invalid
meter/price configuration and price-scoped grants excluding storage return an
actionable `409 storage_billing_not_ready`. Reconcile conflicts explicitly; the
endpoint never deletes items or changes credit grants. Existing metered-scope
grants include storage automatically. Trial accounts without subscriptions are
not given subscriptions by this endpoint.

Item and grant inventories are limited to 1000 entries each; an incomplete or
oversized inventory fails closed. Limit parallel operator calls to the billing
pool capacity. Each team operation has a 30-second timeout. Stripe reads and
writes hold that team's billing-account lock, so use this bounded operator path,
not a sandbox create/resume hook.

## Activate

Complete the separate retained-storage and provider reconciliation rollout
checks first. Record the approved environment cutoff. Enable that team's
`billing_storage_billing_enabled` flag, then submit:

```json
{"mode":"activate","approved_cutoff":"2026-10-01T00:00:00Z"}
```

Use the actual approved UTC cutoff, not the example date. Activation only verifies
subscription shape; it does not add an item. It atomically records
`effective_at=max(database clock, approved_cutoff)` and verified subscription/price
provenance. Record the returned `effective_at`. Concurrent/repeated calls preserve
the original timestamp. Each later team gets its own prospective timestamp.

An old Checkout session may complete after preload. Verify/reconcile its actual
current subscription before activation. Replacements use the same cutoff;
reconcile their items without recreating activation. Every storage submission
rechecks the current subscription/customer association, meter, price and grant
scope. Provider failures leave the event pending/uncertain in the normal ledger
and expose the error through existing export accounting. CPU/memory submission
remains available. Existing accepted events keep their identifiers.

Raw intervals, hourly rollups, summary resource usage and chart usage remain
tracked. Payable snapshots, costs, trial consumption, export previews and
correction measurements intersect each storage interval with
`[max(window_start,effective_at),window_end)`. Shared retained artifacts keep their
existing distinct-path and quantization semantics. No averaging is introduced.
`1024 MiB * 3600 eligible seconds = 3686400 MiB-seconds = 1 GiB-hour`.

## Delivery holds and recovery

The storage enablement flag authorizes initial activation only. Turning it off
later does not suspend accrual. Pause delivery with the existing
`billing_export_enabled` gate; it pauses all resource delivery. Preserve raw
usage, activation, reservations and accepted events. Resume the normal worker to
export only the eligible unreserved delta. Never reset a cutoff or create new
identifiers for accepted events. Legacy pending storage events created before
activation require operator review and cannot be sent by the storage path.

Keep the existing provider comparison rule; this change adds no tolerance.
Deployment, live meter/price creation, real subscription reconciliation, physical
allocation verification and canary/invoice evidence are separate operational work.
Merging this implementation does not establish production readiness.

Provider request contracts: [subscription item creation](https://docs.stripe.com/api/subscription_items/create)
and [billing credit grants](https://docs.stripe.com/api/billing/credit-grant/object).

### Template allocation evidence

Apply the allocation-provenance migration before deploying the API or VMD
binaries that send `allocations_verified`. The new API accepts old VMD build
reports: a positive allocation remains usable, but a zero without the new
capability remains unknown. Old API finalizers keep working against the new
schema and cannot assert a measured zero. New VMD results persist the capability
only after every declared allocation path was successfully measured; older
persisted build results default to unverified. This does not change build
readiness or the separate publication obligation.

Template manifests record the asserting build/attempt and a database-owned
eligibility time. Existing positive allocations retain their historical
eligibility. Historical zero-valued manifests are unknown regardless of hash.
New evidence, including a changed quantity on the same path, is eligible only
prospectively. A publication with zero or unavailable allocation can preserve
an existing measurement only for its exact build, attempt, and artifact path;
it cannot certify zero on its own. Frozen usage and exported events are not
rewritten, and this migration does not activate storage charging.

The team migration tool refuses to copy team-owned template manifests with
known allocations or measurement evidence. Its generic insert path cannot
preserve their original eligibility timestamps. The refusal occurs before
source fencing or destination copying; keep the evidence intact. Faithful
transfer requires separate migration support.

### Partial legacy storage measurements

Apply the partial-storage migration before deploying its API binary. It adds
nullable completeness metadata without classifying historical cached rows.
Old close and export writers derive the payable quantity and completeness in
one database snapshot, so the schema can precede the binary rollout.

An unknown legacy template contribution is excluded while measured private
storage and other measured shared artifacts remain payable. Full raw storage
usage stays null; summary and series add `known_usage` and
`measurement_status` (`complete`, `partial`, or `blocked`). Platform rows add
`known_storage_mib_seconds` and `storage_measurement_status`. Costs use the
known subtotal after activation. Before activation, payable storage stays zero
while tracked usage can remain partial. Measured zero is complete; unknown is
not a zero measurement.

Receipt, host ownership, retained epoch, and report completion failures still
block settlement. This behavior only isolates missing legacy template evidence.
Shared paths retain their existing union semantics, split at new measurement
eligibility boundaries. No endpoint averaging or historical catch-up is added.

Legacy references are captured without rewriting the sandbox fleet. A template
rebuild preserves its prior fallback for uncaptured old owners. New sandbox
fallback capture requires matching pinned snapshot and memory paths. Template,
base, and delta pins cannot change after sandbox creation. Team migration
materializes source references in both copy and checksum paths; retries retain
the same authority. Reconstructing an unidentified path later cannot change a
previously excluded interval.

Hourly rollups persist the known subtotal separately from nullable full usage.
Consumed export measurements and period close record nullable completeness;
aggregates prioritize partial, then unclassified, then complete. Authoritative closed quantities and completeness remain unchanged, including
imported historical rows. Observation caches still track legitimate corrections
without changing settled quantities or exported events. This migration does not activate storage billing.
