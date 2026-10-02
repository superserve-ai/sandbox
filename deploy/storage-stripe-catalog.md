# Repeatable storage Stripe catalog setup

`scripts/provision_storage_stripe.py` provisions only the shared meter, product,
and monthly price described in [storage billing](storage-billing.md). It never
updates application configuration, customers, subscriptions, credits, usage,
invoices, or activation cutoffs. A successful run is catalog setup, not rollout
validation or permission to enable billing.

## Credentials and definition

Use separate restricted keys for staging and production, stored in `pass`.
The first line of each entry must contain the key. Grant read access to account
identity and read/write access to Billing meters, products, and prices. Preview
needs only the corresponding read permissions. Account identity is checked
against `--expected-account` before inventory or writes; an existing key without
account-read permission will fail this check. Never pass the key on the command
line or put it in the definition file.

Create a local JSON definition containing exactly these fields:

```json
{
  "schema_version": 1,
  "storage_usd_per_gib_second": "REPLACE_WITH_VERIFIED_ACTIVE_DATABASE_RATE",
  "tax_behavior": "exclusive"
}
```

Replace the rate with the canonical active `storage_gib` USD-per-second rate
from the database. The placeholder deliberately fails validation. Do not assume
a migration's seed or a runbook example is the current rate. Use the same
reviewed definition in both environments and verify their database rates agree.
The command converts seconds to hours and dollars to cents using exact decimal
arithmetic, rejecting rates that require rounding beyond Stripe's precision.

Choose `tax_behavior` explicitly to match the intended commercial terms
(`exclusive`, `inclusive`, or `unspecified`). This field does not configure
Stripe Tax or enable tax collection; retain the application's existing tax
setup and review it before billing activation.

## Preview, apply, verify

Run from the repository root with Python 3.10 or later and `pass` installed:

```sh
python3 scripts/provision_storage_stripe.py \
  --definition /path/to/storage-catalog.json \
  --environment staging \
  --expected-account acct_REPLACE_WITH_STAGING_ACCOUNT \
  --pass-entry staging/stripe/catalog
```

Preview is read-only. It reports the exact rate in cents, existing IDs, and
which objects would be reused or created. Once reviewed, run the same command
with `--apply`. The command checks the inventory again, creates only missing
objects, and verifies the resulting catalog. Save its JSON output outside the
repository as the environment's ID receipt. Run preview again; every action
should now say `reuse`.

Validate staging invoices and credits separately. Then repeat preview and apply
with the **same definition**, `--environment production`, the production account
ID, and the production credential entry. Production and staging have separate
object IDs; use each receipt's `ids.price` for that environment's later
`stripe_price_id` configuration. Catalog provisioning itself leaves billing
activation and subscription reconciliation untouched.

## Reruns and conflicts

The command inventories all meters, products, and prices, including inactive
objects, before writing. It stops on incomplete inventory, duplicate storage
objects, mismatched rates, incompatible meters/prices, or the wrong account or
key environment. It reuses a compatible manually created storage meter/price.
A manually created product without a storage price is recognized by the exact
name `Superserve Storage`, the stable product ID, or `billing_resource=storage_gib`
metadata. Review differently named standalone products manually before applying.

The meter uses `storage_gib_hours`, raw ingestion, sum aggregation, and the
application's customer/value payload keys. The script uses a stable product ID,
price lookup key, and deterministic Stripe idempotency keys for creation. If a
request times out or a later creation fails, rerun the same definition: inventory
recovers already-created objects. Do not delete objects to retry. Provider
errors print only endpoint and status; inspect Stripe request logs for details.

Run one provisioning process per account at a time. This tool does not lock out
Dashboard edits or other provisioning tools; coordinate those separately. It
never archives, replaces, or silently repairs conflicting objects. Intentional
rate changes require a separate price migration.

The API version is pinned in the script. References: [meter creation](https://docs.stripe.com/api/billing/meter/create),
[price creation](https://docs.stripe.com/api/prices/create), and
[idempotent requests](https://docs.stripe.com/api/idempotent_requests).

## Local checks

```sh
python3 -m unittest discover -s scripts -p 'test_provision_storage_stripe.py' -v
```
