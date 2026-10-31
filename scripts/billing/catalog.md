# Editing the plan catalog

Plan prices, included credit, limits, names, card copy, funding policy and
top-off terms are rows in `billing_plan_version`. Changing them is a staff
catalog operation, not a code change or a migration.

## Workflow

Staff with the platform billing write permission use the console's admin plan
page, which calls the staff catalog API:

| Step | Request |
| -- | -- |
| Read the catalog | `GET /internal/billing/catalog` |
| Create a draft | `POST /internal/billing/catalog/plans` |
| Edit the draft | `PUT /internal/billing/catalog/plans/{version_id}` |
| Discard the draft | `DELETE /internal/billing/catalog/plans/{version_id}` |
| Publish | `POST /internal/billing/catalog/plans/{version_id}/publish` |
| Stop selling a family | `POST /internal/billing/catalog/plans/{version_id}/retire` |

Every write takes a `reason` and is recorded in `billing_catalog_audit`.
Published versions are immutable. To change a published plan, create a draft
with the family's current terms plus the change, then publish it. Publishing
retires the version it replaces in the same transaction.

A draft body carries the whole version (placeholders in angle brackets):

```
{
  "pricing_version": "v2",
  "family": "<family>",
  "kind": "subscription",
  "public": true,
  "self_serve": true,
  "display_name": "<name>",
  "price_label": "<label>",
  "tagline": "<tagline>",
  "features": ["<feature>"],
  "sort_order": 1,
  "monthly_fee_cents": <fee_cents>,
  "credit_schedule": [{"start_months": 0, "repeat": null, "every_months": 1, "amount_cents": <included_cents>, "expires_after_months": 1}],
  "limits": {"max_concurrent": <n>, "max_vcpu": <n>, "max_memory_mib": <n>, "max_disk_mib": <n>, "max_templates": <n>},
  "funding_policy": "prepaid",
  "topoff": {"amount_cents": <cents>, "threshold_cents": <cents>, "default_enabled": true},
  "reason": "<why>"
}
```

`funding_policy` is `postpaid` unless set; only v2 subscriptions can be
`prepaid`. `topoff` needs `prepaid`; its amount is a multiple of 500 cents and
its threshold whole dollars from 100 cents, both up to 1,000,000. The publish
body may carry `expected`: the version's terms as last read (a full version
object, or the same fields as a draft body, including `funding_policy` and
`topoff`). A version whose terms differ is rejected rather than published.

Production has two regions with separate databases. Make every write in both,
with the same version `id` and `version` (the admin plan page does this), and
check the published ids match before anything keyed by version, such as the
YC coupon.

## What a publish changes

- `GET /billing/plans` and the `offers[]` of `GET /billing/capabilities` read
  the published rows on every request, so the console shows the new price,
  limits and name without a deploy.
- New checkouts sell the new version. Its Stripe price is created by the API
  on first use (`ensurePlanPrice`), keyed by version, so nobody creates prices
  by hand. When the API is configured with an explicit Pro price ID and the
  fee still matches it, that price is used instead.
- Teams already on the family keep the terms frozen into their assignment.
  Nothing moves them to the new version.
- Auto Topoff uses the top-off amount and threshold frozen into the team's
  assignment. The low-credit email and banner use the configured
  `billing_funding_policy.low_credit_warning_cents`, not the catalog.

## Stripe coupons tied to a version

Every version gets its own Stripe product, so a coupon restricted with
`applies_to` covers only the version that existed when it was created. After
publishing any new Pro version, including a limit-only edit, deactivate the
old YC promotion code and create a new one for the new version (see
`developer-pro-launch.md`). A configured Pro price shared across versions is
the exception: it keeps one product, so only the promotion code changes.
