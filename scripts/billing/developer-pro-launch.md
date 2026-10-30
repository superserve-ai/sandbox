# Developer and Pro launch runbook

Launching Developer and Pro is configuration: catalog publishes through the
staff catalog API (`catalog.md`), the trial settings row, and a Stripe
promotion code. No step here is a migration, and no value below is in code.

Rehearse in a disposable dev environment, then configure both production
regions with explicit authorization. Staging gets no operator SQL or
migrations outside normal deploys; after each deploy, only sanity-check it
(the API is healthy and `GET /billing/plans` renders the catalog). Problems
found after go-live are fixed forward; there is no rollback step.

## Inputs

Take the values from the approved launch record. Public values:

| Input | Developer | Pro |
| -- | -- | -- |
| `monthly_fee_cents` | 2000 | 25000 |
| Included credit (`credit_schedule` amount, expires after 1 month) | 2000 | 25000 |
| `funding_policy` | `prepaid` | `postpaid` |
| `topoff` | `amount_cents` 500, `threshold_cents` 200, `default_enabled` true | none |
| `max_concurrent` | 100 | 2000 |
| `max_vcpu` / `max_memory_mib` | 4 / 16384 | 16 / 65536 |

Internal caps are never published, so they are not written here. Pass them
from the launch record: `<disk_mib>` (`max_template_disk_mib` on the plan version), `<developer_templates>`
and `<pro_templates>` (`max_templates`), and `<developer_snapshots>` and
`<pro_snapshots>` (`max_snapshots`, a column that arrives with the snapshot-cap
change; deploy it before this checklist runs in any environment).
The internal limits checklist below confirms they are set.

Trial settings: `credit_usd` 0.05, `max_sandboxes` 1, and from the launch
record `<trial_vcpu>`, `<trial_memory_mib>` and `<trial_disk_mib>`.

## Regions

Production has two regions with separate databases. Every production step
below runs in both, and both must end with the same version ids. The console's
admin plan page writes to every region with one minted version id; when using
the API directly, send the same `id` and `version` in each region's draft.
Before creating a YC code, check the version ids match:

```sql
SELECT family, version, id FROM billing_plan_version
WHERE pricing_version = 'v2' AND state = 'published' ORDER BY family;
```

## Configure

In the dev environment, then in both production regions:

1. Set the trial settings (below), before or together with publishing
   Developer. Until Developer is published, signups keep getting Free.
2. Publish a Pro version with the launch terms: a draft copying the published
   Pro, with the inputs above, then publish.
3. Publish Developer the same way. Check the published row has
   `funding_policy = 'prepaid'` and its top-off columns set; an editor that
   does not send them publishes a postpaid plan. In production, publishing
   Developer is the go-live: from then on every new signup gets the trial.
4. Run the internal limits checklist (below).
5. Check `SELECT billing_paid_first_sellable(), billing_trial_configured();`
   returns `t, t`.
6. Check the version ids match across regions, then create the YC coupon and
   promotion code (below) for the Pro version from step 2.

Production preconditions:

- The end-to-end test passed in the dev environment and the publish is
  authorized.
- The catalog carries snapshot caps, and the Developer and Pro drafts set them.

## End-to-end test

Run in the dev environment before production, and the checks that need no new
signups again in both production regions after go-live:

- A new signup starts on the trial with the configured credit and one sandbox,
  and `GET /billing/plan` reports `entry_state: trial`.
- When the trial credit runs out, sandboxes pause, `entry_state` becomes
  `trial_ended`, the console shows the plan picker, and billing members get
  exactly one "free trial has ended" email. No "running low" email is sent
  during the trial, and none after a paid checkout.
- Developer checkout with Auto Topoff on and with it off both activate. No
  low-credit email arrives before the included grant is issued. With Auto
  Topoff off, the banner shows and the email ("Your credit balance is too low.
  Buy usage to continue running sandboxes.") arrives once when credit falls
  below the low-credit level; with it on, neither appears.
- Pro checkout with the YC code activates with a $0 first invoice.
- A team that signed up on Free before the test keeps its assignment, limits
  and `entry_state: active`. Enterprise still books a call.
- Existing Free teams see the upgrade banner and can buy Developer and Pro.
- Legacy-pricing pay-as-you-go and Starter teams: everything they see and use
  is unchanged, and they are not offered Developer yet (a follow-up). v2 Starter
  teams can buy Developer.
- Cancellation (support-only at launch): staff switch a Developer or Pro team to Free
  with `POST /internal/teams/{team_id}/billing/plan-changes`
  (`target_plan` `free`, `idempotency_key`, `reason`). Check the request is
  accepted and scheduled for the period end, and that at the period end the
  team is on Free with its sandboxes paused, Auto Topoff off and no further
  charges.
- Try the YC code from a Free team that already paid a $0 invoice: Stripe may
  treat it as a returning customer and reject `first_time_transaction`. Record
  the result; such teams need a separate path.

Customer-facing Pro cancellation and the Pro to Developer downgrade ship after
go-live and are tested then.

## Trial settings

`billing_trial_policy` is a single row per region, edited with that region's
privileged database connection:

```sql
\set ON_ERROR_STOP on
BEGIN;
UPDATE billing_trial_policy
SET credit_usd = :'credit_usd', max_sandboxes = :'max_sandboxes', max_vcpu = :'max_vcpu',
    max_memory_mib = :'max_memory_mib', max_disk_mib = :'max_disk_mib', updated_at = clock_timestamp()
WHERE singleton RETURNING *;
SELECT billing_trial_configured();
COMMIT;
```

Pass the values with `psql -v credit_usd=... -v max_sandboxes=... ...`. A team's
credit and limits are frozen when its trial starts; later edits apply to new
signups.

## Internal limits checklist

Run in the dev environment and in each production region after publishing. The snapshot-cap
change must be deployed first, since it adds `max_snapshots`. Every column
must be non-null; fix any null with a new catalog version or trial settings
edit before going live.

```sql
SELECT family, version, max_template_disk_mib, max_templates, max_snapshots
FROM billing_plan_version
WHERE pricing_version = 'v2' AND state = 'published' AND family IN ('developer', 'pro')
ORDER BY family;
SELECT max_sandboxes, max_vcpu, max_memory_mib, max_disk_mib
FROM billing_trial_policy WHERE singleton;
```

## Low-credit messaging

A Developer-style plan's banner and email fire when the balance is below
`billing_funding_policy.low_credit_warning_cents` (100 unless changed) and Auto
Topoff is off. The email names no amount. The trial has no running-low
message: its banner shows for the whole trial and one email goes out when it
ends.

The low-credit email waits for each period's included grant. It stops
waiting when the renewal invoice's collection fails, or
`billing_funding_policy.low_credit_grant_grace` (24 hours unless changed; per
region, editable like the trial row) after the period starts. Email links use the API's `CONSOLE_URL`;
without it the emails carry no link.

## YC promotion code

`yc_promotion_code.py` creates a coupon (100% off, `duration=once`,
`applies_to` the Pro price's product only) and a promotion code limited to
first-time customers with a redemption cap. It previews by default and writes
only with `--apply`; reruns reuse what exists and fail if it differs. It only
accepts the Pro monthly fee price (`commercial_offer` `pro_monthly`, licensed,
monthly, positive amount).

```bash
python3 scripts/billing/yc_promotion_code.py --environment production \
  --expected-account <acct_id> --plan-version-id <pro_version_id> \
  --code <CODE> --max-redemptions <cap> [--apply]
```

In the dev environment, use `--environment staging` with a test-mode key.

The API creates the version's Pro price when it opens the first Pro checkout
session for that version, so open one (it need not be paid) before running
the script. If the API is configured with an explicit Pro price ID that still
matches the fee, pass `--price <price_id>` instead of `--plan-version-id`; that
price must carry the `commercial_offer` metadata. The key comes from
`STRIPE_SECRET_KEY` or `--pass-entry`, and must be a live key for
`--environment production`.

After every new Pro version, including limit-only edits:

1. Deactivate the previous promotion code in Stripe.
2. Run the script with a new code string for the new version. The redemption
   cap starts again from zero, and the new code has to be sent out again.

A version-keyed price has its own product, so the new version needs a new
coupon. A configured Pro price shared across versions keeps one product: the
script then reuses the existing coupon and only the promotion code is new.
