# Event credit

This is a manual operation with explicit targets. It gives each listed team the
usage credit amount set on that team's row for an event. Nothing changes for
teams outside the list. Credit goes where the team's plan already looks for it:

| Team state | Route | Credit |
| --- | --- | --- |
| New-signup trial, no plan yet | trial | A new `team_credit_grant` row with reason `signup trial credit` |
| Current Developer or Pro subscription assignment, subscription active, trialing or past due | stripe | A Stripe billing credit grant on the team's customer |
| Free | refused | "upgrade to Developer first" |
| Legacy pay-as-you-go (no plan assignment) or Starter | refused | Unverified, under test |
| Enterprise/custom, or a contract other than a Developer/Pro offer | refused | Handled under its contract |
| Canceled or unpaid subscription, no billing customer, managed billing, missing team | refused | Nothing to credit |

A manual top-up through `POST /billing/prepaid/checkout` is not a way to do this.
That endpoint charges the team's card.

`event_credit.py` is the entry point. It routes teams with a read-only query. It
runs the trial part through `trial-credit-topup.sql` in one transaction. The SQL
can also be run directly against trial teams.

## Input

The input is a CSV of `team_id,amount_usd` rows. A header row is optional.
Amounts are whole cents, above 0 and at most 1000 USD. Amounts can differ per
team. For example, a Developer/Pro team that reached its plan from Free through
a 100%-off Developer checkout gets 80, because its 20 USD of included credit
makes it 100. Other teams get 100. A team listed twice with different amounts is
rejected before anything runs.

The label is the idempotency key per team. A rerun with the same label and amount
reports `already granted` and changes nothing. A rerun with the same label and a
different amount reports `REFUSED: label already granted …` for that team and
adds nothing. `event_credit.py` then exits with status 2, so the mismatch cannot
pass silently. Run directly, the SQL prints the same row and a WARNING. Either
way, fix the CSV, or decide explicitly on a new label.

The check does not depend on the team's current route. Before routing, the
script looks for the team's trial event grant under this label. Paid activation
keeps that row and only zeroes its balance. So a team credited during its trial
that later checks out into Developer/Pro reports `already granted as trial credit`
on rerun, or is refused if the amount differs. It does not get a second grant
in Stripe. The row also shows the trial grant's remaining balance, which paid
activation zeroes. The reverse case cannot arise: paid activation sets
`trial_ended_at`, which makes the trial SQL refuse the team.

## Before executing

1. Get approval for the exact environment, label, and team and amount list. Keep
   the list out of Git.
2. Use the environment's existing privileged database connection. `psql` must be
   on `PATH`. Do not print credentials.
3. For Developer/Pro teams, use the Stripe key from `STRIPE_SECRET_KEY` or
   `--pass-entry`, and name the account with `--expected-account`. A live key is
   refused unless `--environment production` is given, and a test key is refused
   with it.

```sh
python3 scripts/billing/event_credit.py --grants grants.csv --label event-2026-11-01
# Inspect the result, then repeat with the key and --apply:
python3 scripts/billing/event_credit.py --grants grants.csv --label event-2026-11-01 \
  --environment production --expected-account acct_... --apply
```

By default nothing is written. The trial transaction runs, shows what it would
change, and rolls back. Each Developer/Pro customer gets the exact Stripe request
printed. Add `--environment` and `--expected-account` without `--apply` to make
the preview a read-only Stripe check: account, customer and existing labelled
grants, reporting `would grant` or `already granted`. `--apply` commits the trial
transaction and creates the Stripe grants.

`--only trial` or `--only stripe` limits a run to one route. Whoever holds the
Stripe key should run `--only stripe … --apply` rather than paste the printed
request. The script checks the account, the mode, customer ownership and existing
grants. A bare request checks none of those.

To run trial teams directly:

```sh
psql "$DATABASE_URL" -X -v grants='<uuid>:100,<uuid>:80' -v label=event-2026-11-01 \
  [-v commit=yes] -f scripts/billing/trial-credit-topup.sql
```

Each team gets one output row, with these columns:

- amount
- outcome
- grant ID
- trial balance before and after: `get_team_trial_balance` remaining, state and eligible
- whether sandbox admission now passes

After committing, run the same command once more. Every row should read
`already granted` with `after_eligible` true.

## Trial path

Trial credit is the sum of unexpired `signup trial credit` grants, minus usage
since the earliest of them. Trial admission needs four things:

- one such grant with remaining balance
- no `trial_ended_at`
- a cached eligibility verdict that is not false
- no plan assignment

The script adds a new grant with `amount_usd = remaining_usd`, `expires_at NULL`
and reason exactly `signup trial credit`. It never updates an existing grant. The
grant ID is `md5('trial-credit-topup:' || label || ':' || team)`, which makes the
insert idempotent without a schema change. A team that used more than its
original grant receives the new amount less that overage.

An exhausted team's cached verdict in `team_trial_eligibility_cache` is false.
The eligibility sweep (`ListTeamsWithTrialCredits`) rescans such a team only when
it has a grant newer than the verdict. So the script recomputes the verdict in
the same transaction, using the statement from `RefreshTeamTrialEligibility`. The
team is eligible, and `billing_team_entry_state` reads `trial`, as soon as the
transaction commits. The rerun recomputes the verdict again, which repairs a
verdict that a concurrent sweep wrote from an older snapshot. Exhaustion never
sets `trial_ended_at`, so nothing else needs resetting. Sandboxes paused at
exhaustion stay paused until the team resumes them.

These trial teams are refused:

- a current plan assignment
- not enrolled on the new-signup path
- `trial_ended_at` set
- signup trial denied
- claim still pending, because a claim rewrites every signup grant's amount
- no existing signup trial grant

The script locks the billing account rows and then the team rows, the same
order checkout and paid activation use. Paid activation zeroes signup grants and
sets `trial_ended_at` under the billing account lock. Holding that lock means a
grant cannot land beside a paid activation. On contention the transaction stops
at the 5 second lock timeout and can be rerun. Staff YC approval and sponsored
apply lock the team first. If one of them runs against a listed team at the same
moment, Postgres aborts one side as a deadlock within about a second, and that
side can be rerun.

## Stripe path

The grant terms match the funding and invoice checks for credit that the
platform does not own:

- `category=promotional`, `priority=50`, USD cents
- `applicability_config[scope][price_type]=metered`, with no prices
- no `expires_at`
- metadata only `event_label` and `team_id`, and never the reserved keys
  `entitlement_id`, `matching_credit_id`, `prepaid_purchase_id`,
  `pro_upgrade_id` or `activation_identity`

Invoices then apply it after every credit that expires.

Routing reads the plan family from the current assignment. Checkout assignments
carry an offer key such as `pro_monthly` and a contract. A contract qualifies
only when its offer is that family's monthly or annual offer, and its customer
is the team's billing customer.

Before creating a grant, `--apply` checks these:

- the current customer exists in the key's mode
- the current customer's `team_id` metadata, if present, names the team
- whether any customer the team has used already holds a grant, voided or not,
  carrying the same `event_label`

A team whose billing customer was replaced after it was credited is not credited
again. The customers searched are the union of two sources:

- every customer the database recorded for the team. The script finds every
  public table with a `team_id` uuid column and a text `customer_id` or
  `stripe_customer_id` column: the billing account, contracts, invoice accounts,
  usage exports, upgrades, purchases and so on.
- every Stripe customer whose `team_id` metadata names the team, found with
  Stripe customer search

Only grants whose `team_id` metadata names the team count. A grant on the
current customer with the same amount reports `already granted`. A different
amount is REFUSED. A grant on a previous customer is also REFUSED, with exit
status 2. Credit only applies to its own customer's invoices, so the team cannot
use it. To re-grant, void it and use a new label.

The idempotency key is built from team and label only, not the customer or
amount. A second request for the same team and label with any different
parameters is rejected by Stripe and reported as REFUSED. That covers overlapping
runs with different amounts, and a customer replaced between overlapping runs.
Stripe keeps idempotency keys for 24 hours; after that, the label lookup above
is what prevents a second grant. After creating the grant, the script reads it
back and checks it against the terms above.

Just before each create, the script re-reads the team's routing state from the
database. That covers plan, subscription status, contract, current customer and
known customers. If anything differs from the state the run started with, the
team is REFUSED with "billing state changed during the run; rerun" (exit 2) and
nothing is granted. This narrows the window but cannot close it, because no
database transaction can include the Stripe request. A change that commits
between the re-read and the create is not caught. If a team's billing was
changing during the run, compare the report with its current state. Trial grants need no extra check, because their insert
re-checks the team's state under the billing account and team row locks in the
same transaction.

The database keeps no history of `team_billing_account.stripe_customer_id`;
replacing it overwrites the old value. So the database alone cannot list every
past customer. A replaced customer can still be missed when no other billing
table ever recorded it, and either:

- it lacks `team_id` metadata (the API sets it on every customer it creates), or
- that metadata was set within about a minute of the run (Stripe search is
  eventually consistent)

A grant this script created within the last 24 hours is still caught. Its
team-and-label idempotency key makes Stripe reject a request for a different
customer, which is reported as REFUSED.

If a team in the list is known to have changed customers through a path
outside the API, check by hand before `--apply`. In the Stripe dashboard, open
each of the team's customers and look under credit grants for the event label.
The `customers_checked` field of each report row lists what the script searched.

To undo a Stripe grant, void it in Stripe
(`POST /v1/billing/credit_grants/<id>/void`). A rerun then refuses that team's
label, so granting again needs a new label.

To undo a trial grant, delete its row before any usage is billed against it.
Deleting the row frees the label: a later rerun with the same label inserts the
grant again.

## Credit forfeited by upgrading during the trial

When a trial team pays for Developer or Pro, paid activation ends the trial. It
sets `trial_ended_at` and zeroes `remaining_usd` on every signup trial grant,
including event and manual top-up grants. Whatever trial credit was left is
forfeited.
The event copy tells participants that upgrading during the trial drops leftover
trial credit and that staff restore it. Developer participants who check out
with the event's 100%-off first-month code pay the 20 USD monthly fee from their
second month. That is intended: the restored credit pays for usage, not the fee.

### Report

```sh
python3 scripts/billing/event_credit.py --report [--label event-2026-11-01] [--min-forfeit-usd 1]
```

The report is read-only and makes no Stripe calls. It scans every team that has
a `signup trial credit` grant and whose trial ended through paid activation
(`trial_ended_at` set). For each team it computes the total trial credit
forfeited at activation, then keeps the teams whose forfeit is strictly above
`--min-forfeit-usd` (default 1 USD). A forfeit of exactly 1.00 USD is left out
and 1.01 USD is kept. Ordinary signup trials (0.05 USD) fall below the
threshold, so the report shows teams credited for an event and teams given a
manual top-up alike. The event label does not decide who is found. A team that
paid while `trial_ended_at` stayed NULL, which no current activation path does,
would not appear.

`--label` adds a `holds_label_grant` column: whether the team holds that event's
trial grant (the deterministic ID above). `--label-holders-only` limits the
report to those teams. Each row also shows:

- the trial grants and the usage charged against them
- the forfeited amount in cents
- the current plan, subscription status and Stripe customer

The forfeit is the trial balance as it stood at activation, computed by
`trial-forfeit.sql`. It uses the same accounting inputs as
`get_team_trial_balance`, but evaluates every one of them at `trial_ended_at`.
That includes the pricing plan and its rates, chosen by effective dates alone.
Unlike the live helper, it ignores a plan's current `active` flag, which has no
history, so deactivating a plan later does not change the forfeit. It does
not call the live-balance helper, which filters grants by expiry at `now()`. With
that filter, a grant that expired after activation would drop out of the
forfeit.

```text
T         = trial_ended_at
pool      = signup trial credit grants with created_at <= T
            and (expires_at IS NULL or expires_at > T)
grant_usd = sum(pool.amount_usd)
start     = min(pool.created_at)
consumed  = round(cpu_seconds * vcpu_rate + memory_gib_seconds * memory_rate
                  + storage_gib_seconds * storage_rate, 6)
            usage: compute intervals clipped to [start, T]; storage counted only if
            storage billing was active before T
            rates: the team's pricing plan and its rates effective at T
forfeited_cents = floor(max(0, grant_usd - consumed) * 100)
included when forfeited_cents > min_forfeit_usd * 100
```

For example, take a 0.05 USD signup grant and a 100 USD event grant, with 0.07
USD of usage before activation. The team forfeits 99.98 USD.

### Restore

```sh
python3 scripts/billing/event_credit.py --restore --label event-2026-11-01
# Inspect, then:
python3 scripts/billing/event_credit.py --restore --label event-2026-11-01 \
  --environment production --expected-account acct_... --apply
```

Restore recomputes the report with the same threshold and filters. It grants
each team its forfeited amount as a Stripe credit grant on the team's current
customer. The label is the idempotency key: `<label>-restore`, or an explicit
`--restore-label`. Use the same restore label for every run of an event.

A trial ends once, so a team's forfeit is restored once, whatever the label.
Restore grants carry `trial_forfeit_restore` metadata. A team that already holds
an unvoided restore grant under another label is REFUSED (exit 2) and not paid
again. A grant under the restore label without that marker, such as an ordinary
event grant that reused the name, is an idempotency conflict and is also
REFUSED. The reverse holds as well: an event grant run (`--grants`) is refused
if its label holds a restore grant. A forfeit above 1000 USD is refused and must
be restored by hand. Never run two restores at the same time: overlapping runs
under different labels can both grant before either sees the other.

Restore uses the Stripe route above with all its guards:

- the team-and-label idempotency key
- the check across the team's previous customers
- preview by default
- the account and live-key checks

It refuses any team not on a Developer or Pro subscription that is active,
trialing or past due. Forfeits at or below the threshold are never granted. A
rerun reports `already granted`. Every input is evaluated at `trial_ended_at`,
so a team's forfeit only changes if its historical records change, for example
compute intervals recorded late. Just before each create, restore recomputes that
team's forfeit, after re-checking its route. If the amount differs from the one
loaded at the start, the team is REFUSED with "forfeit changed during the run;
rerun" (exit 2) and nothing is granted. A rerun under the same label with a
different amount is also REFUSED rather than granting the difference.

### Event-day routine

Once a day during the event, and once after it ends:

1. Run `--report` and check the list. A team on Free or a canceled subscription
   shows up but cannot be restored until it is on Developer or Pro.
2. Run `--restore` as a preview, then with `--apply`, using the same restore
   label every time.
3. Rerun `--restore` and confirm every row reads `already granted` or a refusal
   you expect.
