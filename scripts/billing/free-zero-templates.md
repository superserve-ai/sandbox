# Free template-cap correction

This is a manual, explicit-target database operation, not an automatic migration
of customer plans. The additive schema migration precomputes immutable allowance
continuity when assignments are inserted; sandbox admission reads only the current
row. Existing rows retain their existing assignment start. It does not publish a
plan or select customer teams.

Before executing:

1. Deploy and verify the console that accepts `max_templates: 0` in the public
   catalog, plan and effective-limit views. Old console parsers reject zero.
2. Apply `20261027060000_free_assignment_continuity.sql` through the normal
   reviewed migration process. Replace all API and worker consumers as required
   by the surrounding billing rollout. Keep public paid entry closed until the
   combined rollout passes acceptance.
3. Obtain approval for the exact environment, source catalog UUID, new catalog
   UUID, operator profile UUID, reason and each team/current-assignment UUID.
   Use the environment's existing privileged database connection without printing
   credentials. No production or development execution is implied by this file.
4. Coordinate a brief billing-write quiet window. Keep normal application locks
   enabled; the helper takes the invoice advisory lock, team row lock and billing
   account row lock. Use a short lock timeout and abort on contention.

The source must be a published v2 Free version with ten templates. Its replacement
copies every commercial/display/allowance/resource term and changes only the
maximum template count. Publication uses the existing lifecycle function and
records draft/publication audit events. Existing versions remain immutable.

Load the session-local helpers and run a dry-run transaction using a fresh,
recorded replacement UUID. Substitute the reviewed UUIDs below:

```sql
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
\i scripts/billing/free-zero-templates.sql
SELECT pg_temp.publish_free_zero_templates(
  :'source_version'::uuid, :'replacement_version'::uuid,
  :'operator'::uuid, :'reason', true);
SELECT pg_temp.transition_free_zero_templates(
  :'team'::uuid, :'current_assignment'::uuid, :'replacement_version'::uuid,
  :'operator'::uuid, :'reason');
-- Repeat the transition only for separately reviewed exact targets.
SELECT * FROM team_effective_limits(:'team'::uuid);
SELECT * FROM billing_free_plan(:'team'::uuid);
SELECT * FROM billing_free_allowance WHERE team_id=:'team'::uuid;
ROLLBACK;
```

Capture before/after catalog, assignment-history and allowance evidence. After a
successful dry run and fresh target checks, repeat the exact operation in a new
session and use `COMMIT` only with the execution authorization. The boolean is an
operator assertion of the console prerequisite, not an automatic deployment check.
The temporary functions disappear with the session; they create no public RPC.

Publication affects new signups immediately. Existing teams retain their frozen
assignment until explicitly transitioned. A transition closes the old assignment
and inserts the replacement at the same timestamp. It preserves frozen terms
apart from version provenance and preserves limits apart from the template cap.
Contiguous Free assignments with the same allowance inherit the immediately
preceding stored floor (or its assignment start for an older row). They retain
the allowance window, usage and blocked-until time. Derived `amount_usd` display
serialization does not change allowance authority or reset continuity. A gap, paid plan, changed
allowance or ambiguous zero-length predecessor stops continuity. The operation
neither deletes existing templates nor interrupts an already in-flight build;
new template creation and new rebuilds are denied by existing API admission.
Existing artifacts remain in the ordinary template list and existing sandboxes
are not paused or deleted by this correction. Sandbox starts still use the normal
Free resource-shape and budget checks; selecting a ready template is separate
from creating/rebuilding one. Platform default templates remain available. The
quota watcher skips nonpositive template caps for alert calculations and performs
no destructive cleanup. Previously created Free-owned artifacts require a
separate operational decision if their future use should also be restricted.

The helper deliberately rejects customized limits, explicit template overrides,
a pause request tied to the current assignment, commercial-contract history, any
Pro operation, any prepaid intent/purchase, or a
subscription/checkout/commercial-anchor fence. It also rejects non-signup/migration
assignments, any frozen terms or limits that differ from the referenced catalog
(including extra fields), and catalog changes beyond this cap. Report such a target as
**blocked**, retaining its payment and customer state, and coordinate a separate
reviewed transition with its owner. Do not cancel pending payment, clear an
override, rewrite accepted quotes or claim all Free accounts have changed.

Replays use the same source/replacement UUIDs and actor/reason. An identical current
transition returns its existing ID; stale identities or a later plan change fail
closed. There is no blanket customer update and no automated rollback to ten
that would rewrite assignment history. Any rollback is another reviewed immutable
version/assignment transition. Verify new signup effective cap zero, existing
explicit targets effective cap zero, API creation/rebuild denial, allowance
continuity and paid/custom-plan preservation before opening public entry.
