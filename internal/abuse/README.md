# Config-backed restrictions

Set `COMPUTE_RESTRICTIONS_FILE` to an operator-supplied private JSON file on the
control plane. An empty path disables loading. Provisioning and distribution of
the file are separate operational concerns.

```json
{
  "mode": "observe",
  "trusted_teams": ["6c4bd877-6e58-4c97-bb61-d489bb755289"],
  "restrictions": [
    {
      "subject_type": "team",
      "subject_id": "580a748d-84de-4137-9db5-e14d64c59061",
      "actions": ["create", "resume"]
    },
    {
      "subject_type": "fingerprint",
      "subject_value": "opaque-visitor-id",
      "actions": ["signup"]
    }
  ]
}
```

Modes are `off` (also the omitted default), `observe`, and `enforce`. Trusted
teams bypass compute restrictions only. `team` and `user` subjects require a
nonzero UUID `subject_id` and one or more `create` or `resume` actions.
Either legacy action blocks both create and resume and targets active sandboxes
for periodic containment; there is no create-only or resume-only policy.
`fingerprint` subjects require a nonempty, opaque `subject_value` of at most
256 bytes and only the `signup` action. Fingerprint matches are exact and
case-sensitive; they do not affect create or resume. Unknown fields,
unsupported subject/action combinations, and invalid values reject the
candidate config. No promotion, payment, or domain state is interpreted as
trust or a restriction.

Roll out the new file format in stages. Deploy a version that understands
`fingerprint`/`signup` entries to every control-plane reader in every cell,
and confirm no older reader remains, before adding those entries to any
distributed restriction file. Older readers reject the entire file as invalid;
an older reader restarted with that file serves empty/off policy, including
for existing compute restrictions. Before rolling back to an older version,
remove all `fingerprint`/`signup` entries from every distributed file and
confirm the older compatible content is in place before restarting old
readers. Keep existing `team`/`user` entries while removing signup entries.

The file loads at startup and refreshes before each approximately five-minute
containment sweep. Sweeps do not overlap within a process; their duration is
not a pause-completion deadline. `off` does no enforcement, `observe` records
would-pause outcomes without lifecycle changes, and `enforce` claims active
matches through the normal pause path. Starting and resuming sandboxes finish
their transitions and can be targeted on a later sweep. An already-started
pause may finish across file edits; removing a restriction does not resume it.
Valid mode, trust, and
restriction edits replace one immutable snapshot. Any file read/access failure
publishes empty/off state, including after a successful load. Invalid readable
content retains the current snapshot; invalid initial content leaves empty/off
state. Prefer atomic file replacement to avoid publishing a partial edit.

User restrictions match all active canonical `team_owner` assignments, joined
with active team memberships. The refresh resolves these identities from the
database and precomputes team matches. Requests perform constant-time
in-memory lookups and never substitute the requesting user or API-key creator.
Owner changes become effective on refresh. If owner resolution fails, user
matching fails open for that snapshot while explicit team restrictions remain.
Already-running operations are unaffected, and a passed preflight is not
reevaluated during the resulting lifecycle transition. Billing eligibility
continues to apply independently.

With operational metrics enabled, `compute_restriction_decision_total` reports
`allowed`, `would_deny`, or `blocked`, with bounded action, mode, subject type,
and `source=config` labels. `compute_reconciliation_total` reports bounded sweep
and candidate outcomes, including would-pause, pending and confirmed completion.
`signup_restriction_decision_total` reports signup decisions with bounded labels
and no visitor ID. `compute_restriction_refresh_total` reports success,
read errors, invalid content, and owner-resolution errors. Refresh failures also
emit an error log without subject or policy values. An owner-resolution error
can accompany successful publication of the remaining config state.

# Authoritative compute policy

Set `COMPUTE_RESTRICTIONS_SOURCE=database` on **every** control-plane replica
and cell to select the authoritative database projection. The default `file`
retains the behavior above. These are alternative compute authorities; they
are never merged. Signup continues using the file source in either case.
Database policy starts in `off`. Eligible platform abuse administrators can
read or update `/internal/abuse/mode` with `{"mode":"observe"}` or
`{"mode":"enforce"}`. Mode changes use the existing transactional audit and
change record boundary.

The database background writer performs a complete coherent projection every
two seconds, with a ten-second query deadline. The published generation is the
snapshot's maximum committed change ID. Complete replacement handles updates,
release/invalidation, expiry, account membership, and trust revocation without
relying on a gap-free incremental cursor. Only this writer publishes snapshots;
operator mutations write durable state, never a parallel cache. Publication wakes the existing pause reconciler; its five-minute sweep
also catches transitions that finish afterward. At the start of each pause attempt,
the worker rechecks current authoritative team policy. A concurrent operator
edit after that check may race with the normal pause claim. Existing pause claim,
lease, and finalization semantics are preserved. An operation already started
may finish; trust, release, or mode changes never automatically resume a VM.

Explicitly verified teams win over every compute deny. A canonical account
with active membership in a verified team may transfer that exemption to teams
where it has an active canonical `team_owner` role and active membership.
Corporate trust requires a runtime association and Google provider identity
with verified email and matching hosted-domain evidence in `auth.identities`.
Caller-supplied provider/domain strings, editable user metadata, payment status,
and similar email addresses are not proof. When the auth identity table is
absent, corporate inference is unavailable; explicit and confirmed membership
trust still work. Email-domain restrictions use exact normalized owner email
domains, independently of destination domains. A create or resume row blocks
both compute actions. The union of active restrictions applies until every
matching restriction is released or expires. Exact IP subjects remain supported
for signup administration; compute/IP creation is rejected because there is no
authoritative account-to-client-IP mapping. Existing compute/IP rows must be
replaced with confirmed team/user restrictions before this backend is enabled.

Admission retains the existing immutable in-memory lookup, with no new work
in create/resume/start/restore/reattach. The cache admits at most 16,384 denied
teams and retains existing denies before new admissions under pressure. Trust
is outside that eviction budget. Unavailable initial policy and capacity misses
fail open. Failed refreshes preserve the last valid state until authoritative
expiry or one hour since the last successful projection, whichever applies
first. Background maintenance then removes denies and marks negative trust
unknown; sticky positive trust remains exempt until a successful replacement.
This freshness TTL does not delete database quarantine or extend on requests.

Background metrics `abuse_policy_sync_total` and `abuse_policy_cache` report
refresh outcomes, readiness, cache size/capacity, and age of last success with
bounded labels. Failure logs are coalesced and recovery is explicit. Existing
compute metrics label the selected source; signup/file metrics retain `config`.

The shared interfaces also define host observation and receipt contracts.
Host detection and durable incident delivery are separate follow-up changes;
this foundation does not activate mining automation.
