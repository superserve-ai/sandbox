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
