# Config-backed compute restrictions

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
    }
  ]
}
```

Modes are `off` (also the omitted default), `observe`, and `enforce`. Trusted
teams bypass all restrictions. Subjects are `team` or `user` UUIDs; each entry
requires at least one action, `create` or `resume`. Unknown fields, unsupported
values, and invalid UUIDs reject the candidate config. No promotion, fingerprint,
payment, or domain state is interpreted as trust or a compute restriction.

The file loads at startup and every five minutes. Valid mode, trust, and
restriction edits replace one immutable snapshot. Any file read/access failure
publishes empty/off state, including after a successful load. Invalid readable
content retains the current snapshot; invalid initial content leaves empty/off
state. Prefer atomic file replacement to avoid publishing a partial edit.

User restrictions match all active canonical `team_owner` assignments, joined
with active team memberships. The refresh resolves these identities from the
database and precomputes team/action matches. Requests perform constant-time
in-memory lookups and never substitute the requesting user or API-key creator.
Owner changes become effective on refresh. If owner resolution fails, user
matching fails open for that snapshot while explicit team restrictions remain.
Already-running operations are unaffected, and a passed preflight is not
reevaluated during the resulting lifecycle transition. Billing eligibility
continues to apply independently.

With operational metrics enabled, `compute_restriction_decision_total` reports
`allowed`, `would_deny`, or `blocked`, with bounded action, mode, subject type,
and `source=config` labels. `compute_restriction_refresh_total` reports success,
read errors, invalid content, and owner-resolution errors. Refresh failures also
emit an error log without subject or policy values. An owner-resolution error
can accompany successful publication of the remaining config state.
