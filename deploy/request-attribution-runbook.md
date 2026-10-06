# Request attribution and endpoint inventory

The control API and sandbox operation proxy emit structured, content-free
request records. These records describe physical attempts, including denials;
client retries are separate attempts. They are not historical audit records.

## Identity contract

| Field | Meaning |
| --- | --- |
| `service`, `plane` | `sandbox-api` / `control`, or `proxy` / `data` |
| `actor_type`, `actor_id` | Verified actor kind and principal ID, when known |
| `credential_id` | Non-secret credential record ID; API keys also retain `api_key_id` |
| `user_id` | Verified human, never inferred from key creator or sandbox owner |
| `team_id` | Authenticated caller's team, when known |
| `resource_team_id`, `sandbox_id` | Resolved target team and requested sandbox ID; neither proves caller identity |
| `auth_outcome` | `authenticated`, `missing`, `invalid`, `error`, `not_evaluated` |
| `authorization_outcome` | QM authorization decision: `allowed`, `denied`, `error`, `not_evaluated`; absent on other routes |
| `attribution_status` | `identified`, `sandbox_only`, `unavailable`, `error` |
| `delegated_by` | Authenticated actor kind that supplied a verified human assertion |
| `route`, `method` | Matched route template and HTTP method; unknown targets are `__unmatched__` |

Ordinary API keys use the key record ID as their principal and credential ID.
Their creator is not treated as the current human. Authenticated service and
operator shared tokens identify a role but no individual (`unavailable`). A
human assertion is accepted only behind its existing authenticated internal
boundary or signed assertion verifier. Authorization denials retain identities
that already passed authentication. `not_evaluated` includes public routes and
requests rejected before authentication; it does not mean invalid credentials.
The QM authorization route retains its existing HTTP 200 response for policy
denials; use `authorization_outcome` to distinguish those from an allowed
decision. A rejected human proof retains the verified API-key identity without
asserting a human; authorization remains `not_evaluated`.

Legacy sandbox access tokens prove sandbox access only. They emit
`actor_type=sandbox_capability`, `auth_outcome=authenticated`, and
`attribution_status=sandbox_only`, with no fabricated actor, credential, user,
or caller-team ID. Resource-team context is present after the existing resolver
succeeds. A requested sandbox ID can also appear on failed authentication and
must not be treated as verified resource ownership. No extra lookup is made
for logging. Exact key/person attribution on this path requires the verified capability
contract below; legacy tokens do not acquire it retroactively.

Queries, arbitrary path parameters, headers, credentials, command arguments,
environment, terminal frames, file contents and error-body snippets are omitted.
The API's `path` may retain validated UUIDs only in known identifier parameters;
tenant-chosen names stay redacted even when UUID-shaped. Region-prefixed sandbox
IDs are normalized to the same UUID used in `sandbox_id`. Use `route` for grouping.
Existing API client-IP behavior is unchanged; it is not identity evidence.

## Events and measurement

* `request`: one completed ordinary request, or a stream rejected before establishment.
* `session_start`: prompt establishment event for exec streams, exec WebSockets,
  terminals and desktop streams. This is the primary inventory event for a session.
* `session_complete`: correlated closure, duration and outcome; not another call.
* `proxy_forward`: edge transport completion for a request sent to an owner proxy.
  The owner emits the primary event. Join on `request_id`, not sandbox or time.

The proxy generates request IDs and carries them only over the private peer
boundary. Public correlation and identity headers cannot supply attribution.
Control API events do not currently share these proxy IDs.

`status` is an observed HTTP status, not a process exit code. A 101 upgrade or
200 stream does not establish command success. `process_exited` records an
observed process exit, including nonzero exits. `closed` means the transport
ended without a more specific observed outcome. `transport_error`,
`upstream_error`, `invalid_request`, `canceled` and `aborted` distinguish other
observed endings. Process termination can prevent a completion event entirely.

`latency` uses the existing millisecond duration encoding. Completion measures
the full request/session; start measures time to establishment. `body_size`
counts response-body bytes accepted by the HTTP writer, not request or wire
bytes. It is omitted after hijacking; API unwritten responses retain Gin's
existing `-1` sentinel. No events are emitted per frame or content chunk.

## Locate the deployed sink first

Control API stdout is collected by Cloud Run into Cloud Logging. Both services
emit the recognized `severity` field alongside the existing `level`. Proxy stdout
goes to journald (`proxy.service` or `proxy-<generation>.service`). Cloud Logging
queries for proxy records require the host's existing log collector to forward
and parse that JSON. Confirm one known request from **each** plane reaches the
selected sink before interpreting an empty query as absence of traffic. Check
every serving revision/host; a mixed rollout gives an incomplete inventory.

The current host collector allowlist does not yet preserve the attribution
fields or numeric status/latency. Central inventory requires a collector
contract update; the source logging deployment can proceed independently.
Until field preservation is verified, use the journal export below.

If proxy collection is unavailable or drops required fields, export on each serving host for the same
UTC interval and retain host/generation alongside the export:

```sh
journalctl -u proxy.service -u 'proxy-*.service' \
  --since '2026-01-01 12:00:00 UTC' --until '2026-01-01 12:10:00 UTC' \
  --output=cat --no-pager |
  jq -Rc 'fromjson? | select(.plane == "data" and .event_type != null)' > proxy-events.jsonl
```

Field-preserving central collection is a prerequisite for central queries, not proof that
the workload used no data-plane endpoints. The separately deployed QM management
service must document its own actual sink and verified human attribution; do
not assume an AWS service is collected into Cloud Logging.

## Queries

In Logs Explorer, replace the synthetic IDs and UTC bounds. Also constrain the
project and deployed environment using its actual resource labels. Principal
or credential to routes:

```text
timestamp >= "2026-01-01T12:00:00Z"
timestamp < "2026-01-01T12:10:00Z"
jsonPayload.service = ("sandbox-api" OR "proxy")
jsonPayload.event_type = ("request" OR "session_start")
(jsonPayload.actor_id = "PRINCIPAL_ID" OR jsonPayload.credential_id = "CREDENTIAL_ID")
```

Route and caller/target team to principals:

```text
timestamp >= "2026-01-01T12:00:00Z"
timestamp < "2026-01-01T12:10:00Z"
jsonPayload.service = ("sandbox-api" OR "proxy")
jsonPayload.event_type = ("request" OR "session_start")
jsonPayload.route = "/sandboxes/:sandbox_id/pause"
(jsonPayload.team_id = "TEAM_ID" OR jsonPayload.resource_team_id = "TEAM_ID")
```

Copy the exact route template from the deployed record. Keep `team_id` and
`resource_team_id` separate in results. For legacy data-plane inventory, replace
the identity clause with `jsonPayload.sandbox_id = "SANDBOX_ID"` and
`jsonPayload.resource_team_id = "TEAM_ID"`. For the correlated export, filter
by sandbox alone: unresolved failures and edge forwarding events lack a
resource team. Label this export **sandbox-only**, even
when the controlled workload used a known API key on the control plane.

Save the selected filter as `inventory.filter`, including **all four** event
types when correlating sessions and forwarding. Export without a finite limit:

```sh
gcloud logging read "$(cat inventory.filter)" --project=PROJECT_ID \
  --order=asc --format=json > inventory.json
jq -c '.[] | .jsonPayload' inventory.json > events.jsonl
```

If collecting proxy records from journald, concatenate those JSONL files with
the control export. Do not import the same proxy records from both sinks.
For a bounded workload whose requests have finished, group primary records by
service, plane, method, route, identity and status. Include forward-only records
as explicitly incomplete observations, so a failure before reaching the owner
does not disappear:

```sh
jq -s '
  [.[] | select(.event_type == "request" or .event_type == "session_start")] as $primary |
  (reduce $primary[] as $e ({}; if $e.request_id then .[$e.request_id] = true else . end)) as $seen |
  ($primary + [.[] | select(.event_type == "proxy_forward" and ($seen[.request_id] != true))]) |
  group_by([.service, .plane, .method, .route, .actor_type, .actor_id,
            .credential_id, .team_id, .resource_team_id, .status, .authorization_outcome, .outcome, .event_type]) |
  map({service: .[0].service, plane: .[0].plane, method: .[0].method,
       route: .[0].route, actor_type: .[0].actor_type, actor_id: .[0].actor_id,
       credential_id: .[0].credential_id, team_id: .[0].team_id,
       resource_team_id: .[0].resource_team_id, status: .[0].status,
       authorization_outcome: .[0].authorization_outcome,
       outcome: .[0].outcome, event_type: .[0].event_type, attempts: length})
' events.jsonl > endpoint-inventory.json
```

An unmatched `proxy_forward` may mean an owner-side failure, missing collection,
an older owner revision, or a start event outside the export window. Keep it
marked as forward-only; a hijacked bridge may not know the HTTP status. Expand
the window to include establishment and completion before declaring inventory
complete. Sessions still running and events lost to process termination remain
explicitly incomplete. Inspect `session_complete` by `request_id` separately
for final outcome and duration.

Query syntax: [Cloud Logging filters](https://docs.cloud.google.com/logging/docs/view/logging-query-language)
and [export command](https://docs.cloud.google.com/sdk/gcloud/reference/logging/read).

## Required staging evidence

After deployment, record privately: environment, both service revisions, proxy
hosts/generations, UTC interval, non-secret key record ID, sandbox/team IDs,
sink queries, and the resulting inventories. Run a real staging workload that
includes a turn, process/command execution, file access, terminal/stream use,
and lifecycle operations. Include local and peer paths, a denial, and a stream
that closes or is canceled. Check each observed operation against its primary
event and any completion event.

Use synthetic secret markers in test requests/content to check the actual sink
for leaks; never paste real credentials into evidence. Preserve representative
redacted records and check the server still returns the original content.
Record control-plane key attribution and data-plane sandbox-only observations
as separate evidence. This baseline does not establish final machine attribution
or human QM-management attribution, and local tests do not replace this deployed
workload verification.


## Verified machine integration

The logging adapter consumes the identity authority's `CallerContext` only
following credential/capability verification. See the
[machine identity contract](../docs/runbooks/hosted-machine-identity.md) for
issuance, expiry, revocation and authorization. Logging does not add an
authority lookup or change permission checks, HTTP responses or stream limits.

The integration is preparatory until that authority's consumer contract and
rollout are accepted. In particular, the current capability kind `human` does
not establish session provenance: its producer can use an API key's creator.
For those capabilities, logs use the verified parent credential as an
`api_key` actor, omit `user_id`, and never substitute the target machine owner.
Missing required identity references produce `attribution_status=error`.
A separately verified human discriminator must come from the identity owner
before these data-plane records may claim human attribution.

| Observation | Log interpretation |
| --- | --- |
| Machine authentication succeeds | `actor_type=machine`, stable principal in `actor_id`, originating credential record in `credential_id`, authenticated caller `team_id` |
| Credential rotates | Same `actor_id`; newly used credential has a different `credential_id` |
| Verified caller fails route scope or sandbox ownership | Retain caller metadata and `auth_outcome=authenticated`; record actual rejection status and separately resolved `resource_team_id` |
| Signature, expiry, audience or current generation fails verification | Do not copy claimed principal/credential/team into logs |
| Authority lookup fails | `actor_type=unknown`, `auth_outcome=error`, `attribution_status=error`; no claimed caller IDs |
| Stream ends after credential expiry/revocation | Completion retains the identity verified at establishment; it does not assert that the credential remains valid |
| Peer edge checks only a capability signature to route it | Forwarding event has no verified machine caller; the owner verifies current authority and emits the primary record |

The current proxy authority interface returns untyped errors for both some
revocation denials and infrastructure failures. These failed lookups are
conservatively logged as `error`; the logger does not inspect error strings
or invent a distinction. A returned generation mismatch is `invalid`.
The final authority handoff must resolve this distinction before final
acceptance. A valid, current capability used for another sandbox retains its
verified caller in the rejection record; its requested sandbox is still only
the attempted target. HTTP rejection codes remain owned by authentication.

### Rotation and denied-request inventory

Use the same environment and UTC bounds for control and data-plane exports.
Add this identity predicate to the Cloud Logging query above, keeping all
four event types for correlation:

```text
jsonPayload.actor_type = "machine"
jsonPayload.actor_id = "PRINCIPAL_ID"
```

Run once with the old credential and once with its replacement. Group the
primary events by `credential_id`, `service`, `plane`, `method`, `route` and
`status`. Confirm both credentials belong to the same stable principal.
Do not require revoked/invalid attempts to match the principal filter: the
verifier may legitimately discard those claims. Find those attempts using
the controlled workload window, requested sandbox and captured trusted
request IDs, and inspect the unfiltered authentication-outcome export.

For the inverse query, retain the shared `service`, `plane`, event and time
filters and constrain a route plus caller team:

```text
jsonPayload.route = "/files"
jsonPayload.team_id = "CALLER_TEAM_ID"
```

Group by principal and credential. Query `resource_team_id` separately when
investigating the target team's requests; never merge that field with caller
team. The primary-event/deduplication procedure above applies to both queries.
A forward-only record cannot prove the final verified caller or owner result.

### QM management service

QM management logs are a separate collection surface. The
[QM API runbook](https://github.com/superserve-ai/qm-deployments/blob/304fd561f2490172fa70776af6538485e5bb2459/docs/qm-api.md)
documents its authority and deployment contract. The configured sink is
CloudWatch Logs in `us-west-2`, log group `/qm/api` in the selected QM AWS
account. Verify the actual deployed account, image and log streams first;
a configured sink or merged code is not evidence of delivery.

Use CloudWatch Logs Insights with the same UTC workload interval:

```text
fields @timestamp, request_id, actor_type, actor_id, credential_id, user_id, team_id, method, route, status, auth_outcome, attribution_status
| filter event_type = "request" and service = "qm-api" and plane = "management"
| filter actor_id = "PRINCIPAL_ID" or credential_id = "CREDENTIAL_ID"
| sort @timestamp asc
```

For route/team to callers, replace the identity predicate with:

```text
| filter route = "/v1/qm/tenants/{id}/admin-link" and team_id = "CALLER_TEAM_ID"
```

For the verified-human acceptance example, use the console's authenticated
session adapter and filter by `user_id` and captured request IDs. Require
`actor_type=human` and `delegated_by=api_key`, keeping the underlying
`credential_id`. A direct key-only request proves the key and team, not a
logged-in human. Do not forge a proof or equate a fixture's signed JWT with
real console-session integration. Use create/delete/admin-link attempts and
a permission denial; admin-link success depends on its separately enabled
broker. Never retain a minted link or response body in evidence.

Cloud Logging and CloudWatch request IDs are service-local. No cross-service
causal trace is implied merely because actor IDs or timestamps match.

### Final evidence checklist

Retain evidence privately, with exact serving revisions, every serving
host/generation, sink/account, UTC interval and non-secret identity references:

1. The initial legacy workload inventory, explicitly marked sandbox-only.
2. A real machine-backed QM turn, command/process, file and lifecycle workload
   with principal/key inventory in both planes. Include local and peer paths,
   session establishment and closure/cancellation, and comparison against the
   workload's observed operations.
3. Same-team cross-sandbox and other-team denials preserving a verified caller
   where authentication succeeded; invalid/revoked attempts carry no invented
   caller. Keep caller and resource context distinct.
4. Credential rotation with stable principal and changed credential, plus the
   identity owner's expiry/revocation evidence. Logging is not proof of
   enforcement or of termination of already-started background processes.
5. A real console human action in the QM sink and matching denial semantics.
6. Representative full sink records checked privately for synthetic credential,
   cookie, admin-link, command, file and stream markers. An allowlisted export
   alone cannot demonstrate absence of leaks in other fields or diagnostics.

Local regression tests validate log behavior, not deployed workload coverage.
Do not mark final verification complete while any producer, serving revision,
sink, inventory or identity-authority prerequisite remains unverified.
