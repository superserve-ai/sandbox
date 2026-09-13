# Host drain implementation packet

Status: inspection/design only, 2026-09-13. Baseline: migration branch at
`f584e04609534807def382af30abd1e7c3b4d6ef`. No drain, movement or production action
was performed. This packet proposes work; it does not claim the gaps are fixed.

## Existing behavior and gaps

| Area | Already present | Missing or unsafe assumption |
| --- | --- | --- |
| Placement | `db/queries/hosts.sql`: `ListActiveHosts`, `ListActiveHostsByLoad` select only `active`; `internal/scheduler/scheduler.go` refuses a non-active default fallback | Cached ranking and cached positive capability preflight can admit work after a DB status change; active-only SQL is not an immediate host-side fence |
| Operator | `cmd/hostctl`: `drain`, `activate`, `list`, `--wait`; `POST /internal/hosts/:host_id/status` accepts `active`/`draining` | No durable, acknowledged VMD gate transition; no compare-and-set transition revision for concurrent operators |
| Authentication | `internal/api/router.go`: operator endpoints use `OPERATOR_API_TOKEN`, distinct from VMD's internal token | Confirm deployment has operator credentials; never give VMD the operator token |
| Reactivation | `UpdateHostStatus` atomically requires a fresh heartbeat for `active`; heartbeat recovery preserves deliberate draining | Fresh heartbeat alone does not prove admission reconstruction complete or that reopening a concurrent drain is authorized |
| Existing owner routing | `vmdForHost` resolves persisted owner; proxy DB resolver derives registered VMD IP + 5009, without an active-status placement filter | Shared `HostHasCapabilities` and `HostHasCapabilitiesUnlocked` require `active`; preview-policy checks used by resume/other existing-sandbox operations can therefore reject draining owners |
| Progress | `GET /internal/hosts?id=...` / `ListHostsAdmin`: running (active + starting), transitional (pausing + resuming), paused, builds, paused-unbacked | Need per-status ownership detail, unknown/error/cleanup states and authoritative local pending/in-flight work; pressure is sampled, not an admission barrier |
| Completion | `hostctl --wait drain` waits 75s then 90s continuous zero running/transitional/build counts, bounded to 15min polling | It returns success even if paused ownership remains, with a NOT-safe-to-retire warning. This is not a power-off authorization |

The positive capability cache defaults to 10s, is capped at 30s, and has 2s stale
grace (`internal/api/hostcap_cache.go`); host query/registry time and an already
admitted create's boot/cleanup extend the race. Scheduler candidate caching is
separate and can serve stale candidates while refreshing. Status handling only
invalidates this API replica's scheduler; it cannot synchronously fence peers.
Creates can boot before their sandbox row is inserted. Fixed sleep windows and
DB counts alone cannot establish that no invisible boot remains.

## Required contract

Drain is admission control, not shutdown. A successful drain operation means
no *new admission* can pass the host gate after the acknowledged close point.
Already admitted work may complete and is counted until settled. Preserve peer
ingress, public routing, lifecycle RPCs, credentials, heartbeat, component labels
and the host directory row. Do not disable services or force-pause guests.

Existing paused sandboxes remain resumable on their owner during this ticket;
there is no re-placement fallback. Resume policy can change only with the later
ownership-transition work. Split placement eligibility (`active`) from
operation-specific owner usability (healthy/reachable `active` or `draining`,
with required capability). Do not globally loosen the shared active-only SQL:
create/build paths must retain their admission checks. Cache keys must include
operation eligibility so a positive owner check cannot authorize placement.
Inventory preview access/network mutation, auto-resume, manual resume, pause,
delete/destroy and reaper rollback; do not claim every capability is enforced
until each call path has been reviewed.

## Proposed bounded implementation

1. Share the authoritative VMD admission primitive with the capacity-admission
   work. No such drain RPC/gate contract was found in this branch. Add durable
   gate state and monotonically ordered transition ID, an authenticated close/
   open operation, and synchronous status including local pending admissions,
   in-flight boots/builds and reattach readiness. Gate check + pending increment
   must be atomic with close. Decrement only after commit/cleanup settles;
   include retries, template restores used for creates, and template builds.
   Existing-owner lifecycle requests must not be classified as new placement.
2. Serialize operator transitions per host using a persisted operation/revision.
   Close the local gate first; record `draining` after acknowledgement. A DB
   failure leaves the gate closed and a retryable operation, never implicitly
   reopens it. Lost acknowledgements retry the same operation ID. A restarted
   VMD restores closed state and never opens during incomplete reconstruction.
   Unreachable hosts may be marked draining, but report fence unconfirmed and
   refuse completion until observed/fenced by an explicit recovery procedure.
3. Reactivate only with fresh heartbeat, completed reattach, compatible gate
   protocol and no conflicting transition: persist active under the revision,
   then acknowledge gate open. Failure leaves admission closed. An old open
   request cannot override a newer drain. Return success only after the gate
   state is confirmed; keep operations idempotent.
4. Add operation-specific capability predicates described above. Continue
   resolving existing sandboxes to exactly their owner; no broadcast/fallback.
5. Extend hostctl/operator view with detailed counts and separate booleans for
   placement fenced, drain quiescent, and safe to power off, plus blocking
   reasons and observation revision/time. Keep the existing aggregate columns.
   Bound list/count work to the requested host. Gate status is synchronous;
   heartbeat pressure may be shown as diagnostic context only.
6. Add a final retirement check with nonzero exit status unless the predicate
   below holds. This ticket does not stop/delete machines, mutate Terraform,
   remove load balancers, move sandboxes, or retire Host 1.

## Exact conservative power-off predicate

All terms must be true for the same still-current drain revision:

- Host remains `draining`; durable local admission gate is closed and reopening
  is excluded by the operator transition lock/revision.
- Local authoritative pending admissions, boots, restores, builds and other
  lifecycle operations are zero; reattach/reconciliation has completed.
- Zero non-destroyed sandbox ownership rows of **any** status, including paused,
  failed/recoverable and unknown states; zero live template builds or exclusive
  template/artifact dependencies still needed by the cell.
- Deleted-row cleanup is complete: no surviving guests/Firecracker units,
  orphan runtime state requiring recovery, live sandbox streams, or pending
  backup/report work whose only required state resides on this disk.
- Control-plane inventory and local inventory agree, checks are fresh, and no
  unresolved ownership transition/recovery task targets this host. Unknown or
  unreachable observations block authorization.

Keep the gate closed through the actual maintenance operation; a report is not
an indefinitely reusable permission slip. Paused-with-backup is still blocked:
current backups are filesystem recovery, not proof that normal memory resume
can survive loss of its recorded owner. No zero-running shortcut is acceptable.

## Tests and acceptance

- Enumerate all host statuses: only active accepts create/build placement,
  including default fallback. Exercise multiple API replicas with warm caches.
- Pause a create immediately before/after atomic gate admission; after close,
  no new boot starts, and the pre-close one remains counted through failure
  cleanup/DB insertion. Include retry, process crash and gate restart recovery.
- Drain/reactivate retries, concurrent opposite transitions, stale operation
  delivery, DB write failure, unreachable VMD and reattach-not-ready cases.
- While draining, existing public exec/files/preview, long-lived streams,
  pause/destroy and owner-pinned resume continue; capability absence still
  fails closed. No endpoint/label/credential change accompanies drain.
- Count active/starting/pausing/resuming/paused/failed/deleting/unknown and
  builds without join multiplication. Paused-only and orphan-only inventories
  refuse power-off; missing observations do too.
- Staging rehearsal after implementation: operator drain one explicitly chosen
  host, direct new creates elsewhere, exercise existing owner traffic, inspect
  blockers, reactivate; do not move sandboxes in this ticket.

## Decisions to settle before implementation

- Define “immediately” as gate linearization/acknowledgement, not wall-clock
  request arrival or instant cancellation of previously admitted work.
- Agree the shared admission-gate owner/API with capacity work; avoid parallel
  gates. Gate protocol support is required before promising immediate drain.
- Confirm existing-owner resume remains allowed until migration exists. Earlier
  proposals to refuse resumes or count backed paused rows as retirable must
  not be implemented under the current no-movement scope.
- Choose a distinct hostctl retirement-check command/output; preserve existing
  drain-wait semantics or change its exit code explicitly, never silently.
- Decide authorization for final power-off separately; this packet grants none.
