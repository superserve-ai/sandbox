# Proxy routing production prerequisites

Keep each cell's GitHub routing variable unset or `0` until these steps and the
host-generation rollout are complete for its remote destinations. No routing
credential is installed while routing is disabled.

| GitHub Environment | Cell | Routing variable | Routing database secret |
| --- | --- | --- | --- |
| staging | staging | `PEER_ROUTING_ENABLED` | `PROXY_DATABASE_URL_STAGING` |
| production | use4 | `PEER_ROUTING_ENABLED_USE4` | `PROXY_DATABASE_URL_PROD` |
| production | usw2 | `PEER_ROUTING_ENABLED_USW` | `PROXY_DATABASE_URL_USWEST` |

The workflow maps each cell's variable to the runtime `PEER_ROUTING_ENABLED`.
The generic GitHub variable `PEER_ROUTING_ENABLED` only controls staging.

## Database access

The normal Supabase migration workflow installs the role and authorization
contract in `supabase/migrations/20260923000010_sandbox_proxy_router.sql` in each
cell. CD applies the same migration history to staging (`DATABASE_URL_STAGING`),
east (`DATABASE_URL_PROD`), then west (`DATABASE_URL_USWEST`), independently of
routing enablement. East receives this role even while its routing variable is
unset; enabling east later requires no region-specific SQL change.

The migration preserves existing credentials and connection limits, repairs
security attributes, and replaces direct SELECT grants on `sandbox` and `host`
with the routing column allowlist. Grants on unrelated objects are preserved.
Repairing privileged attributes requires an administrator authorized to change
those attributes; the migration fails rather than silently retaining them.
For a new role, set a generated
password separately using psql's
`\password sandbox_proxy_router`; do not commit it or put it in command history.
The role can read only the sandbox and host columns used for discovery. Its
SELECT policies permit fleet-wide discovery without bypassing row-level security
or granting access to sandbox contents or tokens. It has no write grants or role
memberships. Audit pre-existing PUBLIC grants when provisioning into a database
with additional custom objects.

Install connection strings for that role in GitHub secrets
`PROXY_DATABASE_URL_STAGING`, `PROXY_DATABASE_URL_PROD`, and
`PROXY_DATABASE_URL_USWEST`. Use the appropriate database per cell and TLS settings
for that database. Existing control-plane `DATABASE_URL_*` secrets are not used by
the proxy. Missing routing secrets block enabled deployments; startup also rejects
an administrative or incorrectly named database role.

Each proxy process permits at most four database connections, independent of CPU
count or URL pool options. The role's initial shared limit is 32 connections per
database. Budget four per concurrently running proxy process, including rollout
overlap, against the database's total connection budget before enablement. Adjust
the role limit deliberately if the fleet needs more; do not raise the process cap
to compensate for latency. Ownership queries have a 500 ms deadline, including
pool acquisition, and a matching server statement timeout.

## Ownership freshness

The cache retains at most 4,096 entries and starts expiry before the database
query. Successful routes expire after one second, including local routes. Up to
32 distinct lookups may run concurrently; requests for the same sandbox share
one lookup. Errors, including not-found results, are retained for at most 100 ms.
Expired entries are never served when the database is unavailable. There is no
background refresh and no unbounded database acquisition queue.

After movement, deletion, or host re-registration, new requests may select the
previous owner for at most this freshness window. Existing streams remain pinned.
The destination is always local-only, so stale routes cannot recursively forward.
A failed request is never replayed. Movement must stop/fence the old sandbox as
it does without this cache; the cache is not an authorization or lifecycle fence.
The ownership-lookup latency metric covers cache hits and shared/uncached misses;
use its latency distribution and ownership-error outcomes during staged rollout.

## Peer capacity

The edge opens at most four connections with 256 streams each per destination
(1,024 total). Ingress defaults to 1,024 active streams globally across connections;
`PEER_PROXY_MAX_STREAMS` still controls the active limit. Up to 128 additional
streams can wait globally for at most 500 ms. Waiting streams do not dial the
local proxy or consume request frames. Releasing capacity wakes waiters;
cancellation removes them. A full queue or expired wait returns ResourceExhausted,
which the HTTP bridge reports as 502 before any response bytes. No retries or
request replay are introduced. This bounded queue absorbs brief multi-source
bursts; sustained overload is deliberately rejected rather than retained forever.

Validate burst latency, lookup latency, and ingress rejection metrics on a small
enabled cohort before expanding it. Long-lived terminals count against active
stream capacity, so size ingress for both terminals and ordinary requests.

## Independent ingress rollout

Set `PEER_INGRESS_ENABLED_PROD=1` for use4 or `PEER_INGRESS_ENABLED_USW=1` for
usw2 before deploying ingress to that cell's production serving hosts. Staging uses
`PEER_PROXY_LISTEN_ADDR_STAGING=auto`. Leave outbound routing disabled while
verifying listeners, firewall access, and accepted endpoint heartbeats across
all destination hosts reachable from that cell. Then set that cell's routing
variable from the table above to `1` and redeploy.

For a west-only production rollout, leave `PEER_ROUTING_ENABLED_USE4` unset or
`0`, set `PEER_ROUTING_ENABLED_USW=1`, and manually run Deploy Proxy with
`environment=production`, `target=serving`, and `production_cell=usw2`. Staging
deploys first using its independent configuration, then only west deploys in
production. Selecting `production_cell=use4` instead deploys only east after
staging. Production serving deployments still require staging to succeed;
staging routing does not need to be enabled.

Production outbound routing and serving ingress are independent. To deploy an
outbound-only source in either production cell, set its routing variable to `1`
and leave its ingress variable unset or `0`. Its peer listener stays empty and
client credentials are loaded. Local ownership is recognized using the proxy's
configured `HOST_ID`, including legacy IDs; every remote destination still needs
an authoritative peer endpoint. Manual standby deployment enables ingress even
when routing is disabled. Staging retains its existing behavior: routing enabled
forces `auto`; otherwise `PEER_PROXY_LISTEN_ADDR_STAGING` selects ingress.

To disable outbound routing, set the source cell's routing variable to `0` and
redeploy that cell. This does not disable independently configured ingress.
Before removing ingress from a destination or rolling it back to an older binary,
disable routing on every source that can reach that destination and let existing
streams drain. Then clear the destination's serving ingress setting and redeploy.
An outbound-only source does not need its own listener for rollback or routing;
keep ingress on destinations that other sources still use.

Readiness accepts an acknowledged heartbeat from the current VMD invocation,
including identity-bound hosts retaining the legacy `default` ID. Bound hosts
also acknowledge removal of an endpoint. The database fallback accepts only a
fresh, matching heartbeat for the running VMD’s explicit `HOST_ID` when that host
is unbound (including named legacy hosts); it cannot
substitute for a missing acknowledgement on a bound host.

## Signed SDK routing hints

Create, get/activate and resume responses include an optional `routing_hint`.
HTTP clients send it as `X-Superserve-Routing-Hint`; WebSocket clients add
`route.<hint>` to their subprotocols. `X-Access-Token` and `token.<access-token>`
are unchanged and remain required. Preview traffic does not use hints.

Version 1 binds sandbox UUID, logical host, ownership version and edge-domain audience for one hour.
Expiration is anchored to database statement time returned by the existing
lifecycle query, so delayed responses cannot renew an old route.
A domain-separated HMAC uses the existing cell access-token seed; the hint is
never usable as an access token. Seed changes invalidate old hints, which retain
lookup fallback; no additional signing secret or per-request secret fetch is
required. Different blue/green processes using the same cell seed accept the
same hint and select the current serving endpoint independently.

Each routing proxy refreshes a bounded host directory every five seconds using
only the existing read-only discovery column grants. Snapshots expire after
15 seconds; missing, malformed, expired hints or unavailable directory entries
use the existing bounded ownership lookup. No host-directory query runs on
create/resume or in response to an SDK request.

Database triggers record each deleted or superseded ownership version atomically,
including changes made by older servers and hard deletes. Movement increments the
version even when returning to an earlier host. Proxies accept hints only while
holding a complete revocation snapshot less than one second old, measured from
before its query. Snapshots poll every 500ms and cap at 65,536 entries; overflow,
query errors, startup, replica connections, or clock skew over one minute disable
hint bypass. The existing bounded ownership lookup remains the fallback.

A PostgreSQL notification adds only the revoked ownership version to the local
denied set without renewing snapshot freshness. Lost notifications are covered by polling. Host discovery, LISTEN, and
revocation reads share one dedicated database session per process, separate from
the four ownership connections. Initial readiness and public data-plane dispatch
wait for fresh host and revocation snapshots, for at most one second. After that
bounded warmup, unavailable snapshots use ownership fallback so overflow cannot
prevent replacement proxies from serving. Later snapshot failures use fallback while
the normal database readiness check remains in effect. `PROXY_DATABASE_URL` must use a primary database
with direct or session-pooled connections (not transaction pooling). Budget five
connections per proxy process, including both generations during blue/green.
The migration raises the original role limit of 32 to 64 and preserves other
configured limits; larger fleets must provision a matching role/database budget.

Revocation records survive sandbox removal. Background control-plane maintenance
first observes committed records, then assigns a two-hour retention window in
bounded batches on a dedicated one-connection maintenance pool with a one-second
statement timeout. Until observed, records have no expiration. This protects long
transactions as well as delayed responses. Maintenance failure retains records;
if the snapshot cap is reached, hints safely use ownership lookup. Keep database
API and proxy clocks synchronized within one minute. Issuance suppresses future-dated
hints and retention refuses to prune when database and API time differ by more
than one minute. Destination access-token and
VMD checks remain in force, and already-dispatched operations are not replayed.

If opening a peer stream fails before forwarding request bytes, the proxy may
resolve ownership and open once more. After forwarding begins, it never replays.
A destination's pre-execution missing-sandbox response has code
`sandbox_route_stale`; SDKs activate once to refresh ownership and retry. Deletion
therefore fails at activate. Clients refresh expired hints before their next
operation. They must never treat an ambiguous network failure as safe to replay.

Apply the schema migration before deploying new API/proxy binaries, then deploy SDKs. Older clients and old proxies keep the
lookup path; rollback does not require a token migration. Explicit
`PEER_PROXY_MAX_STREAMS` overrides still win: set each participating host to at
least 1024 for the 1000-concurrent-request acceptance run. Authenticated boxd
traffic permits 1024 concurrent requests per source IP, including peer-local
traffic; preview/unauthenticated limits and the 200-per-sandbox bound remain.

Validate a controlled burst across distinct sandboxes on local and cross-host
routes. Record route outcomes `hint_local`/`hint_remote`, ownership lookups, capacity rejections,
proxy-added p50/p95/p99, and create/resume latency. A local benchmark is not
production proof; capture deployed results before declaring the target met.

Automatic proxy deployment waits for the same-release schema migration workflow
when a push includes migrations. Manual dispatch requires the operator to apply
migrations before deploying, matching the API deployment contract.
