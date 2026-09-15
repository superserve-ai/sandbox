# Proxy routing production prerequisites

Keep `PEER_ROUTING_ENABLED=0` until these steps and the host-generation rollout
are complete. No routing credential is installed while routing is disabled.

## Database access

Run `deploy/proxy-routing-role.sql` against each routing database as its
administrator. Set a generated password separately using psql's
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

The edge opens at most four connections with 32 streams each per destination
(128 total). Ingress defaults to 128 active streams globally across connections;
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

Set `PEER_INGRESS_ENABLED_PROD=1` and `PEER_INGRESS_ENABLED_USW=1` before
production serving-host ingress deployment. Staging uses
`PEER_PROXY_LISTEN_ADDR_STAGING=auto`. Leave outbound routing disabled while
verifying listeners, firewall access, and accepted endpoint heartbeats across
all destination hosts. Then enable `PEER_ROUTING_ENABLED=1`.

To disable routing, keep the ingress settings enabled while the routing-disabled
version reaches every source host and existing streams drain. Only then clear
the independent ingress settings and deploy again. Routing being enabled always
forces ingress on; turning routing off does not remove an independently enabled
listener. Manual standby deployment continues enabling ingress automatically.

Readiness accepts an acknowledged heartbeat from the current VMD invocation,
including identity-bound hosts retaining the legacy `default` ID. Bound hosts
also acknowledge removal of an endpoint. The database fallback accepts only a
fresh, matching heartbeat from a genuinely unbound `default` host; it cannot
substitute for a missing acknowledgement on a bound host.
