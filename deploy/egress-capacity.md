# Host egress connection capacity

VMD can limit concurrent connections handled by its outbound egress proxy. Host
firewall redirects currently cover TCP 80/443. This is separate from the inbound
edge proxy and does not gate pause, resume, exec, or file operations. A command
inside a sandbox can encounter an outbound connection failure. Existing
per-sandbox limits (256), destination checks and mining controls still apply.
Direct TCP/UDP traffic, team quotas and connection-rate limits are separate
controls. This change does not promise equal tenant shares or protection against
all packet floods or conntrack exhaustion.

## Configuration

| VMD environment variable | Default | Meaning |
| --- | --- | --- |
| `VMD_EGRESS_MAX_CONNECTIONS` | `4096` | Positive candidate host connection limit, shared by all listeners. |
| `VMD_EGRESS_ENFORCE` | `false` | `true` enables rejection at the host ceiling; `false` observes existing traffic. |

Enforcement is deliberately off until rollout validation. Observation mode does
**not** bound aggregate connections. Invalid explicit settings fail startup;
zero and negative limits never mean unlimited. Changes take effect on VMD restart.
There is no database lookup for admission and no persistent connection counter.

At saturation, the accept loop closes new sockets without spawning a handler or
queueing work. Clients see TCP connection failure/closure, not HTTP 429. Existing
streams keep their slots until cleanup; they are not evicted for new arrivals.
Inspection is bounded to 4096 bytes and five seconds; upstream dialing (including
DNS) and the initial inspected-data write have 30-second deadlines. Established
relays retain their existing half-close semantics without a maximum lifetime.

With limit C and L listeners (currently three), there are at most C admitted
connections plus L transient accepted sockets. Each relay normally uses two FDs;
DNS and dual-stack dialing can add transient sockets. Startup reserves 4096 FDs
for other VMD work and budgets four FDs per admitted connection against the
process soft limit. This guard is only a coarse ceiling: production sizing must
also consider memory, CPU, legitimate concurrency and other VMD descriptor use.
The candidate 4096 limit is not a measured production recommendation.
Kernel SYN/listen queues and conntrack entries are outside that userspace count.
Rapid connection churn can accumulate TIME_WAIT/conntrack state even below C.

## Development and rollout

Development uses local Linux tests and mocked deployment configuration checks.
Staging execution and evidence collection belong to the rollout owner; they are
required before production activation, not before development completion or PR
merge. No new automated staging load runner is required.

The deployment workflow reads the three GitHub environment variables
`VMD_EGRESS_MAX_CONNECTIONS`, `VMD_EGRESS_ENFORCE`, and
`VMD_EGRESS_ROLLOUT_APPROVAL` in staging and each production cell. An unset
workflow enforcement variable explicitly writes `false`; an omitted maximum
preserves the host setting (or the binary default on a fresh host). When invoking
the deployment script directly, omitted maximum/enforcement settings preserve
existing host values. Preflight examines those effective values without sourcing
the host environment file. The workflow supplies the actual `DEPLOY_CELL` for
each step. Direct staging invocations must set `DEPLOY_CELL=staging` to use the
staging activation exemption; any other or omitted cell requires release/limit
approval when enabling enforcement. Telemetry metadata does not select this gate.
Inherited scalar settings may have surrounding
whitespace or simple quotes. Invalid inherited scalar values require explicit
deployment settings. Multiline/escaped host environment syntax must be normalized
before deployment, even with explicit overrides: physical-line updates could
otherwise alter an unrelated multiline value. Preflight fails before host mutation.

1. Deploy the candidate to staging with enforcement enabled and an explicit
   finite limit. Use the same host class and settings intended for production.
2. Run legitimate package-installation, API, browser and polling workloads beside
   controlled short-lived connection churn, slow handshakes/dials and long-lived
   streams from many sandboxes. Include deletion and network-address reuse.
   Record active/rejected connections, FDs, conntrack, socket pressure, CPU/RAM,
   and neighboring-workload and pause/resume/exec latency. Define acceptable
   workload/latency thresholds before assessing the measurements. Test direct
   traffic separately and do not attribute its protection to this proxy.
3. Confirm the new metrics reach existing observability. Exercise saturation,
   recovery, and missing-kernel-counter behavior. Verify admission still works
   when telemetry is disabled or its exporter cannot reach the collector.
4. Measure VMD restart and readiness recovery; verify sandbox VMs survive and
   proxied outbound streams reconnect. Record rollback behavior. No database
   migration/backfill, sandbox recreation or host reboot is needed. Restart
   interrupts proxied outbound streams and temporarily affects control readiness;
   this is not a zero-downtime deployment.
5. Record and review the full release SHA, effective connection limit, host
   capacity, traffic mix, measured impact, restart time and rollback settings.
   Set the production environment's `VMD_EGRESS_ROLLOUT_APPROVAL` to
   `<full-release-SHA>:<effective-limit>` and explicitly set
   `VMD_EGRESS_ENFORCE=true`. This operator-controlled value records that review;
   the script checks the binding, not the truth of the evidence. A successful
   staging boot alone is insufficient. Missing/mismatched approval fails before
   uploading or modifying the host, even if enforcement was already enabled.
6. Roll out incrementally by the existing scoped host/cell selectors and observe
   rejection rates and neighboring workloads. A subsequent release or changed
   limit needs updated staging evidence/approval. Production is not activated by
   merging with the default configuration.

To stop enforcement, explicitly set `VMD_EGRESS_ENFORCE=false` and deploy through
the normal scoped path; disabling does not need activation approval. This requires
a VMD restart and removes aggregate protection. Preserve the per-sandbox/security
controls. A binary rollback follows existing compatibility guards and has the
same outbound interruption; connection accounting has no state migration.
