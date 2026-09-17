# Authoritative peer identity rollout

The database host row owns the registered VMD address and peer generation.
Migrations leave existing hosts with both incarnation and generation NULL.
`identity_bound` alone does not establish forwarding eligibility.

1. Apply the schema migration, then deploy this fencing-aware control plane to
   **every** serving replica. Old control planes reject the new heartbeat JSON;
   do not install host identity before the control-plane rollout completes.
   Deploy the updated host-local OTel collector and apply the backup/launch-path
   alert policies in every cell before installing generated host IDs. The
   collector stamps `collector_host_id` with its stable instance name while
   preserving VMD's generated `host_id`. Policies accept either the collector
   label or the legacy host ID, retaining coverage during the staged rollout
   and across later replacements. Verify the new label on VMD series before
   binding hosts. Keep collectors host-local so this label identifies the VMD
   host that produced these metrics.
2. Establish this control-plane/VMD release as the rollback floor before binding
   the first host. Once a host binds, rollback to an earlier writer or VMD is
   prohibited. The database trigger rejects older heartbeat/address writers for
   bound hosts, but this is a fail-closed backstop, not a supported rollout mode.
   Keep the schema and identity files when rolling back to a supported release.
3. On an existing VM with a preserved `sandbox-host-identity` provider metadata
   record, use `deploy/install-host-identity.py --project PROJECT
   --zone ZONE --instance INSTANCE --slot REGION-SLOT --legacy-host-id HOST_ID
   --fencing-control-plane-ready`. The legacy ID must match the provider record,
   whose project and immutable instance ID must match this VM. The flag cannot
   create a legacy mapping when the provider record is absent. A running VMD's
   ID, instance name, or reused slot alone is not evidence of same-VM ownership.
   If no provider identity record exists, leave the host on the legacy
   non-forwarding rollout stage until its original identity record can be
   recovered from authoritative operator records proving that same-VM mapping.
   Do not synthesize a record from a supplied host ID or copy one from another
   VM. A replacement must use `--new-machine` and receive a new full host ID.
   The command installs identity only; restarting and activating a production
   host remain separate operator procedures. It never restarts VMD itself.
   Install identity before deploying the new systemd units: they require the
   identity files even on legacy hosts. Unupgraded legacy units may continue
   serving non-forwarding traffic during the staged rollout.
   Configure `HOST_REGION`, `VMD_SCHEDULABLE_MEMORY_MIB`, and
   `VMD_SCHEDULABLE_VCPUS` before starting an identity-bound VMD, including a
   legacy `default` host. Capacity values must be positive schedulable limits,
   not physical totals. Missing or invalid values now fail startup explicitly
   because every bound heartbeat requires a complete self-description.
   `deploy-vmd.py` enforces this prerequisite for every target, including when
   all runtime inputs are supplied. Its read-only preflight checks the installed
   JSON identity and matching installer-format environment file before uploading
   the bundle, and repeats the check before remote mutations. Missing, empty,
   malformed, or mismatched files abort that host's deployment with its existing
   binaries, units, and running services intact. The deployment never generates
   or repairs identity; complete the operator installation/recovery procedure
   first. Provider identity verification still occurs in VMD at startup. Keep
   identity installation/reinstallation serialized with deployment for that VM.
4. New/replacement VMs use `--new-machine` instead of `--legacy-host-id`.
   A new random suffix is allocated even when a human-readable slot is reused.
   If local installation fails after metadata is persisted, retry the same
   command with VMD stopped. It reuses that identity without requiring rebind.
   `--new-machine` attests the VM has never registered; do not use it to recover
   lost local state on a previously registered VM.
   Before provisioning, bake this release's `deploy/superserve-vmd.service` and
   `deploy/superserve-vmd.socket` into the image's systemd unit directory together
   with the fencing-aware VMD binary. Pin provisioning to that image. The baked
   units require identity before any daemon start, including socket activation
   before cloud-init. Images with older units or binaries are unsupported;
   cloud-init `bootcmd` cannot close their early-boot registration race.
   Verify the image's effective units retain the mandatory identity environment
   and nonempty state check, with no drop-ins clearing these settings. Boot a
   disposable VM with missing identity and attempt socket activation: VMD must
   not register. Repeat with copied identity from a different disposable VM:
   provider-ID verification must fail before registration. Do not admit the
   image for provisioning until both checks pass.
   The host modules reassert the gate before caller boot commands as a secondary
   safeguard. Existing instances ignore startup metadata changes and keep
   their current IDs. Never copy instance metadata or identity files to a
   replacement. The installer and VMD reject mismatched immutable provider IDs.
5. After the normal approved VMD restart, inspect `host.incarnation_id`,
   `peer_generation`, `vmd_addr`, and `last_heartbeat_at`. Binding establishes
   generation 1 atomically. Verify two subsequent heartbeats keep the generation
   unchanged. Activation still requires a fresh heartbeat and operator token.
6. Enable forwarding only for discovery results with a bound incarnation and a
   positive generation and a registered `proxy_addr` matching the VMD IP on
   port 5009. Other listener addresses or ports are ineligible. Legacy hosts remain supported for non-forwarding use;
   missing generation is an explicit routing failure, never a local default.

The installation file is `/etc/sandbox/host-identity.json`, paired with provider
metadata keyed `sandbox-host-identity`. A systemd drop-in loads the dedicated
identity environment after the ordinary VMD environment. Do not remove this
file/drop-in to bypass identity errors. Deployments must preserve both. VMD reads
identity and verifies the immutable provider VM ID once at daemon startup, with
bounded metadata timeouts; no sandbox create/resume path does this work.

For same-VM in-place reinstall or lost local identity, retain the provider
metadata record and full host ID. Stop VMD and its activating socket through the
normal drain procedure; the installer rejects either unit while active or
transitioning. Keep both stopped throughout installation and rebind. Invoke
the installer with `--reinstall --expected-incarnation CURRENT_UUID`
and the same provider coordinates. This explicitly creates a new installation
incarnation. Execute the emitted `hostctl rebind HOST_ID CURRENT_UUID NEW_UUID`
using the separate operator token before restarting VMD. If provider identity
metadata is also lost, stop and recover the original mapping from authoritative
operator records; do not allocate another ID for the same installation by guess.
Unrelated local/provider identity mismatches fail closed and require operator reconciliation.
For a failed reinstall, repeat the original command with the same expected old
incarnation. Provider metadata retains `previous_incarnation_id`, so retries
reuse the new incarnation and repeat the same idempotent rebind instruction,
including when the local JSON was written before SSH failed. A subsequent
ordinary installation also repeats that instruction; keep the predecessor
record until the next explicitly authorized reinstall replaces it.
Serialize install operations for a VM; concurrent mismatches stop installation.

Rebind atomically retires the old incarnation, increments generation even at the
same address, demotes to provisioning, and clears heartbeat, capabilities, and
pressure. Retrying the same rebind is idempotent. Retired IDs cannot be authorized
again. Staleness never authorizes replacement. A heartbeat from the new holder
and a separate activation are required before scheduling resumes.

For address changes within an incarnation, retain the existing stale-holder
check. Each accepted VMD address change atomically increments the generation and
permanently retires the previous address **within that incarnation**. Delayed
claims cannot restore it even after a timeout. Intentional address reuse requires
an operator-authorized new incarnation. Proxy address changes, heartbeats,
status, and metadata do not increment generation. Bigint overflow aborts the
transaction rather than wrapping or partially accepting routing changes.

After replacing/destroying a VM, drain and retire its old row using the existing
retirement procedure. Deletion tombstones the full ID in `host_identity_registry`;
never delete this registry or retirement history. Do not reclaim an old row for
a replacement VM. Preserving a row for paused data does not authorize its ID on
a new VM. Same-VM rebuild and VM replacement are distinct operations.

## Forwarding consumer seam

`GetSandboxPeerEndpoint` joins sandbox ownership and registered host state in one
query. `host_id` is a string; nullable `vmd_addr` and `proxy_addr` are `*string`;
nullable `peer_generation` is `*int64`; nullable `incarnation_id` is `pgtype.UUID`.
`PeerEndpointFromDiscovery` requires bound positive state and derives IP:5009
solely from `vmd_addr`. The registered `proxy_addr` must match that IP and port;
a missing or mismatched advertisement fails discovery instead of redirecting it.
Configure `PEER_PROXY_LISTEN_ADDR` to that endpoint before enabling forwarding.
Custom listener IPs or ports remain supported for non-forwarding use only.
An incarnation with no
heartbeat after rebind is unavailable. The later forwarding change should fold
these fields into its existing ownership query, carry the validated generation
through `SandboxRoute`, and pass it unchanged into `PeerEndpoint`. Do not add a
second lookup per request. Router-to-peer integration testing belongs to that
consumer change. The pool's generation comparisons and retained high-water marks
remain unchanged.

Before enabling public cross-host routing, also complete the database credential
and capacity prerequisites in [proxy-routing-capacity.md](proxy-routing-capacity.md).
