# Cold-standby peer identity bootstrap

Run staging first. The migration targets are `superserve-vmd-staging-2`
(`10.0.0.3`, `n2-standard-32`) and then `superserve-vmd-usw2-2`
(`10.1.0.3`, the existing production Z3 configuration). No serving Host 1
operation is part of this procedure. Do not allocate another VM or IP.

## Plan and migrate

Terraform CD and the generic manual rollout workflows reject saved plans that
change Host 2's Compute instance or managed identity adapter in either cell.
This includes adapter-only changes, which can restart the VM independently.
Routine applies can resume once both resources are no-ops. Perform this
migration with an operator-applied saved plan after the checks below; a merge
or generic rollout confirmation does not authorize Host 2 maintenance.

1. Confirm the target owns no sandbox state and remains provisioning in the
   host directory. Remove its ready label and exclude it from concurrent CD
   and placement for the maintenance window. Keep peer routing disabled.
2. Review sanitized plans for the applicable root. Expect only Host 2's
   service account/stop opt-in, its dedicated runtime IAM, the new cell CA
   and managed identity adapter, and us-west2's shared peer firewall rule.
   Host 1 must have no action. Existing VM, disk and private IP resource
   addresses remain unchanged. `prevent_destroy` and ordinary hosts' default
   stop protection remain enabled. Any proposed VM replacement is a stop
   condition: this implementation uses supported in-place updates.
   In the applicable root, run `terraform plan -out=host2-migration.tfplan`
   and review that saved plan with `terraform show host2-migration.tfplan`.
   For production, first require the completed staging rehearsal evidence.
3. Apply the reviewed plan with a current Google Cloud SDK (tested command
   schema: 578.0.0), Python 3.10+, and authenticated Terraform credentials.
   The identity adapter invokes `gcloud` using **its active credential**, so
   configure it as the same approved infrastructure principal as Terraform;
   provider-only impersonation is insufficient. That principal needs existing
   Compute/IAM deployment rights plus workload identity pool and CA admin
   permissions. Runtime accounts receive none of those admin roles.
   Run `terraform apply host2-migration.tfplan` in that same root while the
   maintenance window and discovery exclusion remain in effect. Do not bypass
   the workflow guard or re-plan between review and apply.
4. Export the public bootstrap artifact from that exact root:

   ```sh
   terraform output -json host2_peer_bootstrap > /tmp/host2-peer.json
   python3 deploy/bootstrap-host2.py /tmp/host2-peer.json
   ```

   Run the Python command from the repository root. The script checks the
   immutable instance ID, private IP, runtime service account and host name,
   preserves the existing host-row ID, installs the refresh worker, and enables
   guest certificate provisioning with `[MWLID] enabled=true` in
   `/etc/default/instance_configs.cfg`. It starts the cold standby if Terraform
   left it stopped; identity enablement's restart was handled by the adapter.
   It stops VMD during preparation and leaves it for the controlled runtime
   deployment to start. Only the guest agent is restarted after installation.
   Staging keeps `superserve-vmd-staging-2`; production keeps `usw2-2`.
   A conflicting existing HOST_ID is an error, not an implicit rename.

The pinned stable production provider lacks the required identity fields.
`terraform_data.managed_identity` reconciles its Terraform-owned inputs with
Google's CLI, including exact instance-ID attestation. The Compute update
explicitly allows `RESTART` (required by the SDK); unchanged identities are
not updated again. This operation is visible in the adapter's configuration,
not as a native Compute field in a plan. It must be reviewed with the code.
For drift repair, replace that adapter resource in a reviewed plan; it reuses
existing pools/identities and replaces the attestation policy with the exact
configured set. It never deletes trust resources. Do not manually add hosts
to this policy: extend the Terraform configuration when the next drained host
is ready, retaining the existing authorized instance IDs.

## Runtime baseline and readiness

These existing cold standbys retain their local SSD, background-data disk,
secretsproxy CA/configuration, vmd environment, seeded template/rootfs/kernel
artifacts, host patching policy and agents. Bootstrap checks the mount,
secretsproxy files, Firecracker/template builder, and KVM before modifying
services; it never formats disks or invents missing secrets. A failed
baseline check must be repaired using the normal host preparation and release
artifacts before retrying. In particular, do not seed production snapshots
from staging hardware, silently upgrade the kernel, or copy a live Host 1's
runtime identity. Compare production CPU family, OS/kernel and Firecracker
build against the approved snapshot-compatible host build before admission.

After any stop/start, verify the local SSD is mounted at `/var/lib/sandbox`,
`/mnt/sandbox-data` is mounted, and the configured `KERNEL_PATH` and
`BASE_ROOTFS_PATH` exist. Reseed the normal release's templates when local SSD
contents were lost. Deploy the matching normal VMD release to this specific
provisioning host through the controlled deployment path; routine ready-host
CD must remain excluded during preparation.

Wait for the guest agent and credential timer, then run:

```sh
python3 deploy/bootstrap-host2.py --verify /tmp/host2-peer.json
```

This is only the local verification subset: Compute identity, URI SAN, key pair, trust chain, expiry,
key ownership/mode, services, and endpoint acknowledgement from the current
VMD invocation. Also inspect the host directory: the expected stable HOST_ID
must have a fresh heartbeat, the correct private VMD address and capabilities,
and remain non-serving. With peer ingress disabled, its advertised proxy
endpoint retains the existing contract. After the routing rollout enables
ingress, verify the advertised private peer endpoint is `10.0.0.3:5009` or
`10.1.0.3:5009` respectively.

### Required pre-admission evidence

Complete every check below while Host 2 is provisioning, its ready label is
absent, and routing is disabled. A successful `--verify` is not admission
approval. Any failed or missing check blocks admission and production rollout.
Save timestamped output with the release SHA, Terraform bootstrap artifact and
VMD invocation ID in the private rollout evidence; never attach credentials,
full environment files, or customer data to the public repository.

1. **Directory and capabilities.** Use the existing read-only database access
   for the target cell. Run this query in `psql` (staging values shown):

   ```sql
   \set host_id superserve-vmd-staging-2
   SELECT now() AS observed_at, h.id, h.region, h.status, h.identity_bound,
          h.vmd_addr, h.proxy_addr, h.last_heartbeat_at,
          now() - h.last_heartbeat_at AS heartbeat_age,
          ARRAY(SELECT hc.capability FROM host_capability hc
                WHERE hc.host_id = h.id
                  AND hc.heartbeat_at = h.last_heartbeat_at
                ORDER BY hc.capability) AS current_capabilities
   FROM host h WHERE h.id = :'host_id';
   ```

   Require exactly one row with the Terraform `host_id`, expected region,
   `identity_bound = true`, and `status = provisioning`. Require heartbeat age
   below 60 seconds, then repeat after the next heartbeat and require the
   timestamp to advance. Compare `vmd_addr` to the private IP and configured
   gRPC port (normally `10.0.0.3:50051`; production `10.1.0.3:50051`). Compare
   `proxy_addr` to the deployed release's effective advertisement, including
   `PROXY_ADVERTISE_ADDR` and `PEER_PROXY_LISTEN_ADDR`; do not assume the peer
   port before ingress is enabled. Record the expected capability set from
   the deployed release and compare it to `current_capabilities`. In
   particular, browser preview support requires all four capabilities in
   [the deployment registry](README.md#preview-authentication-rollout-and-rollback-safety).
   An empty or incomplete set is not a pass for a release that requires them.
   Production uses `\set host_id usw2-2`.

2. **Admission gates.** Capture the target's Compute labels with
   `gcloud compute instances describe INSTANCE --project=PROJECT --zone=ZONE --format='json(id,labels)'`,
   using the exact values from the bootstrap artifact. Require
   `sandbox_status` to be absent or different from `ready`, confirm the ready
   selectors in `deploy/environments.yaml` exclude this host, and retain the
   provisioning row from check 1. Check the deployed routing configuration
   still has peer routing disabled. Do not change status or labels as part of
   verification; both database activation and CD enrollment require the
   separate deliberate admission step.

3. **Artifacts after restart.** On Host 2, inspect the effective VMD unit with
   `sudo systemctl cat superserve-vmd.service` and read only `KERNEL_PATH`,
   `BASE_ROOTFS_PATH` and template-path settings from its environment files and
   overrides. For each resolved kernel, rootfs and required seeded template
   artifact, run `sudo test -s PATH` and `sudo sha256sum PATH`; compare against
   the approved, hardware-compatible release manifest. Record manifest ID,
   paths, checksums, and the complete required template inventory. A present
   template-builder binary does not prove seeding. Missing templates or a
   missing reference manifest block the check; reseed through normal host
   preparation, then repeat after confirming the data mounts. Hashing is an
   offline maintenance check, never part of sandbox startup or resume.

4. **Agents actually ready.** On Host 2, run the collector's existing probes:

   ```sh
   curl --fail --silent --show-error --max-time 10 http://127.0.0.1:13133/
   curl --fail --silent --show-error --max-time 10 http://127.0.0.1:8888/metrics
   sudo systemctl is-active google-guest-agent.service
   ```

   Require healthy collector HTTP responses, collector self-metrics, and
   an active guest agent. Inspect their current-boot journals for
   authentication or export failures. Capture fresh host-scoped telemetry in
   the configured monitoring backend after migration, with the expected host
   label and increasing sample timestamps; local health alone does not prove
   the new identity can export. Compare
   `/etc/needrestart/conf.d/50-superserve.conf` and
   `/etc/apt/apt.conf.d/99superserve-no-auto-upgrades` to the host module's
   patching policy and require `apt-daily-upgrade.timer` to remain disabled.
   For additional agents in the approved host baseline, record each agent's
   own health probe and a fresh backend acknowledgement. Use the
   [collector validation procedure](otel/README.md) for exporter failures and
   queue pressure. Missing remote samples or acknowledgements remain pending, not
   a successful agent check.

Record one row per check with expected value, observed value, UTC observation
time, evidence location and PASS/FAIL/PENDING. Include local `--verify` output
as its own row. The initial staging evidence status is **PENDING: not executed**;
this runbook and local tests are not staging execution evidence. All rows must
be PASS before admission, and the separate staging drain/peer rehearsal must
also pass before the production plan is applied.

Exercise a backup create and restore read using the dedicated runtime
identity in its own bucket. Review effective IAM to confirm it has no delete,
admin, or other-cell read grants; existing shared-account writers retain only
their prior access. Secretsproxy uses the control-plane vault, so no new
Secret Manager or KMS grants are needed on the host identity.

## Credential lifecycle and rollout

A regional cell shares one CA/pool and the `vmd-peer-proxy` managed identity.
Each host is authorized by an immutable instance ID, never by the shared
service account. Staging and production have separate trust domains. The
CA's private key is managed by CA Service; VM private keys never enter
Terraform, GitHub or the exported artifact.

The guest agent rotates 24-hour credentials. A root timer validates and
atomically publishes each complete generation at the fixed peer paths.
It preserves the prior valid generation on invalid SAN/key/chain/expiry and
reports failures through `vmd-peer-credentials.service` in the journal. The
root-only source directory is created by tmpfiles before the guest agent.
The proxy deploy reads `identity.json` locally and checks credentials before
changing its unit/config. Missing bootstrap fails closed when ingress is
requested. A file lock coordinates refresh with systemd `LoadCredential`;
rotation restarts only the proxy to load the new material, retrying failed
reloads. It never restarts VMD or enters a sandbox startup/resume path.

After staging Host 2 passes readiness and host-directory checks, use the
normal rollout to admit it and drain Host 1. Only after the old host is drained
may its separate migration occur. Once both hosts are peer-capable, the
routing rollout may enable ingress/routing and verify bidirectional traffic,
pause/resume and restore across hosts. Record that evidence before applying
the production Host 2 plan. Production admission remains a separate step.

References: [managed identity setup](https://docs.cloud.google.com/iam/docs/create-managed-workload-identities),
[Compute credential lifecycle](https://docs.cloud.google.com/compute/docs/access/authenticate-workloads-over-mtls).
