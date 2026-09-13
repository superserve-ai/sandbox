# Cold-standby peer identity bootstrap

For the current Compute MWI platform blocker and the explicit Superserve provider,
see [Peer credential providers](peer-credentials-runbook.md). Creation-time MWI
alone did not resolve staging issuance. The Superserve path preserves the existing
SPIFFE contract and supports staging preparation without managed credentials.

Run staging first. The migration targets are `superserve-vmd-staging-2`
(`10.0.0.3`, `n2-standard-32`) and then `superserve-vmd-usw2-2`
(`10.1.0.3`, the existing production Z3 configuration). No serving Host 1
operation is part of this procedure. Retain the existing private IP.

## Staging creation-time identity replacement

Staging Host 2 was recreated with managed workload identity in the actual
Compute create request. The retrofit exposed Enabled in the control plane but
never issued certificates, even after full stop/start. The isolated
`staging-mwi-host` module uses Google Beta 8.2.0 for these fields; ordinary hosts
keep their existing module/provider and destroy protection.

The one-shot replacement authorization is now retired: this module has
`prevent_destroy = true`, including while its labels are standby/provisioning.
Normal admission changes labels in place; it never authorizes replacement.
Any future replacement requires a separate reviewed change temporarily opening
that lifecycle guard, with both the current and proposed host still standby and
non-ready. The replacement checker rejects a serving/ready **before** state even
if the proposed labels revert to standby. Restore destroy protection immediately
after the separately authorized replacement. Never relax it for admission.

Historical replacement plan procedure (blocked by the restored guard):

```sh
terraform -chdir=infra/envs/staging/us-central1 plan -out=host2-replacement.tfplan -replace=module.sandbox_host_b.google_compute_instance.this
terraform -chdir=infra/envs/staging/us-central1 show -json host2-replacement.tfplan | python3 scripts/check_host2_replacement_plan.py
```

Do not apply until the replacement diff and every other plan action have been
reviewed. This replacement is restricted to the staging standby, never serving
Host 1. `google_compute_disk.sandbox_data_b` must remain a no-op: preserve the
existing 500 GB disk and its contents. Terraform forgets the old standalone
attachment record with `destroy=false` and the replacement VM reattaches that
same disk in its create request. This avoids attempting to delete an attachment
whose old state has `deletion_policy=PREVENT`; the data disk's independent
`prevent_destroy` remains enabled. Only the old 200 GB boot disk
is disposable. The replacement's mount script refuses to format the data disk.
The existing reservation must cover the same machine type and zone during the
replacement; do not recreate the VM manually to bypass a capacity failure.

Trust-domain, namespace, managed identity and CA permissions are reconciled
before VM creation. The create request enables the identity and certificates.
Attestation then binds the new numeric instance ID. The creation-time path
never retrofits identity with a post-create update. `[MWLID] enabled=true` is
installed through cloud-init, and the host keeps its dedicated runtime account,
standby component and provisioning status. No step admits it.

After applying the reviewed plan, export a fresh `host2_peer_bootstrap` artifact
and run normal bootstrap. It waits for first-boot managed credentials and
publishes a validated generation; missing credentials fail after five minutes.
It does not power-cycle a running VM by default. `--legacy-activate` is a separate
explicit recovery option for legacy retrofit artifacts and is rejected for
`identity_at_creation=true`. It is not a remedy for this staging replacement.


## Plan and migrate

The migration plan checker rejects saved plans that change Host 2's Compute
instance or managed identity adapter in either cell. The temporary branch's
staging rollout currently bypasses that checker and performs a broad apply;
do not use that workflow for admission. Use the restricted saved-plan procedure
below to exclude unrelated dashboard and infrastructure changes.
This includes adapter-only changes, which can restart the VM independently.
Routine applies can resume once both resources are no-ops. Perform this
migration with an operator-applied saved plan after the checks below; a merge
or generic rollout confirmation does not authorize Host 2 maintenance.

Keep the GitHub Actions variable `HOST2_PEER_IDENTITY_READY_STAGING` unset
until staging Host 2 completes migration and bootstrap verification; keep
`HOST2_PEER_IDENTITY_READY_USW` unset until the equivalent production checks
complete. This lets routine proxy deployments continue before migration.
Set the applicable variable to `true` in the `staging` or `production` GitHub
environment after verification and before restoring Host 2 to ready deployment
discovery. The flag requires bootstrap on that host; it does not supply its
SPIFFE URI or enable peer ingress/routing. Once enabled, retain it so missing
bootstrap fails closed on subsequent deployments.

1. Confirm the target owns no sandbox state and remains provisioning in the
   host directory. Remove `sandbox_status=ready` and remove or change
   `component=vmd` on Host 2: routine VMD and proxy workflows use the latter
   selector even when the ready label is absent. Staging Terraform declares
   `component=vmd-staging-standby` for Host 2; use that same value for the
   pre-migration exclusion. Production must retain `active_sandbox_host=primary`,
   which declares Host 2 as `component=vmd-usw2-standby`. If production already
   selects `standby`, stop: this cold-standby migration does not authorize
   switching the serving host. Wait for any deployments
   that already discovered Host 2 to finish before migration. Keep both
   selectors excluded and placement disabled for the maintenance window;
   keep peer routing disabled.
2. Review sanitized plans for the applicable root. Expect only Host 2's
   service account/stop opt-in and standby label, its dedicated runtime IAM,
   the new cell CA and managed identity adapter, and us-west2's shared peer
   firewall rule.
   Host 1 must have no action. Existing VM, disk and private IP resource
   addresses remain unchanged. `prevent_destroy` and ordinary hosts' default
   stop protection remain enabled. Any proposed VM replacement is a stop
   condition for the legacy production procedure; staging uses the explicit replacement plan above.
   In the applicable root, run `terraform plan -out=host2-migration.tfplan`
   and review that saved plan with `terraform show host2-migration.tfplan`.
   For production, first require the completed staging rehearsal evidence.
   Ensure the reviewed plan preserves Host 2's discovery exclusion: its
   Terraform labels must not restore `component=vmd` during maintenance.
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
   left it stopped. If managed credentials are absent on a running standby,
   normal bootstrap waits and fails closed if credentials never appear. Only
   the explicit `--legacy-activate` recovery mode attempts Compute stop/start
   for legacy retrofit artifacts; it is not used for the staging replacement. Before each power operation it
   rechecks the immutable instance identity, runtime account, managed identity,
   exact standby label and exclusion from `sandbox_status=ready`. Keep directory
   placement disabled and do not run admission concurrently with bootstrap.
   The stop requests local SSD preservation and fails rather than discarding
   data if preservation is unsupported. VMD is held behind a temporary systemd
   condition across activation; failed bootstrap retains this guard for retry.
   It remains stopped after bootstrap for the controlled runtime deployment.
   Already-active managed credentials skip the VM stop/start, including when
   a guest-agent refresh temporarily makes source files unavailable.
   Bootstrap waits up to five minutes for all three nonempty files under
   `/run/secrets/workload-spiffe-credentials`, tolerating SSH reconnects after
   start. It then runs `vmd-peer-credentials.service`, requires
   `/etc/superserve/peer/current`, and validates the published generation before
   reporting success. Timeout or publication failure blocks admission; fix the
   underlying identity/guest-agent configuration and rerun bootstrap.
   If GCP reports a capacity stockout at start, bootstrap confirms whether the
   host remains stopped and fails with an operator-visible diagnostic. It does
   not retry start automatically. Retry bootstrap later; do not recreate the
   host or change its identity to work around a zonal stockout.
   Staging keeps `superserve-vmd-staging-2`; production keeps `usw2-2`.
   A conflicting existing HOST_ID is an error, not an implicit rename.

The pinned stable production provider lacks the required identity fields.
`terraform_data.managed_identity` reconciles its Terraform-owned inputs with
Google's CLI, including exact instance-ID attestation. The Compute update
explicitly allows `RESTART` (required by the SDK); unchanged identities are
not updated again. This restart is not certificate activation; full stop/start
belongs only to the guarded bootstrap procedure, never to an unconditional
Terraform side effect. CA-pool bindings for both workload certificate requester
and pool reader use `principal://iam.googleapis.com/projects/PROJECT_NUMBER/name/locations/global/workloadIdentityPools/POOL_ID`;
the `/name/` segment is required for managed workload identity principals.
This operation is visible in the adapter's configuration,
not as a native Compute field in a plan. It must be reviewed with the code.
For drift repair, replace that adapter resource in a reviewed plan; it reuses
existing pools/identities and replaces the attestation policy with the exact
configured set. It never deletes trust resources. Do not manually add hosts
to this policy: extend the Terraform configuration when the next drained host
is ready, retaining the existing authorized instance IDs.

## Runtime baseline and readiness

Recreating a boot disk exposed a missing provisioning contract: CD installs
binaries, but does not supply the cell's secretsproxy CA or kernel/rootfs assets.
The independently preserved sandbox-data disk does not restore these files.

### Existing-cell CA and artifact contract

Existing templates trust the **cell's existing secretsproxy CA**. An additional
or replacement host must restore that same certificate and private key before
activation. This CA is separate from the Superserve peer mTLS credentials;
leave `/etc/superserve/peer/current` untouched. Missing or partial CA state is a
hard CD precondition failure, before binary installation or VMD activation.
CD never generates a CA. A genuinely brand-new cell can explicitly follow the
new-cell provisioning procedure and allow the daemon to initialize its CA
before invoking CD; missing files never select that mode automatically.

The runtime library can generate a CA when both files are absent. That behavior
is not authority to generate one for an existing cell. The previous fresh-host
instructions incorrectly inferred the deployment policy from that library.
There is no secretsproxy CA restore from Secret Manager wired into CD. Use the
canonical operator-workstation transfer below, never GCS for the private key.

Read-only staging Host 1 inspection confirmed these configured artifacts:

| Path | SHA-256 before the next boxd injection |
| --- | --- |
| `/var/lib/sandbox/kernel/vmlinux-4.14-fuse` | `3be77273fc267d2d2c239dc081cb3955f320dd0d3790de2b02690cb7f1af6761` |
| `/var/lib/sandbox/rootfs/base.ext4` | `7494f2288113b40f881575dfa8dfa6e50c4c78114a9d144af36f67fedf720ca0` |

The canonical new-host procedure permits non-secret `hostprep/` bucket assets,
but no exact staging object/version is established here. Use the verified Host 1
files, not an invented bucket location. Coordinate against concurrent deployments:
the kernel is a pinned artifact, but CD modifies base.ext4 by injecting boxd.
Recheck source hashes and target hashes during copying; after CD, the rootfs hash
can legitimately change. Verify the existing Firecracker binary matches Host 1
and retain the cell's guest-kernel/snapshot lineage.

### Operator preparation (not performed by CD)

Run on the operator workstation. These commands do not activate VMD or admit
Host 2. Keep its standby label and non-ready placement state. Do not run while
another operator is deploying or changing the source artifacts. The commands
refuse to overwrite an existing destination CA pair; investigate partial or
unexpected material instead of rotating it.

```bash
set -euo pipefail
umask 077
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
ssh1() { gcloud compute ssh superserve-vmd-staging --project=rayai-dev --zone=us-central1-a --tunnel-through-iap --quiet --command="set -eu; $1" -- -T; }
ssh2() { gcloud compute ssh superserve-vmd-staging-2 --project=rayai-dev --zone=us-central1-a --tunnel-through-iap --quiet --command="set -eu; $1" -- -T; }

# Inspect only selected non-secret settings and artifact hashes.
ssh1 'sudo grep -E "^(KERNEL_PATH|BASE_ROOTFS_PATH)=" /etc/sandbox/vmd.env; sudo sha256sum /var/lib/sandbox/kernel/vmlinux-4.14-fuse /var/lib/sandbox/rootfs/base.ext4 /usr/local/bin/firecracker'
ssh1 'sudo cat /var/lib/sandbox/kernel/vmlinux-4.14-fuse' > "$work/vmlinux-4.14-fuse"
ssh1 'sudo cat /var/lib/sandbox/rootfs/base.ext4' > "$work/base.ext4"
(cd "$work" && shasum -a 256 -c <<'HASHES'
3be77273fc267d2d2c239dc081cb3955f320dd0d3790de2b02690cb7f1af6761  vmlinux-4.14-fuse
7494f2288113b40f881575dfa8dfa6e50c4c78114a9d144af36f67fedf720ca0  base.ext4
HASHES
)
# Repeat source hashes; stop if they changed during the copy.
ssh1 'sudo sha256sum /var/lib/sandbox/kernel/vmlinux-4.14-fuse /var/lib/sandbox/rootfs/base.ext4'
ssh2 'sudo systemctl stop superserve-vmd.socket superserve-vmd.service; sudo install -d -m 0755 /var/lib/sandbox/kernel /var/lib/sandbox/rootfs'
ssh2 'sudo tee /var/lib/sandbox/kernel/vmlinux-4.14-fuse >/dev/null' < "$work/vmlinux-4.14-fuse"
ssh2 'sudo tee /var/lib/sandbox/rootfs/base.ext4 >/dev/null' < "$work/base.ext4"
ssh2 'sudo chown root:root /var/lib/sandbox/kernel/vmlinux-4.14-fuse /var/lib/sandbox/rootfs/base.ext4; sudo chmod 0644 /var/lib/sandbox/kernel/vmlinux-4.14-fuse /var/lib/sandbox/rootfs/base.ext4; sudo sha256sum /var/lib/sandbox/kernel/vmlinux-4.14-fuse /var/lib/sandbox/rootfs/base.ext4'

# Secrets travel host -> private workstation directory -> host, never GCS.
ssh1 'sudo cat /var/lib/secretsproxy/ca.crt' > "$work/ca.crt"
ssh1 'sudo cat /var/lib/secretsproxy/ca.key' > "$work/ca.key"
chmod 0644 "$work/ca.crt"
chmod 0600 "$work/ca.key"
openssl x509 -in "$work/ca.crt" -pubkey -noout > "$work/cert.pub"
openssl pkey -in "$work/ca.key" -pubout > "$work/key.pub"
cmp "$work/cert.pub" "$work/key.pub"
# DynamicUser has no passwd entry while the daemon is inactive. Let systemd
# allocate its actual identity and StateDirectory without starting secretsproxy.
ssh2 'sudo systemctl stop superserve-secretsproxy.service; sudo test ! -e /var/lib/secretsproxy/ca.crt && sudo test ! -e /var/lib/secretsproxy/ca.key'
COPYFILE_DISABLE=1 tar -C "$work" -cf - ca.crt ca.key | ssh2 'sudo systemd-run --quiet --wait --pipe --collect --unit=secretsproxy-ca-restore --property=User=superserve-secretsproxy --property=DynamicUser=yes --property=StateDirectory=secretsproxy --property=StateDirectoryMode=0700 /bin/sh -ec "tar --no-same-owner -xf - -C /var/lib/secretsproxy; chmod 0644 /var/lib/secretsproxy/ca.crt; chmod 0600 /var/lib/secretsproxy/ca.key; stat -c \"%a %U %n\" /var/lib/secretsproxy/ca.crt /var/lib/secretsproxy/ca.key"'
rm -f "$work/ca.key" "$work/ca.crt" "$work/cert.pub" "$work/key.pub"
```

The transient restore unit owns the files as `superserve-secretsproxy`, with
certificate 0644/key 0600. While DynamicUser is inactive its UID may display
numerically; the real service's StateDirectory setup restores ownership to its
allocated identity at startup. Do not create a conflicting static account.
The shell trap removes all workstation copies on exit; do not retain them in
backups or shell output. If transfer fails partway, leave VMD stopped and resolve
the partial destination pair before retrying. Never start secretsproxy to repair
a missing CA in this cell.

Configure the approved artifact paths without copying Host 1's env or HOST_ID:

```bash
ssh2 'sudo install -d -m 0755 /etc/sandbox; sudo touch /etc/sandbox/vmd.env /etc/sandbox/secretsproxy.env; sudo chown root:root /etc/sandbox/*.env; sudo chmod 0644 /etc/sandbox/vmd.env; sudo chmod 0600 /etc/sandbox/secretsproxy.env
for setting in KERNEL_PATH=/var/lib/sandbox/kernel/vmlinux-4.14-fuse BASE_ROOTFS_PATH=/var/lib/sandbox/rootfs/base.ext4 HOST_ID=superserve-vmd-staging-2; do
  key=${setting%%=*}
  if ! sudo grep -q "^$key=" /etc/sandbox/vmd.env; then echo "$setting" | sudo tee -a /etc/sandbox/vmd.env >/dev/null; fi
done
sudo grep -E "^(KERNEL_PATH|BASE_ROOTFS_PATH|HOST_ID)=" /etc/sandbox/vmd.env
sudo test -s /var/lib/secretsproxy/ca.crt
sudo test -s /var/lib/secretsproxy/ca.key
sudo test -s /var/lib/sandbox/kernel/vmlinux-4.14-fuse
sudo test -s /var/lib/sandbox/rootfs/base.ext4
sudo test -x /usr/local/bin/firecracker
sudo test -x /usr/local/bin/template-builder
sudo test -c /dev/kvm
mountpoint -q /mnt/sandbox-data
sudo systemctl is-active google-guest-agent.service
sudo test -d /etc/superserve/peer/current'
```

Review any already-configured paths instead of overwriting them. Host 2 must
retain its own instance-name HOST_ID; an existing value is preserved by CD.
Leave `HOST_INTERFACE` unset for automatic default-route discovery, or verify an
intentional override with `ip link`. Check guest DNS and Firecracker compatibility
against the canonical host preparation procedure. Rerun the documented
`bootstrap-host2.py --provider superserve` baseline with the Terraform artifact
before requesting the standby deployment. It leaves VMD stopped; do not admit it.

### Durable template storage before transfer or admission

Both template trees belong on the separate XFS sandbox data disk, not the boot
disk. Keep the database/runtime paths unchanged:

| Backing directory | Canonical bind mount |
| --- | --- |
| `/mnt/sandbox-data/templates/rundir` | `/var/lib/sandbox/rundir/templates` |
| `/mnt/sandbox-data/templates/snapshots` | `/var/lib/sandbox/snapshots/templates` |

`deploy/template-storage.py install` installs a preparation service, two native
systemd bind-mount units, and enrollment-only VMD service/socket drop-ins. The
preparation service requires the existing `sandbox-data.service` when present;
otherwise the data disk must already have persistent fstab/native mount setup.
It verifies a separate XFS mount before creating any backing directories. No
formatting, data copying, deletion or general runtime/snapshot migration occurs.
The mount units run after preparation and are enabled for boot. Their late
ordering accommodates the existing data-disk service without holding up the
early filesystem/socket boot targets. VMD and its socket bind their lifetimes
to both mounts and run an exact source/inode check before activation. A missing
or wrong disk/mapping blocks startup; unmounting a required mapping stops them.

Fresh VMD deploys and standby bootstrap install this contract. Later deploys on
an enrolled host verify it. Ordinary serving hosts without this enrollment are
not silently converted. Manual bind mounts with exactly the expected sources
are adopted without unmounting or moving their contents. A non-empty unmounted
template tree is rejected: hiding old files would conceal data and leave the
root disk full. Existing source templates are never replaced by installation.

For the currently running Host 2, the manual mounts alone are **not durable**.
In a controlled standby maintenance window, confirm no guest/build workloads,
stop its VMD service/socket (and retire any legacy VMD), then install the units.
The installer refuses an active manager/socket or guest/build processes. It does
not start VMD or admit the host. Do not run this procedure on serving Host 1.

```bash
gcloud compute scp deploy/template-storage.py superserve-vmd-staging-2:/tmp/template-storage.py \
  --project=rayai-dev --zone=us-central1-a --tunnel-through-iap
gcloud compute ssh superserve-vmd-staging-2 \
  --project=rayai-dev --zone=us-central1-a --tunnel-through-iap \
  --command='set -eu
sudo systemctl stop superserve-vmd.socket superserve-vmd.service
sudo python3 /tmp/template-storage.py install
sudo /usr/local/sbin/sandbox-template-storage check
sudo systemctl is-enabled var-lib-sandbox-rundir-templates.mount var-lib-sandbox-snapshots-templates.mount
findmnt -T /var/lib/sandbox/rundir/templates
findmnt -T /var/lib/sandbox/snapshots/templates
df -h /var/lib/sandbox/rundir/templates /var/lib/sandbox/snapshots/templates /mnt/sandbox-data'
```

Repeat the checker, `findmnt -T` and `df` after the next controlled reboot and
before **every template copy**. Both paths must resolve to the data filesystem
with the expected `/templates/rundir` and `/templates/snapshots` source roots.
Do not copy if either resolves to `/` or a parent runtime directory. Confirm
collector/runtime prerequisites and perform final verification before admission.

Before copying, size **both** source trees. On the source host, record:

```bash
sudo du -sb /var/lib/sandbox/rundir/templates /var/lib/sandbox/snapshots/templates
```

Sum those byte counts into `REQUIRED_TEMPLATE_BYTES` on the destination. Use a
conservative apparent-size estimate unless the transfer's sparse/reflink behavior
has been verified. Allow headroom for existing backups, staging and runtime
writes on this shared disk; 20 GiB is a minimum reserve, not a capacity promise.

```bash
sudo /usr/local/sbin/sandbox-template-storage check
: "${REQUIRED_TEMPLATE_BYTES:?Set the sum of both source-tree byte counts}"
free_bytes=$(df -B1 --output=avail /mnt/sandbox-data | tail -n 1 | tr -d ' ')
reserve_bytes=$((20 * 1024 * 1024 * 1024))
test "$free_bytes" -ge "$((REQUIRED_TEMPLATE_BYTES + reserve_bytes))" || {
  echo 'Insufficient template-storage capacity; do not begin transfer' >&2
  exit 1
}
```

Read-only inspection found serving Host 1's two template trees on `/dev/sda1`
(ext4 root, 57 GiB free), while `/mnt/sandbox-data` is separate XFS. It was not
modified. This installer can later adopt a drained/reprovisioned Host 1, but it
will not migrate its populated root trees. At that time, provision persistent
data mounting, copy and verify the two trees during the approved drain, retain
rollback copies as appropriate, and empty the mountpoint directories before
installation. General sandbox state and database template paths stay unchanged.

Backport the installer/checker, generated mount/service/drop-in contract, fresh
deploy and bootstrap integration, workflow bundle/trigger entries, tests and
these transfer gates into durable new-host provisioning. The temporary branch's
manual staging recovery is not the reusable provisioning mechanism.

### Explicit schedulable capacity

Named identity-bound hosts must publish positive `VMD_SCHEDULABLE_MEMORY_MIB`
and `VMD_SCHEDULABLE_VCPUS` from runtime configuration. These are scheduler
admission budgets, not physical machine totals or values recovered from a host
row in the database. Missing capacity causes self-description rejection even
when addresses and region are correct.

The shared deployment/bootstrap policy in `deploy/host_runtime.py` supplies
staging Host 2 with **110000 MiB / 32 vCPU**. Other hosts have no inferred default.
The production workflow passes environment variables from these GitHub production
environment vars:

| Cell | Memory variable | vCPU variable |
| --- | --- | --- |
| use4 | `VMD_SCHEDULABLE_MEMORY_MIB_USE4` | `VMD_SCHEDULABLE_VCPUS_USE4` |
| usw2 | `VMD_SCHEDULABLE_MEMORY_MIB_USW2` | `VMD_SCHEDULABLE_VCPUS_USW2` |

Populate these with the approved cell/host admission budgets before production
standby provisioning. No production numbers have been invented here. Bootstrap
accepts the same `VMD_SCHEDULABLE_*` process environment inputs, or explicit
`capacity_memory_mib` / `capacity_vcpus` fields in its host configuration artifact.
Use the same approved policy values for deployment and bootstrap.

Both paths preserve existing non-empty runtime values. Zero, negative,
non-integer, out-of-range or missing values fail closed for named hosts before
activation; both values are validated before either fallback is written.
Legacy `HOST_ID=default` keeps its existing capacity/identity behavior. Final
bootstrap verification now checks that named-host runtime capacity is positive.
This does not alter admission state, physical-capacity detection or peer TLS.

### Named-host heartbeat region

An identity-bound host must send a complete self-description. Private endpoints
alone are insufficient: an empty region causes heartbeat rejection. VMD deploy
now fills missing or empty `HOST_REGION` for every non-`default` HOST_ID from
`GCP_REGION`, checked
against the discovered instance zone. If deployment is not region-scoped, the
instance zone supplies the region. Staging uses `us-central1`; production hosts
use their actual deployment region, including standby hosts. Bootstrap sets the
same fallback from its Terraform-provided zone. Both paths preserve a non-empty
explicit `HOST_REGION`; final verification checks that the runtime region is
non-empty, rather than requiring it to equal the default. Region/zone ambiguity
fails deployment before uploads; named-host activation requires a non-empty
runtime region. A region already stored in the database does not substitute for
the region in each identity-bound heartbeat.
No manual HOST_REGION or SANDBOX_ID_REGION setting is needed on a fresh host.

Deployment preserves HOST_ID and does not add, replace or remove region settings
on the legacy `HOST_ID=default` host. Its description-less heartbeat compatibility
is not evidence that a named identity-bound host can omit its region. Schedulable capacity uses the explicit admission policy above; this does not admit Host 2 or migrate
legacy identity semantics.

### Host interface and advertised addresses

VMD no longer assumes the primary host NIC is `eth0`. With `HOST_INTERFACE`
unset, it selects the unique lowest-metric IPv4 default route and asks the kernel
for the private source address used to reach that route's gateway. The resolved
interface is shared by host firewall/template-builder configuration; the resolved
address is reused for automatic VMD and proxy advertisement. Queries are local,
bounded to two seconds, and run once at startup rather than on sandbox requests.

Inspect routing with `ip -j -4 route show default` and
`ip -j -4 route get <gateway-from-default-route>`. The selected route must have
one interface and one concrete private IPv4 source. Equal-cost defaults,
multipath, unavailable interfaces, missing source addresses, or public/link-local
sources fail closed. More complex routing requires an explicit `HOST_INTERFACE`.
That interface must provide a unique private IPv4 address for automatic
advertisement. An explicit override is never silently replaced; remove a stale
`HOST_INTERFACE=eth0` setting to opt into discovery, or correct it intentionally.

Existing explicit advertisement overrides retain their semantics, including the
private peer-ingress endpoint validation. Peer mTLS and host admission do not
change. Do not work around an advertisement acknowledgement failure by disabling
the gate or publishing a wildcard/loopback address.

### Provision the standby OTEL collector before final verification

VMD deployment does not install the host-local OTEL collector. After runtime
provisioning, run **Deploy OTEL Collector** from this migration branch with
`environment: staging` and `target: standby`. The staging job sources the same
fixed-label selector as VMD/proxy: `component=vmd-staging-standby`, with exactly
`superserve-vmd-staging-2` required as the discovered host. Zero matches, a
serving host, or multiple matches fail before deployment. It does not fall back
to `component=vmd`.

The OTEL target defaults to `serving` to preserve existing manual behavior;
select `standby` explicitly. Push runs retain the configured staging label, and
production keeps its existing cell filters and rollout sequence (the target
input applies only to staging).

Fresh-host collector deployment must install files **and** leave the service
persistently enabled and active. A staging attempt exposed a shell rendering bug:
an indented `collector.env` heredoc terminator swallowed the enable/restart and
health commands into the env file. The deployment now renders that heredoc
separately from multiline health checks, rewrites the env file cleanly on retry,
and verifies persistent enablement plus runtime health before reporting success.
A manual `enable --now` is not a provisioning requirement; rerun the corrected
collector deployment after reviewing any prior failed attempt.

Do not run `bootstrap-host2.py --verify` until the standby collector deployment
has succeeded. Confirm `superserve-otel-collector.service` is active and its
health endpoint responds before final verification; the deployment also checks
collector metrics. An inactive/not-found collector is an incomplete provisioning
step, not a peer-credential bootstrap failure. This does not admit Host 2.

### Retiring the legacy VMD during enrollment

Enrollment recognizes a loaded `agentbox-vmd.service`, even if its env files
look complete. Before service changes it requires no running Firecracker or
template-builder processes and no active/activating guest units. If workloads
remain, stop enrollment and drain them through the existing lifecycle procedure;
do not kill guests or retire their manager as part of fresh-host deployment.
Inspection failures also abort.

After installing the fresh-host activation guard, deployment stops the new VMD
units, disables and stops `agentbox-vmd.service`, and persistently masks the
legacy unit. A locally installed regular unit file is preserved as
`/etc/systemd/system/agentbox-vmd.service.retired` before masking. The mask
survives reboot and blocks dependency/manual starts as well as boot enablement.
Retries preserve the mask; an unexpected existing backup requires inspection.

Ports 50051 and 9090 must have no TCP listeners after retirement and immediately
before releasing the socket activation guard. A remaining unmanaged VMD or other
listener causes failure, with listener details for diagnosis; deployment never
kills it automatically. Leave the host outside placement and resolve the owner
before retrying. These retirement checks do not run on ordinary configured
serving hosts without the legacy unit. Peer credentials are unaffected.

### Staging workflow runtime configuration

The staging GitHub environment is the canonical source for fresh-host runtime
configuration. The VMD workflow passes `vars.CONTROL_PLANE_URL_STAGING` as
`CONTROL_PLANE_URL`, `secrets.DATABASE_URL_STAGING` as `DATABASE_URL`, and
`secrets.STAGING_INTERNAL_API_TOKEN` as `INTERNAL_API_TOKEN`. These values are
configured in that environment; the workflow rejects unset values before invoking
the deploy script. Never copy Host 1's env file to supply them.

The deploy script also validates these inputs for fresh or partially configured
hosts. If any input is absent, a read-only probe rejects an incomplete host before
bundle upload, env writes, unit changes, binary replacement or boxd injection.
The check runs again at the start of remote convergence. Already-configured hosts
can preserve omitted values when invoked outside the workflow; supplied values
still intentionally reconcile both env files. Missing inputs leave the host as
found, including any guard from an earlier attempt.

Once the CA/artifact and baseline checks above pass, rerun the VMD workflow on
this branch with `environment: staging` and `target: standby`. This configuration
change does not itself transfer prerequisites, deploy, or admit Host 2.

CD creates env files without truncating existing content, keeps vmd.env root-owned
0644 and secretsproxy.env 0600, and reconciles deployment-supplied control-plane,
auth and database values. It requires an explicit approved KERNEL_PATH, defaults
only missing BASE_ROOTFS_PATH to `/var/lib/sandbox/rootfs/base.ext4`, and preserves
configured alternatives. It checks artifacts and the shared CA before installing
binaries, then requires secretsproxy health before first VMD activation. The
persistent bootstrap guard survives failed attempts. A retry also injects boxd
when an earlier partial deploy already installed the same binary. Normal serving
hosts retain their existing restart order. No peer certificates are changed.

After any stop/start, verify the intended runtime filesystem layout,
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

Complete every check below while Host 2 is provisioning, both deployment
selectors exclude it, and routing is disabled. A successful `--verify` is not admission
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
   `sandbox_status` to be absent or different from `ready` and `component`
   to be absent or different from `vmd`. Confirm routine VMD/proxy discovery
   and the ready selectors in `deploy/environments.yaml` exclude this host, and retain the
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
changing its unit/config, even before the cell's readiness flag is enabled.
Missing bootstrap fails closed once that flag is enabled or ingress is
requested. A file lock coordinates refresh with systemd `LoadCredential`;
rotation restarts only the proxy to load the new material, retrying failed
reloads. It never restarts VMD or enters a sandbox startup/resume path.

After staging Host 2 passes readiness and host-directory checks, use the
label-only admission procedure below. As part of that separate admission,
change staging `module.sandbox_host_b.labels.component` to `vmd` in Terraform
and review/apply the label plan through the operator path above before restoring
the ready label. Do not enroll it with an out-of-band component label change
that the next Terraform apply would undo. Only after the old host is drained
may its separate migration occur. Once both hosts are peer-capable, the
routing rollout may enable ingress/routing and verify bidirectional traffic,
pause/resume and restore across hosts. Record that evidence before applying
the production Host 2 plan. Production admission remains a separate step.

References: [managed identity setup](https://docs.cloud.google.com/iam/docs/create-managed-workload-identities),
[Compute credential lifecycle](https://docs.cloud.google.com/compute/docs/access/authenticate-workloads-over-mtls).


## Label-only staging admission after replacement

Keep `prevent_destroy = true`. The module remains restricted to the exact
staging Host 2 name; labels no longer gate every operation on the resource.
No boot disk, data disk, VM identity, service account or Host 1 action is part
of admission. Host 1 draining/migration remains a separate operation.

Use Terraform **1.16.2**, matching the state writer observed during admission.
Terraform 1.15.8 cannot decode the built-in `terraform_data` resource's `store`
attribute written by 1.16.2. This is Terraform core schema skew, not Google
provider skew. Reinitialize with the existing lockfile; do not remove attributes,
remove/import resources, or run state repair. Discard plans generated with the
older CLI and regenerate with the compatible version. Keep saved plans private:
they can contain sensitive state.

1. In `infra/envs/staging/us-central1/main.tf`, change only Host 2's
   `component` from `vmd-staging-standby` to `vmd`; retain
   `sandbox_status = "provisioning"`. This enables normal deployment discovery,
   so coordinate any concurrent deployment before changing it.
2. From the repository root, with Terraform 1.16.2 on PATH:

   ```sh
   set -euo pipefail
   umask 077
   terraform version
   terraform -chdir=infra/envs/staging/us-central1 init -input=false -lockfile=readonly
   terraform -chdir=infra/envs/staging/us-central1 plan -input=false \
     -target=module.sandbox_host_b.google_compute_instance.this \
     -out=host2-admission.tfplan
   terraform -chdir=infra/envs/staging/us-central1 show -json host2-admission.tfplan \
     | python3 scripts/check_host2_admission_plan.py
   terraform -chdir=infra/envs/staging/us-central1 show -no-color host2-admission.tfplan
   ```

   Targeting is appropriate only for this exceptional, isolated admission. It
   includes dependencies and is **not** by itself a label-only guarantee. The
   checker requires exactly one in-place Host 2 update, only the admission
   labels (and computed fingerprint), and no other resource actions. It rejects
   dashboard updates, disk actions, replacement, identity/attestation changes,
   service-account changes and unknown non-label results. Expect
   `Plan: 0 to add, 1 to change, 0 to destroy.` Do not use `-replace`,
   `-refresh=false`, the generic rollout, or an old broad plan for admission.
3. After reviewing the passing saved plan, the authorized operator applies
   **that exact plan**, without replanning:

   ```sh
   terraform -chdir=infra/envs/staging/us-central1 apply host2-admission.tfplan
   ```

4. Verify Host 2 heartbeat/readiness again. Change only its Terraform
   `sandbox_status` from `provisioning` to `ready`, leaving `component = "vmd"`.
   Repeat steps 2–3 with a newly generated saved plan. The checker permits
   `vmd/provisioning -> vmd/ready` and rejects skipping directly from standby
   to ready. Preserve both label changes in the authoritative configuration
   so a later apply cannot revert admission.

Review unrelated monitoring drift separately after admission; a targeted plan
is not evidence that the whole staging configuration has converged.
