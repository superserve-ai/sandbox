# Host drain and reactivation

Drain stops new admission. It does not move sandboxes, stop VMD or proxy, change
component labels, remove endpoints, or rotate credentials. Existing owners stay
routable and paused sandboxes may resume on their current owner.

## Prerequisites and rollout

This implementation depends on the admission primitive from PR #470, carried
with author attribution until that dependency merges. The resume intent uses
protobuf field 10 because fields 7–9 already belong to preview policy. Upgrade
control-plane callers before enrolling a daemon: a drain-capable gate requires
explicit create/resume intent on every boot path.

Apply the host admission revision database migration before the control-plane
upgrade. Enroll one explicitly selected host during a reviewed rollout:

- Set `VMD_DRAIN_ENABLED=true` and `VMD_ADMISSION_CALLER_EMAIL` to the **exact
  control-plane runtime service-account email for that cell**. No runtime VMD
  principal should be authorized as the caller.
- The VMD workflow accepts these through GitHub environment variables suffixed
  `_STAGING`, `_USE4`, or `_USW2`, respectively. Empty variables preserve the
  existing configuration. Enrollment is opt-in and does not enable host-local
  capacity limits unless their separate existing flag is enabled.
- The control plane obtains a Google-signed ID token for audience
  `superserve-vmd-host-admission`. The VMD verifies signature, audience,
  expiration, verified email, and the configured principal. The VMD's shared
  internal API token cannot authorize this RPC; the operator token never goes
  to the VMD.
- New enrollment starts admission **closed**. Existing lifecycle work remains
  usable. Once reconciliation is complete, explicitly activate through hostctl.
- Persisted state is `${VMD_STATE_PATH}.admission.json` (default alongside
  `vmd.db`). Keep this on durable host storage. A corrupt/unreadable file aborts
  startup. An existing file keeps the fence enabled even if the enrollment flag
  is omitted. Do not delete it or roll back to a binary that ignores it.

No production rollout or host transition is performed by this change.

## Existing staging primary: deploy only this host

An omitted runtime input preserves the stored value only when the host passes
all existing-host checks. A loaded legacy unit alone is not fresh enrollment:
an inactive, disabled `agentbox-vmd.service` alongside the loaded, active modern
VMD is an existing-host upgrade when both env files, required settings and the
cell CA pair are complete and no bootstrap-pending marker exists. Active/enabled
legacy units, an unavailable modern VMD, or incomplete runtime state still take
the guarded fresh-host path. Do not bypass that path with an upgrade-mode flag.

The earlier preflight classified a disabled legacy leftover as fresh. Supplying
secrets did not correct that classification and could lead to the guest-workload
retirement gate. Use the corrected script from this branch. It preserves
`HOST_ID=default` and the installed credentials; it does not retire or mask the
inactive legacy leftover during an existing-host upgrade.

After the database and control-plane prerequisites above are complete, run this
from the reviewed branch checkout. This command builds and **deploys**; it is
not a preflight. The name clause intersects the serving label and region, so the
second staging host cannot be selected. Do not replace it with the serving label
alone after both hosts are admitted.

```sh
(
  set -eu
  export GCP_PROJECT=rayai-dev GCP_REGION=us-central1
  export VMD_LABEL='component=vmd AND name=superserve-vmd-staging'
  export VMD_SERVICE=superserve-vmd VMD_INSTALL_DIR=/usr/local/bin
  export SHA="$(git rev-parse HEAD)"
  export CONTROL_PLANE_URL= DATABASE_URL= INTERNAL_API_TOKEN=
  export VMD_DRAIN_ENABLED=true
  export VMD_ADMISSION_CALLER_EMAIL="$(gh variable get VMD_ADMISSION_CALLER_EMAIL_STAGING \
    --repo superserve-ai/sandbox --env staging)"
  : "${VMD_ADMISSION_CALLER_EMAIL:?Configure the verified staging control-plane runtime service-account email first}"
  # Match the staging workflow; omission otherwise removes the backfill flag.
  export BACKUP_BACKFILL=1
  mkdir -p bin
  for binary in vmd boxd template-builder secretsproxy; do
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
      -ldflags '-s -w' -trimpath -o "bin/$binary" "./cmd/$binary"
  done
  python3 .github/workflows/scripts/deploy-vmd.py
)
```

No secret retrieval is needed for this verified existing-host path. If runtime
state is incomplete, stop and investigate rather than filling secrets manually.
The staging workflow's canonical inputs are `vars.CONTROL_PLANE_URL_STAGING`,
`secrets.DATABASE_URL_STAGING`, and `secrets.STAGING_INTERNAL_API_TOKEN`, injected
by the GitHub `staging` environment. GitHub secret values are not downloadable
with `gh secret`; do not invent a local extraction or distribution mechanism.
The workflow's `target=serving` currently selects all matching serving hosts, so
it is **not** a substitute for this one-host command.

## Operator sequence

Use the same cell's control-plane URL and operator token already required by
hostctl. Do not put tokens in command-line arguments or shell history.

```sh
# Existing environment: CONTROL_PLANE_URL and OPERATOR_API_TOKEN.
hostctl drain-status <host-id>
hostctl drain <host-id>
hostctl drain-status <host-id>
# When returning the same healthy host to service:
hostctl activate <host-id>
```

A successful drain response acknowledges the persisted host fence. Cached
scheduler decisions cannot create a new charge after that acknowledgement.
Work admitted before the fence may finish; the ledger retains its charge.
Creates retrying an already-held identity are not a new admission. A definitive
pre-boot refusal permits one attempt on a different eligible host, guarded by
a compare-and-set on an unactivated starting row. Plain transport errors, generic
resource exhaustion, or any earlier ambiguous retry never authorize that switch. Template
builds are refused while closed. Resume remains pinned to its existing owner.

Each transition first records a monotonically ordered revision and desired
status in the database, then sends that revision to the daemon. Draining is
excluded from scheduler queries immediately at that database write. Activation
requires a fresh heartbeat and completed host reconciliation. Old commands
cannot overwrite a newer persisted fence. Lost acknowledgement or DB/network
failure returns an error; retry the operation and inspect its new revision.
A failed open never triggers an implicit reopen or service restart.

`hostctl --wait drain` retains the earlier quiet-window progress behavior. Its
success is **not** retirement approval. Use `drain-status` for per-status
ownership, the live gate revision, readiness and charged work. Failed, paused
and unknown ownership must not disappear from the count just because no guest
is currently running.

## Safe to power off

Every condition must hold while the same drain revision remains current:

1. Directory status is draining and its revision matches a confirmed durable
   closed host gate; prevent concurrent operator reactivation during maintenance.
2. Reconciliation is complete, with zero pending/charged boot, restore and build
   work, and no in-flight lifecycle operations.
3. There are zero non-destroyed ownership rows in **every** status, including
   paused and failed, plus zero live builds or exclusive artifact dependencies.
4. Local inspection confirms no orphan guests/Firecracker units, open sandbox
   streams, unfinished cleanup, backup/report obligations, or sole-copy restore
   state remains on the disk.
5. Local and control-plane inventories agree and no recovery/ownership operation
   targets the host. Missing, stale or unreachable evidence blocks retirement.

```sh
hostctl retire-check <host-id>
```

The implemented endpoint reports admission and ownership evidence but **does not
certify condition 4 or all artifact dependencies**. Consequently `retire-check`
fails closed and reports the required local audit even when automated counts
are zero. It never powers off a VM. Do not interpret quiet counts, backed paused
sandboxes, or a previously successful drain response as a power-off permit.
A separate reviewed retirement procedure must establish the remaining evidence.

## Staging rehearsal

After an explicitly approved rollout, drain one chosen host while both proxies
remain enabled. Confirm new creates use the other host, existing exec/files and
long-lived streams remain usable, and a paused sandbox resumes on its original
owner. Exercise concurrent drain/activate and lost-ack retries. Reactivate the
same host and confirm placement returns. Do not migrate ownership or change
`sandbox.host_id` during this rehearsal.
