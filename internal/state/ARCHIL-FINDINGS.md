# Archil integration — verified findings (real disk, GCP)

Hands-on validation of Archil as the durable `/state` backend (Epic 4.1 input),
run from `superserve-vmd-staging` (GCP us-central1) against a real Archil disk.

## Verified working recipe

1. **Control plane is region-celled.** The GCP us-central1 control plane is
   `https://control.blue.us-central1.gcp.prod.archil.com` (cell is `blue`, not
   the docs' AWS `green`). The API key is **region-scoped** — it returns
   `Unauthorized` against the AWS endpoint.
2. **Create a disk:** `POST /api/disks` with header `Authorization: key-<API_KEY>`
   and body `{"name":"..."}` → `{"data":{"diskId":"dsk-..."}}`.
3. **Mint a mount token** (required on non-AWS hosts — see auth note):
   `POST /api/disks/{id}/users` with `{"type":"token","nickname":"..."}` →
   `{"data":{"token":"adt_..."}}` (shown once).
4. **Mount:** `sudo ARCHIL_DISK_TOKEN=<adt_...> archil mount <dsk-id> /mnt/archil
   --region gcp-us-central1` (install CLI via `curl https://archil.com/install | sh`).
   Mounts a FUSE filesystem. Verified: `✓ Successfully mounted`.

### Auth gotcha (important for the host-side mount in the Actor model)
The `archil` CLI defaults to **AWS IMDS/STS** for IAM credentials. On a GCP host
the AWS IMDS token path 405s, so IAM auth fails with "Unable to determine the
correct AWS region for pre-signing STS requests." **Use token auth**
(`ARCHIL_DISK_TOKEN`) on GCP/non-AWS hosts. Treat the disk token like a secret
(inject as a binding, never write to `/state`).

## Measured latency (single client, warm cache, GCP same-region)

| op | latency |
|---|---|
| small file write + `sync` (warm) | **~7–8 ms** |
| small file write + `sync` (cold/first) | ~26 ms |
| 1 MiB write, `oflag=dsync` | ~26 ms (≈40 MB/s) |

## Architecture implications for the Actor model

- **Archil writes are NOT on the <10ms between-turns hot path.** ~7–8ms warm
  fsync is comparable to the *entire* Tier-1 wake budget (measured ~0.1–0.3ms for
  the VM resume itself). This confirms `SPEC §9.1` / the validation plan: keep
  durable-state writes off the between-turns path; **checkpoint at boundaries**,
  and rely on the resident page cache during a turn. Tier-1 hibernation must keep
  `/state` mounted+warm, not re-mount on wake.
- The mount is per-disk (one disk per durable Actor identity), matching the
  `Provider.Mount(identity, ...)` contract in `provider.go`.

## Not yet validated / next

- **Durability-across-remount was inconclusive:** a file written then read after
  unmount+remount was missing — but a *failed* `checkpoints create` (wrong CLI
  args → `InvalidArguments`) disrupted the clean unmount/flush first. Needs a
  clean write → `sync` → graceful `unmount` → remount cycle to conclude. Re-test
  before trusting Archil for crash-durability; the LocalProvider reference
  semantics (`local.go`) are the bar to match.
- Checkpoint/branch CLI arg form (`archil checkpoints create <mnt> <name>`)
  returned `InvalidArguments`; confirm the exact subcommand syntax/version.
- In-guest (Firecracker) mount needs a FUSE-enabled kernel — the staging host
  already ships `vmlinux-4.14-fuse` for this.

## Wiring `ArchilProvider` (archil.go) for real

Shell out to the verified commands: `Mount` → `archil mount` with
`ARCHIL_DISK_TOKEN`; `Checkpoint`/`Branch` → `archil checkpoints/branches`
(confirm arg form); disk lifecycle (`create`/token/delete) → the REST API above.
Config needed: `ARCHIL_API_KEY`, region, per-identity `disk_id` (+ minted token).
