# latencybench — tiered-hibernation wake-latency harness

Host-side benchmark driver for Epic 1.1. It measures **wake trigger → first
meaningful operation** latency across the three hibernation tiers and decides the
go/no-go gates in [`.context/VALIDATION-latency.md`](../../.context/VALIDATION-latency.md).

> The thesis "hibernate between turns" rests on one number: **Tier-1 wake p99 < 10ms.**
> This harness exists to answer that, not to be broad. See the validation plan for
> the methodology; this README covers how to run the code.

Paired with [`cmd/probe-guest`](../probe-guest), the tiny in-VM probe that holds a
realistic working set and reports first-op completion.

---

## The metric (read this first)

We measure **"first meaningful operation," not "Firecracker resume returned."**
Firecracker's resume/load API returns in ~1ms while the guest has faulted in *none*
of its working set. With UFFD the page-in cost doesn't vanish — it moves from
before-first-instruction to during-the-first-turn. So the only honest number is
end-to-end:

```
wake trigger issued ──▶ guest faults in its working set ──▶ first op completes ──▶ measured
```

`probe-guest` makes this concrete: on a wake trigger it re-touches its working set
(forcing page faults on Tier 2/3) and does a read+write on `/state`, then prints
`FIRST_OP_DONE <nanos>`. That nanos value is `T_guest`, the tail of the wake.

---

## The tiers

| Tier | Name | Mechanism | Gate |
|---|---|---|---|
| **1** | Paused-in-RAM | Firecracker `PATCH /vm` Paused→Resumed; RAM resident, `/state` mounted, network attached, lease held | **wake p99 < 10ms** |
| **2** | Local snapshot + UFFD | Snapshot to host NVMe, reclaim RAM, restore with UFFD mem-backend; page-in lazily on touch | wake p99 < 50ms |
| **3** | Cold / cross-host | Snapshot + state in object storage, restore on a *different* host, attach `/state` there | wake p50 < 1s / p99 < 2s |

Tier 1 is the decision. Tiers 2/3 only matter if Tier 1 passes.

---

## Per-phase decomposition

A total number passes or fails a gate; the decomposition tells you *what to fix*.
Each wake is split into (`.context/VALIDATION-latency.md` §2.3):

| Phase | Meaning | Tiers |
|---|---|---|
| `T_control` | lease acquire + schedule/route (control plane) | all |
| `T_fetch` | snapshot bytes → local | 3 only |
| `T_attach` | `/state` volume mount (Mesa/Archil) | 3 only |
| `T_load` | Firecracker build VM + load snapshot + UFFD up | 2/3 |
| `T_resume` | Firecracker `PATCH /vm` Resumed | all |
| `T_net` | network reattach (tap/veth/nftables) if on the wake path | all |
| `T_guest` | guest faults in working set + does the first op → resp | all |

The output table (matching §6) reports `T_wake` as p50/p90/p99 and each phase as
its p50 median.

---

## Running

Build (the real target is Linux; it also builds on the dev host):

```sh
GOOS=linux GOARCH=amd64 go build ./cmd/probe-guest/... ./cmd/latencybench/...
go test ./cmd/latencybench/...
```

### Stub provider (no VM, synthetic) — default

```sh
go run ./cmd/latencybench -provider=stub -iterations=1000
```

Sweeps the full matrix and renders the results table. **The numbers are SYNTHETIC
and clearly labeled as such** — the harness prints a banner and the table header
says `provider: stub (SYNTHETIC — not measured)`. Use this to exercise the sweep,
percentile math, gates, and table rendering end-to-end without a VM. `-seed`
makes it deterministic.

Narrow the sweep with the matrix flags:

```sh
go run ./cmd/latencybench -provider=stub \
  -tiers=1 -mem=2048 -ws=512 -cache=warm,cold -contention=1,8,32 -iterations=1000
```

| Flag | Default | Meaning |
|---|---|---|
| `-provider` | `stub` | `stub` (synthetic), `firecracker` (real Tiers 1/2/3), or `vmd` (real — not wired) |
| `-iterations` | `1000` | iterations per matrix cell (plan asks ≥1000) |
| `-tiers` | `1,2,3` | tiers to sweep |
| `-mem` | `512,2048,8192` | guest memory sizes (MiB) |
| `-ws` | `128,512,1024` | working-set sizes (MiB) |
| `-cache` | `warm,cold` | host page-cache arms |
| `-contention` | `1,8,32` | paused-VMs-per-core (Tier-1 density test) |
| `-seed` | `1` | stub RNG seed (deterministic) |
| `-fc-bin` `-kernel` `-rootfs` | — | firecracker binary / guest vmlinux / read-only rootfs.ext4 (firecracker provider) |
| `-objstore` | — | Tier-3 snapshot transport: `gs://bucket[/prefix]` (real cross-host fetch) or `local[:/path]` (same-host floor) |

### firecracker provider (real) — Tiers 1, 2 and 3

Requires a Linux KVM host (`/dev/kvm`), the firecracker binary, a guest kernel,
and a rootfs. Tiers 1 and 2 need no object store; Tier 3 needs `-objstore`.

> **Tiers 2 and 3 vary only with `-mem`** in this provider — the snapshot is
> reused by mem size, so `-ws`, `-cache`, and `-contention` are not exercised
> there (only Tier-1 uses `-contention`). Pin them to one value each when sweeping
> Tiers 2/3, or the default matrix re-runs byte-identical cells under different
> labels. See `RESULTS.md`.

```sh
# Tier 1 (bare pause/resume under contention) — contention is the Tier-1 density axis:
latencybench -provider=firecracker \
  -fc-bin=/usr/local/bin/firecracker -kernel=<vmlinux> -rootfs=<base.ext4> \
  -tiers=1 -mem=512 -ws=128 -cache=cold -contention=1,8,32 -iterations=200

# Tier 2 (local snapshot restore) — sweep mem only:
latencybench -provider=firecracker \
  -fc-bin=/usr/local/bin/firecracker -kernel=<vmlinux> -rootfs=<base.ext4> \
  -tiers=2 -mem=512,2048 -ws=128 -cache=cold -contention=1 -iterations=50

# Tier 3 (cold cross-host): stage the snapshot in real object storage and fetch
# it back each iteration. The host's service account needs roles/storage.objectAdmin
# on the bucket. Use local:/path instead of gs:// for the same-host restore floor.
latencybench -provider=firecracker \
  -fc-bin=/usr/local/bin/firecracker -kernel=<vmlinux> -rootfs=<base.ext4> \
  -tiers=3 -mem=512,2048 -ws=128 -cache=cold -contention=1 \
  -objstore=gs://<bucket>/<prefix> -iterations=20
```

The Tier-3 fetch is an **in-process HTTP GET** (resident client, cached
metadata-server bearer token), deliberately *not* `gcloud storage cp` — a CLI
spawn costs ~1.1s and would dominate the measurement. See `RESULTS.md` for the
measured ~230 MiB/s single-stream ceiling and why eager whole-mem fetch fails the
<1s gate for realistic VM sizes.

### vmd provider (real) — not wired yet

```sh
go run ./cmd/latencybench -provider=vmd   # returns "not wired yet" per cell
```

This is the real measurement path. It is **intentionally unimplemented** here:
this dev box has no KVM, and faking the numbers would defeat the benchmark. Each
cell records `ErrVMDNotWired` and the table shows it, so it's obvious nothing was
measured.

---

## probe-guest

Runs inside the VM and is captured in the snapshot.

```sh
# stdin trigger mode (simplest, avoids network on the measured path):
probe-guest -working-set-mib=512 -state-dir=/state
#   prints "READY ..." then waits; write one byte to stdin per trigger;
#   prints "FIRST_OP_DONE <nanos> pages=<n>" per trigger.

# HTTP trigger mode:
probe-guest -working-set-mib=512 -state-dir=/state -addr=:7070
#   GET /probe returns "FIRST_OP_DONE <nanos> pages=<n>".
```

| Flag | Default | Meaning |
|---|---|---|
| `-working-set-mib` | `512` | working set to allocate + touch (loaded-harness footprint) |
| `-state-dir` | `/state` | durable FS exercised on the wake path |
| `-addr` | (empty) | if set, serve trigger over HTTP `GET /probe`; else read a byte from stdin |
| `-touch-stride` | `1` | touch every Nth page on wake (1 = whole working set) |
| `-one-shot` | `false` | stdin mode: handle one trigger then exit |

Because the probe is *in the snapshot*, it answers immediately on thaw. If the
harness had to re-exec instead, the first op would show up as a multi-second
outlier — exactly the SPEC §4.5 #1 failure mode the benchmark should catch.

---

## What's real vs stubbed

**Real (and unit-tested):**

- Percentile math — `stats.go`. **Nearest-rank** on a 0-based sorted slice:
  `idx = ceil(p/100 · n) − 1`, clamped to `[0, n−1]`. Always returns an observed
  sample, never an interpolation. Tested against hand-computed p50/p90/p99 for
  `1..10`, `1..100`, shuffled input (ordering not assumed, input not mutated),
  single-sample, and empty.
- Matrix expansion + flag parsing — `tiers.go`, tested for count, order, and
  validation errors.
- Gate evaluation — `tiers.go`, tested at each threshold boundary.
- Phase decomposition, sweep driver, and results-table rendering — `main.go`,
  `render.go`.
- `probe-guest` working-set allocation/touch + first-op (page-in + `/state`
  read/write) timing.

**Stubbed (clearly labeled, never presented as a measurement):**

- `stubProvider` (`provider_stub.go`) — synthetic per-phase timings drawn from a
  seeded RNG with lognormal jitter and rare tail spikes, scaled per tier and
  working set. Banner + table label mark it as `SYNTHETIC — not measured`.
- `vmdProvider` (`provider_vmd.go`) — the real path. Returns `ErrVMDNotWired`. The
  type doc is the integration spec: which `internal/vm` API each phase wraps, with
  `TODO`s.

---

## What's needed to run it for real (against vmd)

You need a **Linux KVM host** and the `vmdProvider.Wake` integration implemented.
Per-tier seams (see `provider_vmd.go` for the detailed `TODO`s):

1. **Tier 1 — bare pause/resume.** Add a Firecracker `PATCH /vm {state:Paused}` →
   `{state:Resumed}` path in `internal/vm` *distinct from* the snapshot-based
   `Manager.PauseVM` (`manager.go`, which snapshots to disk and stops the unit —
   too heavy). `firecracker.go` already has the FC client plumbing to add a
   `PatchVMState` helper. Keep the netns attached while paused so `T_net` ≈ 0.
2. **Tier 2 — UFFD restore.** Wire `RestoreSnapshotUffdInternalWithOverrides`
   (`firecracker.go`) plus an external UFFD page handler. A/B against eager load
   (`RestoreSnapshot`) to quantify the UFFD win.
3. **Tier 3 — cross-host.** Push snapshot + state to object storage, restore on a
   second host, attach `/state` there. Time `T_fetch` (transport) and `T_attach`
   (mount) independently; run **Mesa vs Archil** side by side — that comparison
   picks the state backend.
4. **Guest probe wiring.** Drive `probe-guest` to first-op (stdin byte over
   vsock/boxd, or HTTP `GET /probe`) and parse `FIRST_OP_DONE <nanos>` into
   `T_guest`. Keep the trigger transport off the network-reattach path so its cost
   stays in `T_net`, not `T_guest`.
5. **Confounders (§4).** `cold` arm: drop host page cache (and for Tier 3 evict the
   local snapshot) before each iteration. Contention arms: hold K paused VMs/core
   resident during Tier-1 wakes. Cross-check the probe's guest monotonic clock
   against the host clock to catch thaw clock-skew. Pull VMM-internal phase timings
   from Firecracker metrics where the host clock can't see inside load/resume.
