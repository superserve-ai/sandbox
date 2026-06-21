# Tier-1 wake-latency results (real Firecracker)

> Measured with `latencybench -provider=firecracker` (see `provider_firecracker.go`)
> on a real KVM host. This is the **go/no-go gate** from `VALIDATION-latency.md §0`:
> **Tier-1 wake p99 < 10ms** decides whether between-turns hibernation — and thus
> the whole Actor model — is viable.

## Verdict: PASS — by ~30–40×.

Bare Firecracker pause/resume (`PATCH /vm {"state":"Paused"} → {"state":"Resumed"}`,
memory left RAM-resident) wakes in **~100–235µs p50 / <350µs p99**, and stays flat
as the number of co-resident paused VMs grows from 1 to 128. Hibernating an Actor
between turns is comfortably viable.

## Numbers

Host: `superserve-vmd-staging` (GCP, 32 vCPU, 125 GiB RAM, Ubuntu 6.17 GCP kernel,
Firecracker v1.15.0), **shared with ~10–15 live staging VMs** during the run (so
these are upper bounds; a quiet host would do better). Guest: `vmlinux-5.10` +
the staging `base.ext4` mounted read-only, no network interface.

| contention (paused VMs resident) | mem | iters | p50 | p90 | p99 | gate (<10ms) |
|---|---|---|---|---|---|---|
| 1   | 512M | 200 | 100µs | 120µs | 231µs | **PASS** (~43×) |
| 8   | 512M | 200 | 186µs | 238µs | 278µs | **PASS** |
| 32  | 512M | 200 | 207µs | 237µs | 267µs | **PASS** (~37×) |
| 64  | 256M | 100 | 235µs | 278µs | 341µs | **PASS** |
| 128 | 256M | 100 | 236µs | 274µs | 310µs | **PASS** (~32×) |

Resume latency is essentially flat vs. contention — packing many paused VMs on a
host does not slow an individual wake.

## Tier-2 (snapshot restore) — also PASSES

Cold-from-disk restore: a Full snapshot (state + memory file) is created once,
then each iteration boots a **fresh** Firecracker that loads the snapshot with an
eager File mem-backend and resumes (RAM reclaimed between iterations).

| mem | iters | p50 | p99 | gate (<50ms) |
|---|---|---|---|---|
| 512M  | 50 | 2.13ms | 2.72ms | **PASS** (~18×) |
| 1024M | 50 | 2.15ms | 2.87ms | **PASS** |

Caveat: the guest here boots `base.ext4` to a small resident set (tens of MB), so
the mem file loads fast and the number is flat vs. configured mem size. A
realistic agent with a few hundred MB resident will read a larger mem file on the
eager path — that is exactly where **UFFD lazy page-in** (Tier-2's optimization,
the 1.4 A/B) moves the page-in cost off the restore and into the first turn. The
~2–3ms here is the floor; the UFFD vs eager comparison at large working sets is
the remaining Tier-2 measurement.

## Tier-3 (cold cross-host) — FAILS eagerly; the fetch is the whole story

Tier-3 stages the snapshot (state + memory file) in **real object storage** (a
same-region GCS bucket) and, each iteration, **fetches it to a fresh local dir
before restoring** — the cross-host model, where a *different* host pulls the
bytes it doesn't have. The provider fetches with an **in-process HTTP GET** (a
resident client with a cached bearer token), not `gcloud storage cp` — see the
methodology note below for why that distinction is load-bearing.

| mem (full mem file fetched) | ws | iters | T_fetch p50 | T_load p50 | T_wake p50 / p99 | gate (<1s / <2s) |
|---|---|---|---|---|---|---|
| 512M  | 128M | 20 | **2.459s** | 2.46ms | 2.461s / 3.466s | **FAIL** |
| 2048M | 512M | 20 | **8.116s** | 2.35ms | 8.118s / 11.385s | **FAIL** |

The wake is **~99.9% T_fetch** (2.459s of 2.461s). The restore itself (`T_load`,
Firecracker loading the snapshot once bytes are local) is a flat **~2.4ms** — the
same floor as Tier-2. Fetch scales with the bytes moved: 512 MiB / 2.46s ≈ 208
MiB/s, 2048 MiB / 8.12s ≈ 252 MiB/s — **single-stream GCS GET throughput of
~210–250 MiB/s**. (n=20 per row, below the plan's ≥1000-iter floor; with
nearest-rank percentiles on 20 samples the p99 column is literally the single
worst draw, so treat the tails as indicative — the **FAIL is driven by p50**,
which is stable and ~2.5×/8× over the 1s gate.)

**Verdict and what it means for the design.** A *naive* Tier-3 — eager
whole-mem-file fetch over a single HTTP stream — meets the <1s gate only for tiny
VMs. The binding p50 crossover, scaled from the measured 512 MiB / 2.461s point
(the slower ~208 MiB/s stream the small VM actually got), is **~208 MiB of *mem
file*** — note this is the full configured-mem snapshot moved, **not** the working
/ resident set (the eager `File` backend fetches every page regardless of working
set). So Tier-3 **fails for any realistic agent** (a 512 MiB–2 GiB mem file is
2.5–8s of pure transfer). This is not a restore problem; it is a **bytes-moved ÷
bandwidth** problem, and it points squarely at the three levers the architecture
already specifies:

1. **Lazy page-in over the network** (UFFD remote mem-backend): fetch only the
   working set on first touch, not the whole mem file, and hide it inside
   `T_guest`. Upper bound drops from `mem` to `ws`.
2. **Parallel / ranged fetch**: GCS serves ranged GETs; multi-stream download
   lifts the ~230 MiB/s single-stream ceiling several-fold.
3. **Warm regional snapshot cache** on the target host's NVMe: the cross-host
   fetch is paid only on a true cold migration, never in steady state (where the
   wake degrades to the Tier-2 ~2.4ms local restore measured above).

The benchmark now isolates exactly this: with `-objstore=local:` (a same-host
copy, no network) the *same* 512 MiB Tier-3 path restores in **157ms total**
(T_fetch 155ms copy + T_load 2.2ms) and **PASSES** — confirming the restore
mechanics are sound and the gate failure is purely the network-fetch long pole.

### Methodology note — why in-process HTTP, not `gcloud storage cp`

The first Tier-3 implementation shelled out to `gcloud storage cp`. It reported a
**flat ~2.4s T_fetch at *both* 128 MiB and 512 MiB** — a red flag: fetch latency
that ignores payload size is not measuring transfer. The cause: each `gcloud`
invocation spends ~1.1s on Python interpreter + auth startup (measured directly:
a 12-byte object `cp` took 1.07s; the same object over in-process HTTP took
52ms), and Download issues two `cp` calls. The CLI spawn was dwarfing the bytes.
A production wake path would never fork a CLI per fetch, so the provider was
rewritten to fetch in-process over HTTP with a metadata-server bearer token —
which is both faithful and what surfaced the real ~230 MiB/s bandwidth ceiling.

## What is measured (and why it's faithful)

The measured quantity is the **in-process latency of the `PATCH /vm Resumed` call**.
For *true* Tier 1, this is the wake cost: under `PATCH Paused` the guest's memory is
never evicted, so resume faults in **zero pages** — there is no page-in to hide. The
"first meaningful op, not resume-returned" concern from the validation plan applies
to **Tier 2/3**, where snapshot-restore page-in dominates and must be measured
against the in-guest probe (`cmd/probe-guest`); it is not a factor here.

The provider holds all `contention` VMs paused-and-resident throughout each
measurement (the density test), boots them with no network interface and a
read-only shared rootfs (so it never touches the host's live vmd networking or
state), and tears every VM down on exit (verified: empty rundir, no leaked procs).

## Caveats / next

- Absolute numbers are upper bounds (shared staging host).
- **The firecracker provider's Tier-2/Tier-3 wakes vary only with `mem`.** The
  snapshot is keyed and reused by mem size, so the `ws`, `cache`, and `contention`
  axes are *not exercised* on these tiers — a `cache=cold` and a `cache=warm`
  Tier-3 cell run the identical fetch (the cross-host fetch is unconditionally
  cold; there is no warm regional-cache fast path yet), and different `ws` values
  fetch the same full mem file. When sweeping Tiers 2/3 with this provider, **pin
  `-ws`, `-cache`, and `-contention` to one value each** (as the commands below
  do) — the full default matrix would re-run byte-identical cells under different
  labels. Only Tier-1 uses `contention` (the density test); `ws`/`cache` await the
  probe-driven `T_guest` + a warm-cache arm.
- The Tier-3 staging upload is a single XML-API PUT (≤5 GiB per object), so a mem
  file larger than ~5 GiB can't be staged this way — Tier-3 here is capped at
  ~5 GiB of configured guest memory until chunked/resumable upload is added.
- Tier-3 here fetches the **whole** mem file eagerly (the worst case). The next
  measurement is the lazy-page-in A/B: a UFFD mem-backend that fetches only the
  working set on demand, which should move most of `T_fetch` into `T_guest` and is
  the path to actually clearing the <1s gate. That needs the probe-driven
  `T_guest` wired (`cmd/probe-guest`), same as the Tier-2 UFFD-vs-eager A/B.
- Tier-3's `T_attach` (the `/state` volume mount on the target host) is not yet on
  the measured path — it reads 0 above because the bench restores without a
  cross-host `/state` reattach. Wiring the Archil/Mesa mount into the Tier-3 path
  is the remaining decomposition gap.
- To reproduce Tier 1: `latencybench -provider=firecracker -fc-bin=/usr/local/bin/firecracker
  -kernel=<vmlinux> -rootfs=<base.ext4> -tiers=1 -mem=512 -ws=128 -cache=warm
  -contention=1,8,32 -iterations=200`.
- To reproduce Tier 3 (real cross-host fetch): add `-tiers=3
  -objstore=gs://<bucket>/<prefix>` (the host's service account needs
  `roles/storage.objectAdmin` on the bucket). Use `-objstore=local:/path` for the
  same-host restore floor (no network).
