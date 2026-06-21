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
- Tier 2 (UFFD snapshot restore, gate <50ms) and Tier 3 (cold cross-host +
  `/state` attach, gate <1s/2s) still need the probe-driven `T_guest` path wired —
  that is where the `cmd/probe-guest` first-meaningful-op correlation matters.
- To reproduce: `latencybench -provider=firecracker -fc-bin=/usr/local/bin/firecracker
  -kernel=<vmlinux> -rootfs=<base.ext4> -tiers=1 -mem=512 -ws=128 -cache=warm
  -contention=1,8,32 -iterations=200`.
