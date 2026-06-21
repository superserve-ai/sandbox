// Command latencybench is the host-side driver for the tiered-hibernation latency
// benchmark described in .context/VALIDATION-latency.md.
//
// It exists to answer exactly one set of go/no-go questions (§0 of the plan):
//
//	Tier 1 (paused-in-RAM):        wake p99 < 10ms   — the gate that decides everything
//	Tier 2 (local snapshot+UFFD):  wake p99 < 50ms
//	Tier 3 (cold / cross-host):    wake p50/p99 < 1s / 2s
//
// The driver sweeps the matrix from §2.2 (tiers × mem × working-set × cache-state
// × concurrency), runs N iterations per cell, decomposes each wake into per-phase
// spans (T_control, T_fetch, T_attach, T_load, T_resume, T_net, T_guest), and
// renders the results table from §6.
//
// IMPORTANT — what is real vs stubbed:
//
//   - The measurement scaffolding (phase decomposition, percentile math, matrix
//     expansion, results rendering) is REAL and unit-tested.
//   - The actual wake against Firecracker/vmd is NOT wired here. This box has no
//     KVM. The vmd provider is a documented stub that returns "not wired yet" and
//     points at the internal/vm resume/restore APIs that must be called. To run it
//     for real you need a Linux KVM host with that provider implemented.
//   - A `-provider=stub` mode emits SYNTHETIC, clearly-labeled per-phase timings so
//     you can exercise the harness end-to-end (table rendering, gates, sweeps)
//     without a VM. Stub numbers are NOT measurements and the output says so.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

func main() {
	cfg := defaultConfig()

	var (
		providerName = flag.String("provider", "stub", "wake provider: 'stub' (synthetic, no VM), 'firecracker' (real bare pause/resume, Tier 1), or 'vmd' (real Firecracker/vmd — not wired yet)")
		iterations   = flag.Int("iterations", 1000, "iterations per matrix cell (the plan asks for >=1000)")
		seed         = flag.Int64("seed", 1, "RNG seed for the stub provider (deterministic output)")
		tiersFlag    = flag.String("tiers", "1,2,3", "comma-separated tiers to sweep")
		memFlag      = flag.String("mem", "512,2048,8192", "comma-separated guest mem sizes in MiB")
		wsFlag       = flag.String("ws", "128,512,1024", "comma-separated working-set sizes in MiB")
		cacheFlag    = flag.String("cache", "warm,cold", "comma-separated cache states: warm,cold")
		concFlag     = flag.String("contention", "1,8,32", "comma-separated paused-VMs-per-core values")

		// Real-firecracker provider config (only used with -provider=firecracker).
		fcBin    = flag.String("fc-bin", "firecracker", "path to the firecracker binary")
		fcKernel = flag.String("kernel", "", "path to the guest kernel (vmlinux) — required for -provider=firecracker")
		fcRootfs = flag.String("rootfs", "", "path to a rootfs.ext4 mounted read-only — required for -provider=firecracker")
		fcRunDir = flag.String("fc-rundir", "/tmp/latencybench-run", "scratch dir for per-VM api sockets")
	)
	flag.Parse()

	matrixCfg, err := parseMatrixFlags(*tiersFlag, *memFlag, *wsFlag, *cacheFlag, *concFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "latencybench: bad matrix flags: %v\n", err)
		os.Exit(2)
	}
	cfg.Matrix = matrixCfg
	cfg.Iterations = *iterations

	provider, err := selectProvider(*providerName, *seed, fcProviderConfig{
		bin: *fcBin, kernel: *fcKernel, rootfs: *fcRootfs, runDir: *fcRunDir,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "latencybench: %v\n", err)
		os.Exit(2)
	}
	// Tear down real providers (kills booted firecracker processes) on exit.
	if c, ok := provider.(io.Closer); ok {
		defer c.Close()
	}

	if _, isStub := provider.(*stubProvider); isStub {
		fmt.Fprintln(os.Stderr, "==> provider=stub: numbers below are SYNTHETIC, not measurements.")
	}

	results, err := run(context.Background(), provider, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "latencybench: run failed: %v\n", err)
		os.Exit(1)
	}

	renderTable(os.Stdout, results, provider.Label())
}

// fcProviderConfig carries the real-firecracker provider's paths from flags.
type fcProviderConfig struct {
	bin, kernel, rootfs, runDir string
}

func selectProvider(name string, seed int64, fc fcProviderConfig) (WakeProvider, error) {
	switch name {
	case "stub":
		return newStubProvider(seed), nil
	case "firecracker":
		return newFirecrackerProvider(fc.bin, fc.kernel, fc.rootfs, fc.runDir)
	case "vmd":
		return newVMDProvider(), nil
	default:
		return nil, fmt.Errorf("unknown provider %q (want 'stub', 'firecracker', or 'vmd')", name)
	}
}

// run executes the full sweep: for each matrix cell it runs cfg.Iterations wakes,
// collects per-phase timing samples, and summarizes them. Cells whose provider
// returns an error (e.g. the vmd stub) are recorded with that error so the table
// can show why nothing was measured.
func run(ctx context.Context, p WakeProvider, cfg Config) ([]CellResult, error) {
	cells := cfg.Matrix.Expand()
	out := make([]CellResult, 0, len(cells))

	for _, cell := range cells {
		res := CellResult{Cell: cell}
		samples := newPhaseSamples(cfg.Iterations)

		for i := 0; i < cfg.Iterations; i++ {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			pt, err := p.Wake(ctx, WakeParams{Cell: cell, Iteration: i})
			if err != nil {
				res.Err = err
				break
			}
			samples.append(pt)
		}

		if res.Err == nil {
			res.Wake = summarize(samples.total)
			res.Phases = samples.summarizePhases()
			res.Gate = evaluateGate(cell.Tier, res.Wake)
		}
		out = append(out, res)
	}
	return out, nil
}

// Config bundles the sweep configuration.
type Config struct {
	Matrix     Matrix
	Iterations int
}

func defaultConfig() Config {
	return Config{Iterations: 1000}
}

// CellResult is the summarized outcome for one matrix cell.
type CellResult struct {
	Cell   Cell
	Wake   Percentiles
	Phases PhaseSummary
	Gate   GateResult
	Err    error
}

// phaseSamples accumulates raw per-phase samples across iterations so each phase
// can be summarized independently (the decomposition that tells you what to fix).
type phaseSamples struct {
	total   []time.Duration
	control []time.Duration
	fetch   []time.Duration
	attach  []time.Duration
	load    []time.Duration
	resume  []time.Duration
	net     []time.Duration
	guest   []time.Duration
}

func newPhaseSamples(capHint int) *phaseSamples {
	mk := func() []time.Duration { return make([]time.Duration, 0, capHint) }
	return &phaseSamples{
		total: mk(), control: mk(), fetch: mk(), attach: mk(),
		load: mk(), resume: mk(), net: mk(), guest: mk(),
	}
}

func (s *phaseSamples) append(pt PhaseTimings) {
	s.total = append(s.total, pt.Total())
	s.control = append(s.control, pt.Control)
	s.fetch = append(s.fetch, pt.Fetch)
	s.attach = append(s.attach, pt.Attach)
	s.load = append(s.load, pt.Load)
	s.resume = append(s.resume, pt.Resume)
	s.net = append(s.net, pt.Net)
	s.guest = append(s.guest, pt.Guest)
}

// PhaseSummary holds the p50 of each phase. The per-phase decomposition in the
// results table reports medians (the table is already dense; tails are reported on
// the total, which is what the gate is decided on).
type PhaseSummary struct {
	Control time.Duration
	Fetch   time.Duration
	Attach  time.Duration
	Load    time.Duration
	Resume  time.Duration
	Net     time.Duration
	Guest   time.Duration
}

func (s *phaseSamples) summarizePhases() PhaseSummary {
	return PhaseSummary{
		Control: summarize(s.control).P50,
		Fetch:   summarize(s.fetch).P50,
		Attach:  summarize(s.attach).P50,
		Load:    summarize(s.load).P50,
		Resume:  summarize(s.resume).P50,
		Net:     summarize(s.net).P50,
		Guest:   summarize(s.guest).P50,
	}
}
