package backup

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// HostRestoreItem is one artifact owner the DB says lived on the dead
// host. Dest is where the owner's newest generation materializes; for
// sandboxes this is the snapshot directory vmd will cold-boot from, so
// the DB's recorded layout carries over to the replacement host
// unchanged.
type HostRestoreItem struct {
	SandboxID string
	Dest      string
}

// HostRestoreResult is the per-item outcome of a bulk restore. Exactly
// one of Generation or Reason is meaningful: a restored or verified item
// names the generation used, a skipped or failed one carries the reason.
type HostRestoreResult struct {
	SandboxID  string
	Dest       string
	Generation string
	Outcome    HostRestoreOutcome
	Reason     string
	Duration   time.Duration
}

type HostRestoreOutcome string

const (
	// HostRestoreRestored: the newest generation materialized and
	// verified at Dest.
	HostRestoreRestored HostRestoreOutcome = "restored"
	// HostRestoreCoverable: dry-run verdict; the newest generation's
	// manifest exists in the bucket and a real run would restore it.
	HostRestoreCoverable HostRestoreOutcome = "coverable"
	// HostRestoreUncovered: the bucket holds no completed generation for
	// this owner. These are the partial-failure playbook's subjects: the
	// owners whose data did not survive the host, enumerated precisely.
	HostRestoreUncovered HostRestoreOutcome = "uncovered"
	// HostRestoreFailed: a restore was attempted and did not complete;
	// the destination holds no completion marker and must not be
	// consumed.
	HostRestoreFailed HostRestoreOutcome = "failed"
)

// HostRestoreReport aggregates a bulk run. Results hold every item in
// input order; the counts exist so operators read the verdict before
// the detail.
type HostRestoreReport struct {
	Results   []HostRestoreResult
	Restored  int
	Coverable int
	Uncovered int
	Failed    int
	Elapsed   time.Duration
}

// HostRestorer bulk-restores every enumerated owner's newest completed
// generation with bounded concurrency. It deliberately wraps the
// single-owner primitives (ListGenerations, RestoreGeneration) so every
// integrity property of the single restore, digest verification, sparse
// rebuild, completion marker, holds per item with no new trust surface.
type HostRestorer struct {
	Reader BlobReader
	Lister BlobLister
	// Concurrency bounds parallel restores. The replacement host is cold
	// (no customer traffic yet), so the bound exists to keep the fetch
	// path below the NIC and disk ceilings, not to protect tenants; the
	// mass-restore wedging seen during the us-east4 cutover was
	// boot-storm churn, which cold-boot-on-demand avoids entirely, but
	// the bound still keeps the failure mode of one slow item from
	// serializing the fleet. 0 means 4.
	Concurrency int
	// DryRun stops after coverage probing: every item resolves to
	// coverable or uncovered and nothing touches disk.
	DryRun bool
	// Progress, when non-nil, receives each result as it lands, in
	// completion order; the report still lists input order.
	Progress func(HostRestoreResult)
}

// Run executes the bulk restore. Per-item failures never stop the run:
// a DR operator needs the full ledger of what recovered and what needs
// the playbook, not an abort at the first missing owner.
func (h *HostRestorer) Run(ctx context.Context, items []HostRestoreItem) *HostRestoreReport {
	start := time.Now()
	workers := h.Concurrency
	if workers <= 0 {
		workers = 4
	}
	results := make([]HostRestoreResult, len(items))
	work := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				results[i] = h.restoreOne(ctx, items[i])
				if h.Progress != nil {
					h.Progress(results[i])
				}
			}
		}()
	}
	for i := range items {
		select {
		case work <- i:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			// Remaining items report as failed-by-cancel rather than
			// silently absent from the ledger.
			for j := i; j < len(items); j++ {
				if results[j].Outcome == "" {
					results[j] = HostRestoreResult{
						SandboxID: items[j].SandboxID, Dest: items[j].Dest,
						Outcome: HostRestoreFailed, Reason: "canceled before restore",
					}
				}
			}
			break
		}
	}
	close(work)
	wg.Wait()

	report := &HostRestoreReport{Results: results, Elapsed: time.Since(start)}
	for _, r := range results {
		switch r.Outcome {
		case HostRestoreRestored:
			report.Restored++
		case HostRestoreCoverable:
			report.Coverable++
		case HostRestoreUncovered:
			report.Uncovered++
		default:
			report.Failed++
		}
	}
	return report
}

func (h *HostRestorer) restoreOne(ctx context.Context, item HostRestoreItem) HostRestoreResult {
	start := time.Now()
	res := HostRestoreResult{SandboxID: item.SandboxID, Dest: item.Dest}
	gens, err := ListGenerations(ctx, h.Lister, item.SandboxID)
	if err != nil {
		res.Outcome, res.Reason = HostRestoreFailed, fmt.Sprintf("list generations: %v", err)
		res.Duration = time.Since(start)
		return res
	}
	if len(gens) == 0 {
		res.Outcome = HostRestoreUncovered
		res.Reason = "no completed generation in the bucket"
		res.Duration = time.Since(start)
		return res
	}
	// ListGenerations returns newest first; the newest completed
	// generation is the recovery point (at most one pause interval of
	// file changes lost, per the recovery contract).
	sort.SliceStable(gens, func(i, j int) bool { return gens[i].Created.After(gens[j].Created) })
	res.Generation = gens[0].Generation
	if h.DryRun {
		res.Outcome = HostRestoreCoverable
		res.Duration = time.Since(start)
		return res
	}
	dest := filepath.Clean(item.Dest)
	if _, err := RestoreGeneration(ctx, h.Reader, item.SandboxID, res.Generation, dest, nil); err != nil {
		res.Outcome, res.Reason = HostRestoreFailed, err.Error()
		res.Duration = time.Since(start)
		return res
	}
	res.Outcome = HostRestoreRestored
	res.Duration = time.Since(start)
	return res
}
