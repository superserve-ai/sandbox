package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// HostRestoreItem is one artifact owner the DB says lived on the dead
// host. Dest is where the owner's newest generation materializes; for
// sandboxes this is the snapshot directory vmd will cold-boot from, so
// the DB's recorded layout carries over to the replacement host
// unchanged.
type HostRestoreItem struct {
	SandboxID string
	Dest      string
	// WantVMStateSHA, when set, names the vmstate digest of the
	// sandbox's latest pause as the control plane recorded it. Bucket
	// object times are upload-completion times, so a retry-delayed old
	// upload can finish after a newer pause's and rank first by age; the
	// digest match selects the generation of the ACTUAL latest pause,
	// with newest-completed as the recorded fallback when no candidate
	// matches (the latest pause's upload may not have finished before
	// the host died).
	WantVMStateSHA string
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
	// path below the NIC and disk ceilings, not to protect tenants, and
	// it keeps one slow item from serializing the fleet. 0 means 4.
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
		stop := false
		select {
		case work <- i:
		case <-ctx.Done():
			stop = true
		}
		if stop {
			break
		}
	}
	close(work)
	wg.Wait()
	// Undispatched items report as failed-by-cancel rather than
	// silently absent from the ledger. Filled only after the workers
	// finish: an item dispatched in the same instant cancellation
	// arrived is owned by its worker, and its real result must not be
	// overwritten here.
	for j := range results {
		if results[j].Outcome == "" {
			results[j] = HostRestoreResult{
				SandboxID: items[j].SandboxID, Dest: items[j].Dest,
				Outcome: HostRestoreFailed, Reason: "canceled before restore",
			}
		}
	}

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
	sort.SliceStable(gens, func(i, j int) bool { return gens[i].Created.After(gens[j].Created) })
	res.Generation = gens[0].Generation
	// Prefer the generation whose vmstate digest matches the control
	// plane's latest pause: completion order is not capture order. The
	// probe is bounded: the anchored generation, if it uploaded at all,
	// completed near the head of the history, and an unbounded walk
	// would turn full-host recovery into fleet-size times history-depth
	// synchronous fetches exactly when the anchor is absent (the
	// expected host-death case).
	if item.WantVMStateSHA != "" {
		matched := false
		for i, g := range gens {
			if i >= anchorProbeLimit {
				break
			}
			m, err := fetchManifest(ctx, h.Reader, item.SandboxID, g.Generation, func(string, ...any) {})
			if err != nil {
				continue
			}
			for _, f := range m.Files {
				if f.Name == "vmstate.snap" && f.SHA256 == item.WantVMStateSHA {
					res.Generation = g.Generation
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			res.Reason = "latest pause not among newest completed generations; using newest completed"
		}
	}
	if h.DryRun {
		// Coverable must mean restorable: fetch and authenticate the
		// selected manifest (identity, self-derived generation key,
		// consistency pairs) so a corrupt or misplaced manifest shows up
		// in the dry-run ledger, not mid-recovery.
		if _, err := fetchManifest(ctx, h.Reader, item.SandboxID, res.Generation, func(string, ...any) {}); err != nil {
			res.Outcome, res.Reason = HostRestoreFailed, fmt.Sprintf("manifest validation: %v", err)
			res.Duration = time.Since(start)
			return res
		}
		res.Outcome = HostRestoreCoverable
		res.Duration = time.Since(start)
		return res
	}
	dest := filepath.Clean(item.Dest)
	// Rerun idempotence: a destination already holding this generation's
	// completion marker finished a prior run past its fsynced
	// verification; report it restored instead of failing on the
	// non-empty directory.
	if gen, ok := completedGenerationAt(dest); ok && gen == res.Generation {
		res.Outcome = HostRestoreRestored
		res.Reason = "already restored by a prior run"
		res.Duration = time.Since(start)
		return res
	}
	if _, err := RestoreGeneration(ctx, h.Reader, item.SandboxID, res.Generation, dest, nil); err != nil {
		res.Outcome, res.Reason = HostRestoreFailed, err.Error()
		res.Duration = time.Since(start)
		return res
	}
	res.Outcome = HostRestoreRestored
	res.Duration = time.Since(start)
	return res
}

// anchorProbeLimit bounds how many newest generations the capture
// anchor probe fetches manifests for before falling back.
const anchorProbeLimit = 5

// completedGenerationAt reports the generation a destination's fsynced
// completion marker records, if one exists and parses.
func completedGenerationAt(dest string) (string, bool) {
	data, err := os.ReadFile(filepath.Join(dest, ManifestObject))
	if err != nil {
		return "", false
	}
	var m GenerationManifest
	if json.Unmarshal(data, &m) != nil {
		return "", false
	}
	return m.Generation, m.Generation != ""
}

// CachingBaseReader wraps a BlobReader, spooling shared base objects
// (the bases/ prefix) into a local directory once and serving repeat
// fetches from disk. A fleet restored from a handful of templates would
// otherwise stream the same multi-gigabyte base object once per
// sandbox; generation-scoped objects pass straight through. Concurrent
// first fetches of one base coalesce.
type CachingBaseReader struct {
	Inner BlobReader
	Dir   string
	group singleflight.Group
}

func (c *CachingBaseReader) NewReader(ctx context.Context, object string) (io.ReadCloser, error) {
	if !strings.HasPrefix(object, "bases/") {
		return c.Inner.NewReader(ctx, object)
	}
	cached := filepath.Join(c.Dir, strings.ReplaceAll(object, "/", "_"))
	_, err, _ := c.group.Do(cached, func() (any, error) {
		if _, err := os.Stat(cached); err == nil {
			return nil, nil
		}
		src, err := c.Inner.NewReader(ctx, object)
		if err != nil {
			return nil, err
		}
		defer src.Close()
		if err := os.MkdirAll(c.Dir, 0o700); err != nil {
			return nil, err
		}
		tmp, err := os.CreateTemp(c.Dir, ".spool-*")
		if err != nil {
			return nil, err
		}
		defer os.Remove(tmp.Name())
		if _, err := io.Copy(tmp, src); err != nil {
			tmp.Close()
			return nil, err
		}
		if err := tmp.Close(); err != nil {
			return nil, err
		}
		// Rename-after-full-write: a crashed spool never masquerades as
		// a cached base, and every restore's own digest verification
		// still covers the served bytes end to end.
		return nil, os.Rename(tmp.Name(), cached)
	})
	if err != nil {
		return nil, err
	}
	return os.Open(cached)
}
