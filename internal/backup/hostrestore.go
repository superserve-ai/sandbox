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
	// Anchors lists the digest sets of the sandbox's pauses in the
	// control plane's capture order, newest first; each anchor maps file
	// name to sha256 and matches a manifest only when EVERY recorded
	// digest appears (vmstate alone can collide across pauses whose
	// rootfs differs). Bucket object times are upload-completion times,
	// so selection walks this list and takes the first anchor with a
	// matching manifest: recovery lands on the newest CAPTURED pause
	// that actually reached the bucket, however deep the control
	// plane's history goes. Newest-completed is the recorded fallback
	// only when no anchor matches (or the list is empty), where capture
	// order is unrecoverable by construction: manifests are timeless.
	Anchors []CaptureAnchor
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
	// PackedBytes is what the selected generation moves over the
	// network; ApparentBytes what it lands on disk. Zero when no
	// generation was selected. These make the ledger sufficient for RTO
	// sizing against the operator's own bandwidth.
	PackedBytes   int64
	ApparentBytes int64
}

// CaptureAnchor is one pause's recorded digest set: file name to
// sha256, as the control plane's artifact manifest holds it.
type CaptureAnchor map[string]string

// matches reports whether every digest the anchor records appears in
// the manifest. A vmstate-only anchor (the pause-time manifest shape)
// matches on that single digest; richer anchors bind the full set.
func (a CaptureAnchor) matches(m *GenerationManifest) bool {
	if len(a) == 0 {
		return false
	}
	byName := map[string]string{}
	for _, f := range m.Files {
		byName[f.Name] = f.SHA256
	}
	for name, sha := range a {
		if byName[name] != sha {
			return false
		}
	}
	return true
}

// sameManifestContent reports whether two manifests name the same
// artifact set with the same digests.
func sameManifestContent(a, b *GenerationManifest) bool {
	if len(a.Files) != len(b.Files) {
		return false
	}
	byName := make(map[string]string, len(a.Files))
	for _, f := range a.Files {
		byName[f.Name] = f.SHA256
	}
	for _, f := range b.Files {
		if byName[f.Name] != f.SHA256 {
			return false
		}
	}
	return true
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
	// Totals over results that selected a generation (see
	// HostRestoreResult byte fields).
	PackedBytes   int64
	ApparentBytes int64
}

// HostRestorer bulk-restores every enumerated owner's newest completed
// generation with bounded concurrency. It deliberately wraps the
// single-owner primitives (ListGenerations, RestoreGeneration) so every
// integrity property of the single restore, digest verification, sparse
// rebuild, completion marker, holds per item with no new trust surface.
type HostRestorer struct {
	Reader BlobReader
	Lister BlobLister
	// seenObjects attributes each packed object to the first result that
	// claims it, so summed PackedBytes equal actual ingress: shared
	// template bases appear in every dependent's manifest but download
	// once through the base cache. Reset per Run.
	seenObjects sync.Map

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
	// Fresh per-run accounting: stale entries from a prior Run would
	// silently omit re-downloaded objects from the packed totals.
	h.seenObjects.Range(func(k, _ any) bool {
		h.seenObjects.Delete(k)
		return true
	})
	workers := h.Concurrency
	if workers <= 0 {
		workers = 4
	}
	// Never more goroutines than work, and never an unbounded operator
	// typo: a six-digit -concurrency would allocate that many workers
	// before dispatching a single item.
	if workers > len(items) {
		workers = len(items)
	}
	if workers > 64 {
		workers = 64
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
		report.PackedBytes += r.PackedBytes
		report.ApparentBytes += r.ApparentBytes
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
	// scan fetches EVERY completed generation's manifest by design, not
	// as an oversight: acceptance requires proving no unreadable
	// candidate hides a newer-anchor match, and ambiguity detection
	// requires seeing every generation the winning anchor matches, so
	// both guarantees are load-bearing on completeness. Cost stays
	// bounded in practice: manifests are kilobytes, candidates probe in
	// small parallel batches, and history depth is capped by retention
	// once GC lands.
	var selManifest *GenerationManifest
	if len(item.Anchors) == 0 {
		// No capture anchors at all (a digest-less sandboxes file, or a
		// DB with no artifact-manifest rows for this sandbox) means
		// selection runs on completion order with no way to know whether
		// it matches capture order. The ledger says so, or the runbook's
		// rollback grep would miss these sandboxes entirely.
		res.Reason = "capture anchors unavailable; using newest completed generation (completion order)"
	}
	if len(item.Anchors) > 0 {
		var manifestByGen sync.Map
		unreadable := 0
		for lo := 0; lo < len(gens); lo += anchorProbeBatch {
			hi := lo + anchorProbeBatch
			if hi > len(gens) {
				hi = len(gens)
			}
			failed := make([]bool, hi-lo)
			var pwg sync.WaitGroup
			for i := lo; i < hi; i++ {
				pwg.Add(1)
				go func(i int) {
					defer pwg.Done()
					m, err := fetchManifest(ctx, h.Reader, item.SandboxID, gens[i].Generation, func(string, ...any) {})
					if err != nil {
						failed[i-lo] = true
						return
					}
					manifestByGen.Store(gens[i].Generation, m)
				}(i)
			}
			pwg.Wait()
			for _, bad := range failed {
				if bad {
					unreadable++
				}
			}
		}
		// Walk the control plane's capture order, newest first: the
		// first anchor with a matching manifest is the newest captured
		// pause that survived.
		match := ""
		matchAnchor := -1
		var matchedGens []string
		for ai, anchor := range item.Anchors {
			for _, g := range gens {
				if v, ok := manifestByGen.Load(g.Generation); ok && anchor.matches(v.(*GenerationManifest)) {
					if match == "" {
						match = g.Generation
						matchAnchor = ai
					}
					matchedGens = append(matchedGens, g.Generation)
				}
			}
			if match != "" {
				break
			}
		}
		// A partial anchor (vmstate-only, the pause-time manifest shape)
		// can match several generations whose other artifacts differ; the
		// digest set alone then cannot say which filesystem generation
		// the anchor's pause captured, and picking newest would silently
		// restore the wrong one. Identical matches are fine (re-uploaded
		// duplicates of one capture); differing matches fail closed and
		// name the candidates so the operator resolves with an explicit
		// per-sandbox digest set.
		if len(matchedGens) > 1 {
			first, _ := manifestByGen.Load(matchedGens[0])
			for _, g := range matchedGens[1:] {
				v, _ := manifestByGen.Load(g)
				if !sameManifestContent(first.(*GenerationManifest), v.(*GenerationManifest)) {
					res.Outcome = HostRestoreFailed
					res.Reason = fmt.Sprintf("anchor is ambiguous: generations %s match the recorded digest set but differ in content; supply the full digest set for this sandbox", strings.Join(matchedGens, ", "))
					res.Duration = time.Since(start)
					return res
				}
			}
		}
		switch {
		case match != "" && unreadable == 0:
			if v, ok := manifestByGen.Load(match); ok {
				selManifest = v.(*GenerationManifest)
			}
			// An older capture winning is a fallback exactly like the
			// no-anchor case: the newest pause's upload never completed.
			// The ledger must say so, or the runbook's rollback grep
			// misses every sandbox that silently came back on an older
			// pause.
			if matchAnchor > 0 {
				res.Reason = fmt.Sprintf("latest pause not in bucket; restored an older captured pause (capture %d of the recorded history)", matchAnchor+1)
			}
			// Acceptance requires the scan to be complete: an unreadable
			// manifest could match a newer anchor than the one found, or
			// be a content-differing duplicate of the winning anchor's
			// match, and either way accepting would silently restore the
			// wrong generation on a transient read error. Reruns are
			// idempotent, so failing closed below costs one retry.
			res.Generation = match
		case unreadable > 0:
			// Fail closed: an unreadable candidate may BE the anchor, and
			// falling back would silently roll the sandbox to an older
			// pause on a transient read error. Reruns are idempotent, so
			// the operator retries this item cheaply.
			res.Outcome = HostRestoreFailed
			res.Reason = fmt.Sprintf("anchor scan incomplete: %d candidate manifests unreadable; rerun", unreadable)
			res.Duration = time.Since(start)
			return res
		default:
			res.Reason = "latest pause not in bucket; using newest completed generation"
		}
	}
	if h.DryRun {
		// Coverable must mean restorable: fetch and authenticate the
		// selected manifest (identity, self-derived generation key,
		// consistency pairs) so a corrupt or misplaced manifest shows up
		// in the dry-run ledger, not mid-recovery.
		// The anchored scan already fetched and authenticated every
		// candidate; refetching the winner would add one GCS request per
		// sandbox host-wide for bytes already in hand.
		m := selManifest
		if m == nil {
			var err error
			m, err = fetchManifest(ctx, h.Reader, item.SandboxID, res.Generation, func(string, ...any) {})
			if err != nil {
				res.Outcome, res.Reason = HostRestoreFailed, fmt.Sprintf("manifest validation: %v", err)
				res.Duration = time.Since(start)
				return res
			}
		}
		res.PackedBytes, res.ApparentBytes = h.manifestBytes(m)
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
	m, err := RestoreGeneration(ctx, h.Reader, item.SandboxID, res.Generation, dest, nil)
	if err != nil {
		res.Outcome, res.Reason = HostRestoreFailed, err.Error()
		res.Duration = time.Since(start)
		return res
	}
	// RestoreGeneration already fetched and authenticated this manifest;
	// a second read would add one GCS request per sandbox and could
	// silently zero the totals on a transient failure.
	res.PackedBytes, res.ApparentBytes = h.manifestBytes(m)
	res.Outcome = HostRestoreRestored
	res.Duration = time.Since(start)
	return res
}

// manifestBytes totals a generation's packed (network) and apparent
// (on-disk) sizes.
func (h *HostRestorer) manifestBytes(m *GenerationManifest) (packed, apparent int64) {
	for _, f := range m.Files {
		// Only shared objects (full bucket paths, downloaded once via
		// the base cache) dedupe host-wide: generation-local entries
		// record bare relative names that can collide across sandboxes
		// while naming different bytes, and deduping those would
		// understate the transfer. Apparent bytes are per-destination
		// and count fully for every sandbox.
		if isSharedEntry(f) {
			if _, loaded := h.seenObjects.LoadOrStore(f.Object, struct{}{}); !loaded {
				packed += f.PackedSize
			}
		} else {
			packed += f.PackedSize
		}
		apparent += f.Size
	}
	return packed, apparent
}

// anchorProbeBatch bounds concurrent manifest fetches within one
// sandbox's capture-anchor scan.
const anchorProbeBatch = 4

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
		// Sync before close and rename, then sync the directory: the
		// cache pathname must never outlive its contents across a power
		// loss, or a rerun would serve a truncated base whose corruption
		// only surfaces as per-sandbox digest failures downstream.
		if err := tmp.Sync(); err != nil {
			tmp.Close()
			return nil, err
		}
		if err := tmp.Close(); err != nil {
			return nil, err
		}
		if err := os.Rename(tmp.Name(), cached); err != nil {
			return nil, err
		}
		// The rename is only durable once the directory entry is synced;
		// a discarded failure here would report a cache commit that a
		// power loss can undo, and the crash-safe rerun guarantee rests
		// on this entry surviving.
		dir, err := os.Open(filepath.Dir(cached))
		if err != nil {
			return nil, err
		}
		if err := dir.Sync(); err != nil {
			dir.Close()
			return nil, err
		}
		if err := dir.Close(); err != nil {
			return nil, err
		}
		return nil, nil
	})
	if err != nil {
		return nil, err
	}
	return os.Open(cached)
}
