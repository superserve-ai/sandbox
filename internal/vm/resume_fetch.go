package vm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/backup"
)

// resumeFetchVMStateName and resumeFetchRootfsName are the two artifact
// names every backup generation's manifest carries them under (see
// backup_hook.go's TaskFile naming) — fixed, not derived from the local
// on-disk filename (which varies: overlay.ext4 for a layered sandbox,
// rootfs.ext4 otherwise), since the manifest names describe what the
// generation was staged and uploaded as, not this host's own layout.
const (
	resumeFetchVMStateName = "vmstate.snap"
	resumeFetchRootfsName  = "rootfs.ext4"
)

// resumeFetchBudget bounds one fetch-before-resume attempt, detached from
// the RPC's own deadline (see fetchGenerationForResume) rather than
// borrowed from it: the boot RPC's ~45s deadline was sized for Firecracker
// startup and the readiness gate, not a network restore of a disk image
// that can be tens of GiB. Sized like this codebase's other large-artifact
// background budgets (pauseRehashBudget, buildHashBudget in manifest.go):
// generous enough that a healthy fetch always finishes inside it, short
// enough that a genuinely stuck one still surfaces as a failure rather
// than pinning a semaphore slot forever.
const resumeFetchBudget = 10 * time.Minute

// resumeFetchPendingSuffix names the sidecar marker fetchGenerationForResume
// writes before touching either target path and clears only once both are
// durably adopted. Its presence on a later attempt is the signal that lets
// resumeVMLocked tell "these two files are a consistent pair" apart from
// "the process died between adopting one and the other" — a state plain
// existence checks cannot distinguish, since both paths can be present
// either way. Suffixed onto snapshotPath (not a directory of its own)
// because that path already uniquely names this vmID's snapshot location,
// matching how the layered-overlay base sidecar and presence sidecar are
// also named relative to a snapshot path elsewhere in this package.
const resumeFetchPendingSuffix = ".fetch-pending"

func resumeFetchMarkerPath(snapshotPath string) string {
	return snapshotPath + resumeFetchPendingSuffix
}

// resumeFetchSource bundles what fetch-before-resume needs: read access to
// the cell's backup bucket and a semaphore bounding how many restores run
// at once. A reconnect storm after a host loss must not let every stranded
// sandbox's resume saturate local NVMe and NIC bandwidth at the same
// instant; requests past the bound queue for a free slot under whatever
// remains of their own RPC deadline, same as any other bounded resource on
// this path.
type resumeFetchSource struct {
	reader backup.BlobReader
	sem    chan struct{}
}

// SetResumeFetch enables fetch-before-resume. A nil reader (the default)
// disables it: resumeVMLocked's local-disk checks behave exactly as before,
// hard-failing when the paused sandbox's artifacts aren't already on this
// host. concurrency below 1 is clamped to 1.
func (m *Manager) SetResumeFetch(reader backup.BlobReader, concurrency int) {
	if reader == nil {
		m.resumeFetch = nil
		return
	}
	if concurrency < 1 {
		concurrency = 1
	}
	m.resumeFetch = &resumeFetchSource{reader: reader, sem: make(chan struct{}, concurrency)}
}

// fetchGenerationForResume restores generation's artifacts into a scratch
// directory beside snapshotPath, then places the two files every sandbox
// generation is guaranteed to carry — vmstate.snap and the disk image — at
// the local paths resumeVMLocked's existing checks expect. It returns the
// apparent bytes placed even on a partial failure, so a caller's metrics
// reflect what actually reached local disk.
//
// The guest memory image (mem.snap, or mem.diff for a layered overlay) is
// never part of the generation this restores: collectPauseManifest omits
// it by design (it never leaves the originating host, and hashing/shipping
// a multi-GiB image on every pause has no durability payoff proportional
// to its cost). A generation fetched here therefore cannot make memPath
// appear — resumeVMLocked's stat check on memPath fails exactly as it did
// before this existed, for a sandbox whose host was fully replaced. Only a
// sandbox whose memory file happens to already be present locally (partial
// loss, not a full replacement) sees this fetch unblock an actual resume.
//
// A layered overlay's base image is similarly out of scope: bases are
// fleet-wide template artifacts distributed by the existing template
// pipeline, not per-sandbox generation content, so this asks
// RestoreGenerationFiles for exactly the two names below and nothing
// else — a shared base entry this generation's manifest carries is never
// fetched at all, not fetched and discarded. Restoring a missing base is
// a separate, existing gap this does not change, and bases can be
// multi-GiB: paying to download and verify one on every resume just to
// throw it away would be real, avoidable latency on this hot path.
func (m *Manager) fetchGenerationForResume(ctx context.Context, vmID, generation, snapshotPath, rootfsPath string, log zerolog.Logger) (bytesRestored int64, err error) {
	src := m.resumeFetch
	if src == nil {
		return 0, fmt.Errorf("fetch-on-resume is disabled on this host")
	}

	// Semaphore admission still respects the caller's own deadline: how
	// long THIS resume is willing to queue for a fetch slot is exactly
	// the RPC's remaining budget, matching SetResumeFetch's contract
	// ("excess resumes queue under existing RPC deadlines"). Only the
	// fetch work admitted below is detached from it.
	select {
	case src.sem <- struct{}{}:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	defer func() { <-src.sem }()

	// Detached from the caller's cancellation and given its own generous
	// budget (resumeFetchBudget): a client that gives up on the RPC must
	// not truncate a download that's otherwise on track. resumeVMLocked's
	// own doc comment already establishes why this is safe — a retry
	// waits on the same vm-op lock and adopts whatever this attempt
	// eventually produces, live VM or freshly fetched files, instead of
	// racing it.
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), resumeFetchBudget)
	defer cancel()

	snapshotDir := filepath.Dir(snapshotPath)
	if err := os.MkdirAll(snapshotDir, 0o755); err != nil {
		return 0, fmt.Errorf("create snapshot dir: %w", err)
	}

	// Written before either target path is touched; see
	// resumeFetchPendingSuffix for why. Left in place on every error path
	// below (including a context timeout) — its whole job is to persist
	// across exactly those failures.
	markerPath := resumeFetchMarkerPath(snapshotPath)
	if err := writeFetchPendingMarker(markerPath, generation); err != nil {
		return 0, fmt.Errorf("write fetch marker: %w", err)
	}

	// RestoreGenerationFiles requires an empty destination (see its doc
	// comment) and refuses to reuse one; a fresh scratch dir every attempt
	// satisfies that without racing a concurrent resume of the same vmID
	// onto shared state, and lives beside snapshotPath so placing
	// vmstate.snap below is a same-filesystem rename.
	scratch, err := os.MkdirTemp(snapshotDir, ".fetch-*")
	if err != nil {
		return 0, fmt.Errorf("create fetch scratch dir: %w", err)
	}
	defer os.RemoveAll(scratch)

	manifest, err := backup.RestoreGenerationFiles(fctx, src.reader, vmID, generation, scratch,
		[]string{resumeFetchVMStateName, resumeFetchRootfsName},
		func(format string, args ...any) {
			log.Debug().Str("generation", generation).Msgf("resume fetch: "+format, args...)
		})
	if err != nil {
		return 0, fmt.Errorf("restore generation %s: %w", generation, err)
	}

	for _, mf := range manifest.Files {
		var dest string
		switch mf.Name {
		case resumeFetchVMStateName:
			dest = snapshotPath
		case resumeFetchRootfsName:
			dest = rootfsPath
		default:
			// RestoreGenerationFiles only ever restores the two names
			// requested above; manifest.Files still lists every entry the
			// generation carries (unrestored ones included) purely as
			// metadata, so this default is reachable and correctly a no-op.
			continue
		}
		if err := adoptFetchedFile(scratch, mf.Name, dest); err != nil {
			return bytesRestored, fmt.Errorf("place fetched %s: %w", mf.Name, err)
		}
		bytesRestored += mf.Size
	}
	// Both artifacts are durably in place: the pair is consistent again,
	// so the marker that would force a future attempt to distrust plain
	// existence can go. Best-effort: a failure to remove it only costs a
	// future resume an unnecessary (but harmless — adoptFetchedFile always
	// overwrites) refetch, never a correctness problem the way leaving a
	// STALE marker after a genuine failure would be reversed.
	if rerr := os.Remove(markerPath); rerr != nil && !os.IsNotExist(rerr) {
		log.Warn().Err(rerr).Str("generation", generation).Msg("resume fetch: clear pending marker failed")
	}
	return bytesRestored, nil
}

// writeFetchPendingMarker creates or overwrites the marker with the
// generation being fetched, fsynced so its presence is crash-durable —
// the property fetchGenerationForResume's interrupted-attempt detection
// depends on. The content is for an operator inspecting the file by hand;
// resumeVMLocked's check only cares whether the marker exists at all.
func writeFetchPendingMarker(path, generation string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(generation); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// fetchResumeError classifies a fetch failure into the gRPC status the
// control plane's boot retry understands (see retryTransientBoot,
// isVMDUnavailable/isVMDDeadline in internal/api/vmd_errors.go):
// FailedPrecondition for the two backup-package sentinels that name a
// permanently unrestorable generation — retrying the same attempt
// immediately cannot fix an object that doesn't exist or a generation
// whose upload never finished — and Unavailable for everything else,
// covering both a GCS transport blip and this attempt's own
// resumeFetchBudget expiring. Other restore-side failures (a digest or
// manifest-identity mismatch, for instance) are also permanent but have
// no exported sentinel to distinguish them from a transient one here;
// defaulting those to Unavailable costs at most one extra identical retry
// via the control plane's existing one-shot policy, never an incorrect
// resume.
func fetchResumeError(generation string, err error) error {
	if errors.Is(err, backup.ErrObjectNotFound) || errors.Is(err, backup.ErrGenerationIncomplete) {
		return status.Errorf(codes.FailedPrecondition, "fetch generation %s for resume: %v", generation, err)
	}
	return status.Errorf(codes.Unavailable, "fetch generation %s for resume: %v", generation, err)
}

// adoptFetchedFile moves one restored artifact from the fetch scratch dir
// to its final resume path. Rename is attempted first (free, and the
// common case: vmstate.snap's destination is always a sibling of scratch
// itself) and is already atomic — it either fully replaces dest or leaves
// it untouched, never partial. A cross-device destination — the disk
// image, whose final path is under RunDir rather than SnapshotDir and so
// may sit on a different filesystem — falls back to a copy that preserves
// the same all-or-nothing guarantee at dest; see copyAcrossDevices.
func adoptFetchedFile(scratchDir, name, dest string) error {
	destDir := filepath.Dir(dest)
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}
	src := filepath.Join(scratchDir, name)
	err := os.Rename(src, dest)
	if err == nil {
		return nil
	}
	if !errors.Is(err, syscall.EXDEV) {
		return err
	}
	return copyAcrossDevices(src, destDir, dest)
}

// copyAcrossDevices is the EXDEV fallback for adoptFetchedFile. It streams
// into a temp file IN DEST'S OWN DIRECTORY, fsyncs it, then renames it onto
// dest — that final rename is then same-filesystem and atomic, so a copy
// that fails or crashes partway leaves dest exactly as it was (missing or
// its prior content), never a truncated file. Without this, a failed copy
// straight into dest would leave a partial artifact that looks like a
// complete one to the plain existence check resumeVMLocked runs next, and
// to every future resume's fetch-trigger check after that.
func copyAcrossDevices(src, destDir, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(destDir, ".fetch-tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	renamed := false
	defer func() {
		if !renamed {
			os.Remove(tmpPath)
		}
	}()
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, dest); err != nil {
		return err
	}
	renamed = true
	return nil
}
