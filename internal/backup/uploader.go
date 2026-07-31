package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/time/rate"
)

// GenerationManifest is the completion marker object, written after every
// artifact object of a generation is in the bucket. Restore reads it to
// learn the file set, verify digests, and rebuild sparse files from the
// extent tables. A generation without its manifest object is incomplete
// and never restored from.
type GenerationManifest struct {
	SandboxID  string         `json:"sandbox_id"`
	Generation string         `json:"generation"`
	Files      []ManifestFile `json:"files"`
	VMDVersion string         `json:"vmd_version,omitempty"`
}

// ManifestFile describes one packed artifact object.
type ManifestFile struct {
	Name       string   `json:"name"`
	SHA256     string   `json:"sha256"` // digest of the full apparent content
	Size       int64    `json:"size"`   // apparent size
	PackedSize int64    `json:"packed_size"`
	Extents    []Extent `json:"extents"`
}

// Uploader drains the journal into the blob store. Single drain loop:
// fleet-wide churn is tens of GB/day, so one bandwidth-capped stream is
// deliberate simplicity, not a bottleneck.
type Uploader struct {
	Journal *Journal
	Store   BlobStore
	// Limiter caps upload bandwidth in bytes/sec so backups never starve
	// guest traffic or the UFFD resume path.
	Limiter *rate.Limiter
	Log     zerolog.Logger
	// VMDVersion is stamped into generation manifests.
	VMDVersion string
	// OnVerified fires after a task's generation is fully in the bucket
	// (manifest object written) and acked. This is the signal downstream
	// bookkeeping and local-staging GC key on.
	OnVerified func(Task)
	// Tick is the idle poll interval. 0 → 1s.
	Tick time.Duration
}

// Run drains the journal until ctx ends. Crash-safe by construction: work
// is acked only after verification, so a restart resumes exactly where the
// journal says.
func (u *Uploader) Run(ctx context.Context) error {
	tick := u.Tick
	if tick <= 0 {
		tick = time.Second
	}
	for {
		worked, err := u.drainOne(ctx, time.Now())
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			u.Log.Error().Err(err).Msg("backup drain error")
		}
		// Sleep when idle AND after errors: a persistently failing journal
		// (e.g. disk full) must back off, not busy-spin.
		if !worked || err != nil {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(tick):
			}
		}
	}
}

// drainOne uploads the next runnable task, if any. Returns whether work
// was attempted.
func (u *Uploader) drainOne(ctx context.Context, now time.Time) (bool, error) {
	task, ok, err := u.Journal.Next(now)
	if err != nil || !ok {
		return false, err
	}
	completed, err := u.uploadTask(ctx, task)
	if err != nil {
		u.Log.Warn().Err(err).
			Str("sandbox_id", task.SandboxID).
			Str("generation", task.Generation).
			Int("attempts", task.Attempts+1).
			Msg("backup upload failed; will retry")
		return true, u.Journal.Nack(task, now)
	}
	if err := u.Journal.Ack(task); err != nil {
		return true, err
	}
	if completed && u.OnVerified != nil {
		u.OnVerified(task)
	}
	return true, nil
}

// uploadTask ships every artifact of a generation, then its manifest
// object. Objects are content-addressed and create-only, so retries after
// partial progress re-cover already-written objects as no-ops. completed
// is false when the generation was abandoned (source files gone): the
// task is done, but nothing was made durable, so verification hooks must
// not fire.
func (u *Uploader) uploadTask(ctx context.Context, task Task) (completed bool, _ error) {
	gen := GenerationManifest{
		SandboxID:  task.SandboxID,
		Generation: task.Generation,
		VMDVersion: u.VMDVersion,
	}
	for _, file := range task.Files {
		mf, err := u.uploadFile(ctx, task, file)
		if err != nil {
			if os.IsNotExist(err) || errors.Is(err, errSourceChanged) {
				// The artifact vanished or mutated between enqueue and
				// upload (sandbox deleted or resumed, local GC won the
				// race). Nothing valid to back up under this content
				// address; the generation is abandoned, not retried.
				u.Log.Warn().Str("path", file.Path).Str("sandbox_id", task.SandboxID).
					Msg("backup source file gone; abandoning generation")
				return false, nil
			}
			return false, err
		}
		gen.Files = append(gen.Files, mf)
	}
	manifestObject, err := SandboxObject(task.SandboxID, task.Generation, ManifestObject)
	if err != nil {
		return false, err
	}
	payload, err := json.Marshal(gen)
	if err != nil {
		return false, err
	}
	if err := u.Store.Create(ctx, manifestObject, &limitedReader{r: bytes.NewReader(payload), limiter: u.Limiter, ctx: ctx}); err != nil {
		return false, fmt.Errorf("manifest object: %w", err)
	}
	return true, nil
}

// errSourceChanged marks a source file whose current content no longer
// matches the digest recorded at pause time: the sandbox resumed and
// mutated the disk before the upload drained. Shipping those bytes under
// the old content address would create a generation whose objects
// contradict their manifest, so the generation is abandoned instead; the
// resume's next pause enqueues the corrective generation under a new key.
var errSourceChanged = os.ErrNotExist

func (u *Uploader) uploadFile(ctx context.Context, task Task, file TaskFile) (ManifestFile, error) {
	if file.Name == ManifestObject {
		return ManifestFile{}, fmt.Errorf("artifact name %q collides with the manifest object", file.Name)
	}
	f, err := os.Open(file.Path)
	if err != nil {
		return ManifestFile{}, err
	}
	defer f.Close()
	extents, apparent, err := Extents(f)
	if err != nil {
		return ManifestFile{}, fmt.Errorf("extents %s: %w", file.Path, err)
	}
	// Verify the source still matches the digest recorded at pause time
	// before any bytes ship. Data extents are read twice (verify, then
	// upload); at tens of MB per artifact the second pass is page-cache
	// warm. A residual race remains between this check and the upload
	// completing; a mutated upload in that window fails restore-side
	// digest verification and the generation is simply unusable, never
	// silently wrong.
	sum, err := hashApparent(ctx, f, extents, apparent)
	if err != nil {
		return ManifestFile{}, fmt.Errorf("verify %s: %w", file.Path, err)
	}
	if sum != file.SHA256 {
		u.Log.Warn().Str("path", file.Path).Str("want", file.SHA256).Str("got", sum).
			Msg("backup source changed since pause; abandoning generation")
		return ManifestFile{}, errSourceChanged
	}
	object, err := SandboxObject(task.SandboxID, task.Generation, file.Name)
	if err != nil {
		return ManifestFile{}, err
	}
	reader := &limitedReader{r: NewPackedReader(f, extents), limiter: u.Limiter, ctx: ctx}
	if err := u.Store.Create(ctx, object, reader); err != nil {
		return ManifestFile{}, err
	}
	return ManifestFile{
		Name:       file.Name,
		SHA256:     file.SHA256,
		Size:       apparent,
		PackedSize: PackedSize(extents),
		Extents:    extents,
	}, nil
}

// hashApparent digests the file's full apparent content from its extent
// table: data extents from disk, holes as zeros without touching disk.
// This must equal the pause manifest's digest, and restore recomputes the
// same thing after rebuilding the sparse file.
func hashApparent(ctx context.Context, f *os.File, extents []Extent, apparent int64) (string, error) {
	h := sha256.New()
	zeros := make([]byte, 1<<20)
	var pos int64
	writeZeros := func(upTo int64) error {
		for pos < upTo {
			if err := ctx.Err(); err != nil {
				return err
			}
			n := upTo - pos
			if n > int64(len(zeros)) {
				n = int64(len(zeros))
			}
			h.Write(zeros[:n])
			pos += n
		}
		return nil
	}
	for _, e := range extents {
		if err := writeZeros(e.Offset); err != nil {
			return "", err
		}
		if _, err := io.Copy(h, io.NewSectionReader(f, e.Offset, e.Length)); err != nil {
			return "", err
		}
		pos = e.Offset + e.Length
	}
	if err := writeZeros(apparent); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// limitedReader applies the bandwidth cap per read. A nil limiter means
// uncapped.
type limitedReader struct {
	r       io.Reader
	limiter *rate.Limiter
	ctx     context.Context
}

func (l *limitedReader) Read(p []byte) (int, error) {
	// Cap read sizes to the limiter burst so WaitN never exceeds it.
	if l.limiter != nil {
		if burst := l.limiter.Burst(); burst > 0 && len(p) > burst {
			p = p[:burst]
		}
	}
	n, err := l.r.Read(p)
	if n > 0 && l.limiter != nil {
		if werr := l.limiter.WaitN(l.ctx, n); werr != nil {
			return n, werr
		}
	}
	return n, err
}
