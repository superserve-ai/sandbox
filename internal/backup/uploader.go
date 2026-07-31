package backup

import (
	"bytes"
	"context"
	"encoding/json"
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
		if !worked {
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
			if os.IsNotExist(err) {
				// The artifact vanished between enqueue and upload (sandbox
				// deleted, local GC won the race). Nothing to back up; the
				// generation is abandoned, not retried forever.
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

func (u *Uploader) uploadFile(ctx context.Context, task Task, file TaskFile) (ManifestFile, error) {
	f, err := os.Open(file.Path)
	if err != nil {
		return ManifestFile{}, err
	}
	defer f.Close()
	extents, apparent, err := Extents(f)
	if err != nil {
		return ManifestFile{}, fmt.Errorf("extents %s: %w", file.Path, err)
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
