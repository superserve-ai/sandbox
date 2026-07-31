package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
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

// ManifestFile describes one packed artifact object. Object is the exact
// object name within the generation prefix, which embeds the packing
// fingerprint: the extent table in this entry describes that object and
// no other, even across retries that repacked a physically changed file.
type ManifestFile struct {
	Name   string `json:"name"`
	Object string `json:"object"`
	SHA256 string `json:"sha256"` // digest of the full apparent content
	Size   int64  `json:"size"`   // apparent size
	// BasePath records an overlay's base-image dependency: the overlay's
	// holes are backed by this file's contents, so a restore of the
	// overlay alone is incomplete without it (the consistency-pair rule).
	BasePath   string   `json:"base_path,omitempty"`
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
	completed, err := u.uploadTask(ctx, &task)
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
// task is a pointer so verification progress recorded during the attempt
// survives into the Nack that re-persists the task on failure.
func (u *Uploader) uploadTask(ctx context.Context, task *Task) (completed bool, _ error) {
	gen := GenerationManifest{
		SandboxID:  task.SandboxID,
		Generation: task.Generation,
		VMDVersion: u.VMDVersion,
	}
	for _, file := range task.Files {
		mf, err := u.uploadFile(ctx, task, file)
		if err != nil {
			if os.IsNotExist(err) || errors.Is(err, errSourceChanged) || errors.Is(err, ErrTruncatedSource) {
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
	if _, err := u.Store.Create(ctx, manifestObject, &limitedReader{r: bytes.NewReader(payload), limiter: u.Limiter, ctx: ctx}); err != nil {
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

func (u *Uploader) uploadFile(ctx context.Context, task *Task, file TaskFile) (ManifestFile, error) {
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
	// before any bytes ship: a cheap early abort for the common mutation
	// case (the sandbox resumed before the drain).
	sum, err := hashApparent(ctx, f, extents, apparent)
	if err != nil {
		return ManifestFile{}, fmt.Errorf("verify %s: %w", file.Path, err)
	}
	if sum != file.SHA256 {
		u.Log.Warn().Str("path", file.Path).Str("want", file.SHA256).Str("got", sum).
			Msg("backup source changed since pause; abandoning generation")
		return ManifestFile{}, errSourceChanged
	}
	// The object name embeds the packing fingerprint: a retry over a
	// physically relaid file (same apparent content, different extents)
	// maps to a fresh object instead of deduping against bytes packed with
	// a different table, so the manifest's extent table always describes
	// the exact object it points at.
	objectName := file.Name + ".p" + PackFingerprint(extents, apparent)
	object, err := SandboxObject(task.SandboxID, task.Generation, objectName)
	if err != nil {
		return ManifestFile{}, err
	}
	// The stream hasher digests the apparent content of what is ACTUALLY
	// shipped (packed bytes as streamed, zeros for the holes), closing the
	// window the pre-check cannot: a mutation while the bandwidth-capped
	// upload streams would ship bytes that no longer match the recorded
	// digest. On mismatch the generation is abandoned before its manifest
	// object is written, and a generation without its completion marker is
	// never restored from; the orphaned artifact object is inert.
	hasher := newApparentStreamHasher(NewPackedReader(f, extents), extents, apparent)
	reader := &limitedReader{r: hasher, limiter: u.Limiter, ctx: ctx}
	created, err := u.Store.Create(ctx, object, reader)
	if err != nil {
		return ManifestFile{}, err
	}
	if created {
		// The store wrote exactly the bytes that flowed through the
		// hasher; anything short of full consumption with a matching
		// digest means the stored object is not what the manifest would
		// claim.
		shipped, complete := hasher.finish()
		if !complete || shipped != file.SHA256 {
			u.Log.Warn().Str("path", file.Path).Str("want", file.SHA256).Str("got", shipped).
				Bool("fully_streamed", complete).
				Msg("backup source changed during upload; abandoning generation")
			return ManifestFile{}, errSourceChanged
		}
		// Persist that these exact object bytes were verified BEFORE any
		// further progress, both in the task (survives nacks) and in the
		// durable history (survives acks): a later retry or an unchanged
		// re-pause may then trust a dedupe of this object.
		if !task.HasVerified(object) {
			task.VerifiedObjects = append(task.VerifiedObjects, object)
			if err := u.Journal.Update(*task); err != nil {
				return ManifestFile{}, fmt.Errorf("persist verification of %s: %w", object, err)
			}
		}
		if err := u.Journal.MarkVerified(object, time.Now()); err != nil {
			return ManifestFile{}, fmt.Errorf("record verification of %s: %w", object, err)
		}
	} else if !task.HasVerified(object) {
		// The object already existed (dedupe). Stream consumption proves
		// nothing here: small objects buffer fully before the
		// precondition failure arrives. The object may be a completed
		// earlier upload (unchanged re-pause after the original task
		// acked) or the residue of a crash between finalize and
		// verification; the durable verification history is the only
		// discriminator, and without it the generation is abandoned
		// rather than completed over bytes nothing can vouch for (this
		// identity cannot read them back).
		wasVerified, err := u.Journal.WasVerified(object, time.Now())
		if err != nil {
			return ManifestFile{}, err
		}
		if !wasVerified {
			u.Log.Warn().Str("object", object).Str("sandbox_id", task.SandboxID).
				Msg("deduped object has no verification history; abandoning generation")
			return ManifestFile{}, errSourceChanged
		}
	}
	return ManifestFile{
		Name:       file.Name,
		Object:     objectName,
		SHA256:     file.SHA256,
		BasePath:   file.BasePath,
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

// apparentStreamHasher digests the apparent content of the bytes flowing
// through it: packed data as streamed, plus zeros for the holes between
// extents, so its sum is directly comparable to the pause manifest digest.
type apparentStreamHasher struct {
	r        io.Reader
	extents  []Extent
	apparent int64
	h        hash.Hash
	idx      int   // extent currently being consumed
	inExt    int64 // data bytes consumed within extents[idx]
	pos      int64 // apparent offset hashed so far
	zeros    []byte
	consumed int64 // total packed bytes seen
}

func newApparentStreamHasher(r io.Reader, extents []Extent, apparent int64) *apparentStreamHasher {
	return &apparentStreamHasher{r: r, extents: extents, apparent: apparent, h: sha256.New(), zeros: make([]byte, 64<<10)}
}

func (a *apparentStreamHasher) hashZerosTo(target int64) {
	for a.pos < target {
		n := target - a.pos
		if n > int64(len(a.zeros)) {
			n = int64(len(a.zeros))
		}
		a.h.Write(a.zeros[:n])
		a.pos += n
	}
}

func (a *apparentStreamHasher) Read(p []byte) (int, error) {
	n, err := a.r.Read(p)
	rest := p[:n]
	for len(rest) > 0 && a.idx < len(a.extents) {
		ext := a.extents[a.idx]
		a.hashZerosTo(ext.Offset)
		remain := ext.Length - a.inExt
		take := int64(len(rest))
		if take > remain {
			take = remain
		}
		a.h.Write(rest[:take])
		a.inExt += take
		a.pos += take
		rest = rest[take:]
		if a.inExt == ext.Length {
			a.idx++
			a.inExt = 0
		}
	}
	a.consumed += int64(n)
	return n, err
}

// finish returns the digest of the streamed apparent content and whether
// the stream was fully consumed. A create-only store that already had the
// object (dedupe, the 412 path) consumes none or only part of the stream;
// those stored bytes were stream-verified when the object was first
// written, so the caller skips the comparison instead of failing. The one
// gap, a crash between an object's create and its verification followed by
// a mutation, is caught by restore-side digest verification.
func (a *apparentStreamHasher) finish() (string, bool) {
	if a.consumed != PackedSize(a.extents) {
		return "", false
	}
	a.hashZerosTo(a.apparent)
	return hex.EncodeToString(a.h.Sum(nil)), true
}
