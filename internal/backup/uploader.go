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
	"path/filepath"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/time/rate"

	"github.com/superserve-ai/sandbox/internal/telemetry"
)

// GenerationManifest is the completion marker object, written after every
// artifact object of a generation is in the bucket. Restore reads it to
// learn the file set, verify digests, and rebuild sparse files from the
// extent tables. A generation without its manifest object is incomplete
// and never restored from.
type GenerationManifest struct {
	SandboxID  string         `json:"sandbox_id,omitempty"`
	TemplateID string         `json:"template_id,omitempty"`
	BuildID    string         `json:"build_id,omitempty"`
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
	BaseSHA256 string   `json:"base_sha256,omitempty"`
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
	// bookkeeping and local-staging GC key on. Delivery is at-least-once:
	// the signal is held durably in the journal's outbox until the
	// callback returns nil, and a restart redelivers undelivered signals,
	// so the callback must tolerate duplicates. A non-nil return keeps
	// the signal outboxed for the next flush (ack-time and idle ticks):
	// a delivery the consumer could not land must not be cleared.
	OnVerified func(Task) error
	// Tick is the idle poll interval. 0 → 1s.
	Tick time.Duration
	// notifyRetryAt gates the next delivery attempt after a failed one.
	// Touched only from Run's goroutine (ack and idle flushes).
	notifyRetryAt time.Time
	// LegacyStagingRoot is a retired staging location still referenced
	// by journal rows enqueued before a relocation. It is swept with the
	// same journal authority as StagingRoot until it empties, then the
	// directory itself is removed; deleting it eagerly would destroy
	// staged copies that queued tasks still need.
	LegacyStagingRoot string
	// StagingRoot is the hard-link staging tree; finished tasks get
	// their staged generation removed. Empty disables staging cleanup.
	StagingRoot string
	// Now overrides the wall clock in tests; nil means time.Now. Used
	// for failure-time backoff, where the drain-start time would let a
	// late failure retry immediately.
	Now func() time.Time
	// Metrics optionally records upload outcomes and notify failures.
	// Nil disables recording (every recorder method is nil-safe), and a
	// metrics error can never affect backup behavior: the recorder only
	// observes, it is never consulted.
	Metrics *telemetry.BackupRecorder
}

func (u *Uploader) clock() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now()
}

// Run drains the journal until ctx ends. Crash-safe by construction: work
// is acked only after verification, so a restart resumes exactly where the
// journal says.
func (u *Uploader) Run(ctx context.Context) error {
	tick := u.Tick
	if tick <= 0 {
		tick = time.Second
	}
	// Claim pre-scoping verification records for the configured bucket
	// before any lookup can miss them; idempotent after the first boot.
	// The drain must not start until this lands: a lookup missing a
	// still-unmigrated record would abandon a generation the record
	// protects, so a transient failure (full disk) retries rather than
	// being logged past.
	for {
		if err := u.Journal.MigrateVerificationScope(u.Store.Identity()); err == nil {
			break
		} else {
			u.Log.Error().Err(err).Msg("verification scope migration failed; retrying before draining")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(tick):
		}
	}
	// Seed the outbox from completions that predate reporter wiring, so
	// pre-rollout generations reach control-plane coverage; once per
	// scope, and only when a consumer exists to deliver them.
	if u.OnVerified != nil {
		for {
			if err := u.Journal.SeedOutboxFromCompletions(u.Store.Identity()); err == nil {
				break
			} else {
				u.Log.Error().Err(err).Msg("outbox completion seed failed; retrying before draining")
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(tick):
			}
		}
	}
	// Deliver completion signals a previous process acked but never
	// notified: the outbox is the only record of those.
	u.flushNotifications()
	lastSweep := u.clock()
	for {
		// Checked every iteration: a successful Nack after a canceled
		// upload returns (worked, nil), and without this check a queued
		// backlog would be drained (and pointlessly nacked) task by task
		// before the idle select ever observed cancellation.
		if ctx.Err() != nil {
			return nil
		}
		worked, err := u.drainOne(ctx, u.clock())
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
			// Retry any undelivered completion signal on the idle tick:
			// a flush that failed (or a ClearNotification that lost its
			// race with a crash) would otherwise wait for the next ack,
			// which on an idle host never comes.
			u.flushNotifications()
		}
		// Staged shared bases are real copies on non-reflink hosts and
		// outlive their tasks by design; sweep them against the journal
		// periodically. Deliberately OUTSIDE the idle branch: a host
		// with a standing backlog never idles, and the sweep must not
		// starve exactly when staged residue accumulates fastest.
		if u.StagingRoot != "" && u.clock().Sub(lastSweep) > stagingSweepInterval {
			lastSweep = u.clock()
			SweepStaging(u.StagingRoot, u.Journal, u.Log)
			u.sweepLegacyStaging()
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
	start := u.clock()
	completed, streamed, err := u.uploadTask(ctx, &task)
	// Bytes count what actually reached new bucket objects, failures
	// included: partial progress is real upload traffic.
	u.Metrics.AddUploadBytes(ctx, streamed)
	if err != nil {
		// Retries are bounded: a task that has failed this many times is
		// structurally stuck (its error is not transient at any horizon
		// that matters), and unbounded retry converts one stuck task
		// class into monotonic journal and staging growth. Abandoning is
		// safe by the same contract every abandon path relies on: the
		// generation's coverage is sacrificed, the owner's next pause
		// covers, and the error log is the operator signal (with the
		// abandoned outcome in the upload metric).
		if task.Attempts+1 >= maxUploadAttempts && !isStoreError(err) && !errors.Is(err, context.Canceled) {
			task.logOwner(u.Log.Error().Err(err)).
				Str("generation", task.Generation).
				Int("attempts", task.Attempts+1).
				Msg("backup upload retries exhausted; abandoning generation")
			if aerr := u.Journal.Ack(task, "", false); aerr != nil {
				return true, aerr
			}
			removeStagedTask(u.StagingRoot, task)
			u.Metrics.RecordUpload(ctx, telemetry.BackupUploadAbandoned, u.clock().Sub(start))
			return true, nil
		}
		// A shutdown-canceled attempt is not a failure signal; the task
		// retries on the next boot.
		if ctx.Err() == nil {
			u.Metrics.RecordUpload(ctx, telemetry.BackupUploadFailed, u.clock().Sub(start))
		}
		task.logOwner(u.Log.Warn().Err(err)).
			Str("generation", task.Generation).
			Int("attempts", task.Attempts+1).
			Msg("backup upload failed; will retry")
		// Backoff counts from the FAILURE, not the drain start: a long
		// upload that fails late would otherwise already be past its
		// NotBefore and retry immediately.
		return true, u.Journal.Nack(task, u.clock())
	}
	result := telemetry.BackupUploadAbandoned
	if completed {
		result = telemetry.BackupUploadDeduped
		if streamed > 0 {
			result = telemetry.BackupUploadVerified
		}
	}
	u.Metrics.RecordUpload(ctx, result, u.clock().Sub(start))
	if !completed && !task.Staged {
		// Abandonment of a mutable-path task: a concurrent dedupe may
		// have upgraded the row to staged snapshots that would survive
		// whatever deleted our sources. Leave the upgraded row for the
		// next drain instead of acking it away.
		if cur, ok, lerr := u.Journal.Load(task); lerr == nil && ok && cur.Staged {
			task.logOwner(u.Log.Info()).
				Msg("abandoned mutable-path attempt; staged row retained for retry")
			return true, nil
		}
	}
	if !completed && task.TemplateID != "" {
		// Operator-visible by design: an abandoned template generation has
		// no automatic corrective pause behind it the way a sandbox does;
		// the recovery sweep re-reconciles from the on-host artifacts, but
		// a template whose artifacts diverged from their stamps needs eyes.
		task.logOwner(u.Log.Error()).
			Str("generation", task.Generation).
			Msg("template backup generation abandoned")
	}
	completedScope := ""
	if completed {
		completedScope = u.Store.Identity()
	}
	if err := u.Journal.Ack(task, completedScope, completed && u.OnVerified != nil); err != nil {
		return true, err
	}
	removeStagedTask(u.StagingRoot, task)
	u.flushNotifications()
	return true, nil
}

// notifyRetryDelay spaces delivery attempts after a failure: the idle
// flush runs every tick, and a control plane that is down must not be
// hammered (or the log flooded) once per second per pending signal.
const notifyRetryDelay = 30 * time.Second

// flushNotifications delivers every outboxed completion signal and
// confirms each only after the callback returns nil. Failures to
// deliver, load, or clear are logged and retried on a later flush
// (spaced by notifyRetryDelay), never dropped.
func (u *Uploader) flushNotifications() {
	if u.OnVerified == nil {
		return
	}
	if !u.notifyRetryAt.IsZero() && time.Now().Before(u.notifyRetryAt) {
		return
	}
	pending, err := u.Journal.PendingNotifications()
	if err != nil {
		u.Metrics.AddNotifyFailure(context.Background())
		u.Log.Warn().Err(err).Msg("backup notification outbox read failed")
		return
	}
	for _, t := range pending {
		if err := u.OnVerified(t); err != nil {
			// Stop the batch: a control plane that failed this delivery
			// will fail the rest too, and each attempt can hold the
			// drain goroutine for the full request timeout. The retained
			// entries redeliver together after the retry window.
			u.Metrics.AddNotifyFailure(context.Background())
			t.logOwner(u.Log.Warn().Err(err)).
				Str("generation", t.Generation).
				Msg("backup notification delivery failed; will redeliver")
			u.notifyRetryAt = time.Now().Add(notifyRetryDelay)
			return
		}
		u.notifyRetryAt = time.Time{}
		if err := u.Journal.ClearNotification(t); err != nil {
			u.Metrics.AddNotifyFailure(context.Background())
			t.logOwner(u.Log.Warn().Err(err)).
				Str("generation", t.Generation).
				Msg("backup notification clear failed; will redeliver")
		}
	}
}

// baseTaskFile synthesizes the shared upload entry for an overlay's
// base image. Size comes from the live file: the digest check subsumes
// it (a size change changes the digest).
func baseTaskFile(file TaskFile) (TaskFile, error) {
	// Read from the staged snapshot when one exists; BasePath stays the
	// recorded identity either way.
	src := file.BasePath
	if file.BaseStagedPath != "" {
		src = file.BaseStagedPath
	}
	fi, err := os.Stat(src)
	if err != nil {
		return TaskFile{}, err
	}
	return TaskFile{
		Name:   SharedBaseName(file.BaseSHA256),
		Path:   src,
		SHA256: file.BaseSHA256,
		Size:   fi.Size(),
		Shared: true,
	}, nil
}

// SharedBaseName derives the manifest file name a shared base entry
// restores to from its content digest. A fixed name would collide when a
// generation depends on two different bases: the upload would succeed,
// but restore's exclusive per-name creation could never materialize both
// files, a complete-yet-unrestorable generation discovered only at
// recovery time.
// SharedBaseName carries the FULL digest: distinct bases must map to
// distinct restored file names unconditionally, and a truncated prefix
// would let a (however unlikely) collision produce a generation that
// uploads completely but is rejected at restore for duplicate names.
func SharedBaseName(sha string) string {
	return "base-" + sha + ".ext4"
}

// ReportedFiles returns the manifest entries a verified generation's
// coverage report should carry: the task's own files plus the shared
// base entries uploadTask synthesizes into the bucket manifest, which
// task.Files alone omits. Shared sizes come from the staged or original
// source when it still exists and are zero otherwise: delivery can
// outlive ack-time staging cleanup, and the base object's authoritative
// size lives in the bucket manifest either way.
func (t *Task) ReportedFiles() []TaskFile {
	out := append([]TaskFile(nil), t.Files...)
	seen := map[string]bool{}
	for _, f := range t.Files {
		if f.BaseSHA256 == "" || seen[f.BaseSHA256] {
			continue
		}
		seen[f.BaseSHA256] = true
		bf, err := baseTaskFile(f)
		if err != nil {
			bf = TaskFile{Name: SharedBaseName(f.BaseSHA256), SHA256: f.BaseSHA256, Shared: true}
		}
		out = append(out, bf)
	}
	return out
}

// uploadTask ships every artifact of a generation, then its manifest
// object. Objects are content-addressed and create-only, so retries after
// partial progress re-cover already-written objects as no-ops. completed
// is false when the generation was abandoned (source files gone): the
// task is done, but nothing was made durable, so verification hooks must
// not fire.
// task is a pointer so verification progress recorded during the attempt
// survives into the Nack that re-persists the task on failure. streamed
// counts bytes written into newly created objects across the attempt,
// error paths included (dedupes and skips add nothing).
func (u *Uploader) uploadTask(ctx context.Context, task *Task) (completed bool, streamed int64, _ error) {
	gen := GenerationManifest{
		SandboxID:  task.SandboxID,
		TemplateID: task.TemplateID,
		BuildID:    task.BuildID,
		Generation: task.Generation,
		VMDVersion: u.VMDVersion,
	}
	uploadedBases := map[string]bool{}
	for _, file := range task.Files {
		mf, n, err := u.uploadFile(ctx, task, file)
		streamed += n
		if err != nil {
			if os.IsNotExist(err) || errors.Is(err, errSourceChanged) || errors.Is(err, ErrTruncatedSource) {
				// The artifact vanished or mutated between enqueue and
				// upload (sandbox deleted or resumed, local GC won the
				// race). Nothing valid to back up under this content
				// address; the generation is abandoned, not retried.
				task.logOwner(u.Log.Warn().Str("path", file.Path)).
					Msg("backup source file gone; abandoning generation")
				return false, streamed, nil
			}
			return false, streamed, err
		}
		gen.Files = append(gen.Files, mf)
		// An overlay's holes are backed by its base image, and the bucket
		// is the only copy that survives host loss: a generation whose
		// manifest names a base that exists nowhere durable is not
		// restorable. The base ships as a bucket-wide content-addressed
		// object, so every sandbox on the base dedupes against one
		// upload; the digest recorded at pause time is the pre-verify
		// authority, so a base rebuilt since then abandons the
		// generation exactly like any mutated source.
		if file.BaseSHA256 != "" && !uploadedBases[file.BaseSHA256] {
			bf, err := baseTaskFile(file)
			if err != nil {
				if os.IsNotExist(err) {
					task.logOwner(u.Log.Warn().Str("path", file.BasePath)).
						Msg("backup base image gone; abandoning generation")
					return false, streamed, nil
				}
				return false, streamed, err
			}
			bmf, n, err := u.uploadFile(ctx, task, bf)
			streamed += n
			if err != nil {
				if os.IsNotExist(err) || errors.Is(err, errSourceChanged) || errors.Is(err, ErrTruncatedSource) {
					task.logOwner(u.Log.Warn().Str("path", bf.Path)).
						Msg("backup base image gone or rebuilt; abandoning generation")
					return false, streamed, nil
				}
				return false, streamed, err
			}
			uploadedBases[file.BaseSHA256] = true
			gen.Files = append(gen.Files, bmf)
		}
	}
	manifestObject, err := task.objectName(ManifestObject)
	if err != nil {
		return false, streamed, err
	}
	payload, err := json.Marshal(gen)
	if err != nil {
		return false, streamed, err
	}
	created, err := u.Store.Create(ctx, manifestObject, &limitedReader{r: bytes.NewReader(payload), limiter: u.Limiter, ctx: ctx})
	if err != nil {
		return false, streamed, fmt.Errorf("manifest object: %w", storeError{err})
	}
	if created {
		streamed += int64(len(payload))
	}
	return true, streamed, nil
}

// stagingSweepInterval paces the running staged-base sweep.
const stagingSweepInterval = 30 * time.Minute

// maxUploadAttempts bounds a task's retries for LOCAL failures, which
// are deterministic: the same bytes and environment fail the same way,
// so this many identical failures is structural, and unbounded retry
// converts one stuck task class into monotonic journal and staging
// growth. Store errors are exempt: an outage or credential problem is
// environmental, however long it lasts, and exhausting durable work
// against it would discard generations (a destroyed sandbox has no next
// pause) that become uploadable the moment the store recovers. Outage
// depth stays visible through the queue-age telemetry instead.
const maxUploadAttempts = 60

// storeError marks a failure that came from the blob store rather than
// local preparation, exempting it from the retry ceiling.
type storeError struct{ err error }

func (e storeError) Error() string { return e.err.Error() }
func (e storeError) Unwrap() error { return e.err }

func isStoreError(err error) bool {
	var se storeError
	return errors.As(err, &se)
}

// sweepLegacyStaging drains a retired staging location under journal
// authority and removes the directory once nothing references it. The
// non-recursive Remove is the emptiness check: it fails harmlessly
// while any sandbox or base entry survives.
func (u *Uploader) sweepLegacyStaging() {
	if u.LegacyStagingRoot == "" {
		return
	}
	SweepStaging(u.LegacyStagingRoot, u.Journal, u.Log)
	// The bases subdirectory outlives its last entry; both removes are
	// non-recursive, so each succeeds only against emptiness.
	_ = os.Remove(filepath.Join(u.LegacyStagingRoot, "bases"))
	if err := os.Remove(u.LegacyStagingRoot); err == nil {
		u.Log.Info().Str("path", u.LegacyStagingRoot).Msg("legacy backup staging tree drained and removed")
		u.LegacyStagingRoot = ""
	}
}

// objectName routes an object into the task owner's prefix. Both owners
// keep the content-addressed generation segment: build ids are reusable
// across rebuilds of a template, so the generation is what stops a rebuild
// from deduping against a previous build's objects (see TemplateObject).
func (t *Task) objectName(fileName string) (string, error) {
	if t.TemplateID != "" {
		return TemplateObject(t.TemplateID, t.BuildID, t.Generation, fileName)
	}
	return SandboxObject(t.SandboxID, t.Generation, fileName)
}

// logOwner stamps the task's owning identity onto a log event.
func (t *Task) logOwner(e *zerolog.Event) *zerolog.Event {
	if t.TemplateID != "" {
		return e.Str("template_id", t.TemplateID).Str("build_id", t.BuildID)
	}
	return e.Str("sandbox_id", t.SandboxID)
}

// errSourceChanged marks a source file whose current content no longer
// matches the digest recorded at pause time: the sandbox resumed and
// mutated the disk before the upload drained. Shipping those bytes under
// the old content address would create a generation whose objects
// contradict their manifest, so the generation is abandoned instead; the
// resume's next pause enqueues the corrective generation under a new key.
var errSourceChanged = errors.New("backup source changed since pause")

// verificationKey scopes a verification record to the destination
// bucket: history is proof that THIS bucket holds verified bytes under
// the name, and a host repointed at a different bucket must re-establish
// existence by streaming rather than trusting records earned elsewhere.
// (Deletion from the same bucket is a control-plane GC invariant: a
// shared base may only be reaped when no manifest references it, with
// enough grace to cover in-flight generations.)
func (u *Uploader) verificationKey(object string) string {
	return u.Store.Identity() + "\x00" + object
}

// verifiedHere reports whether this task or this host's history has
// verified the object against the current bucket. Lookups are purely
// scoped: pre-upgrade records are claimed for the then-configured
// bucket once at startup (MigrateVerificationScope), so a later bucket
// change correctly misses everything.
func (u *Uploader) verifiedHere(task *Task, object string) (bool, error) {
	if task.HasVerified(u.verificationKey(object)) {
		return true, nil
	}
	return u.Journal.WasVerified(u.verificationKey(object), u.clock())
}

// uploadFile ships one artifact object. shipped counts bytes written
// into a newly created object (zero on dedupes, skips, and failures that
// abort the create), so byte accounting reflects storage actually done.
func (u *Uploader) uploadFile(ctx context.Context, task *Task, file TaskFile) (_ ManifestFile, shipped int64, _ error) {
	if file.Name == ManifestObject {
		return ManifestFile{}, 0, fmt.Errorf("artifact name %q collides with the manifest object", file.Name)
	}
	f, err := os.Open(file.Path)
	if err != nil {
		return ManifestFile{}, 0, err
	}
	defer f.Close()
	extents, apparent, err := Extents(f)
	if err != nil {
		return ManifestFile{}, 0, fmt.Errorf("extents %s: %w", file.Path, err)
	}
	// Verify the source still matches the digest recorded at pause time
	// before any bytes ship: a cheap early abort for the common mutation
	// case (the sandbox resumed before the drain).
	sum, err := hashApparent(ctx, f, extents, apparent)
	if err != nil {
		return ManifestFile{}, 0, fmt.Errorf("verify %s: %w", file.Path, err)
	}
	if sum != file.SHA256 {
		u.Log.Warn().Str("path", file.Path).Str("want", file.SHA256).Str("got", sum).
			Msg("backup source changed since pause; abandoning generation")
		return ManifestFile{}, 0, errSourceChanged
	}
	// The object name embeds the packing fingerprint: a retry over a
	// physically relaid file (same apparent content, different extents)
	// maps to a fresh object instead of deduping against bytes packed with
	// a different table, so the manifest's extent table always describes
	// the exact object it points at.
	var object, objectName string
	if file.Shared {
		// Shared objects live outside the generation prefix, so the
		// manifest records the full object path rather than a name
		// relative to the generation.
		object = SharedBaseObject(file.SHA256, PackFingerprint(extents, apparent))
		objectName = object
	} else {
		objectName = file.Name + ".p" + PackFingerprint(extents, apparent)
		object, err = task.objectName(objectName)
		if err != nil {
			return ManifestFile{}, 0, err
		}
	}
	if file.Shared {
		// Skip the stream when this host already verified these exact
		// object bytes: shared bases are multi-GB, and every generation
		// on the template re-references the same object, so streaming
		// just to discover the create-only 412 at finalize would pin the
		// bandwidth cap on redundant bytes and put the drain loop
		// permanently behind the pause arrival rate. The local source
		// was pre-verified above, the name embeds digest and packing
		// fingerprint, and the extent table here describes this host's
		// packing of content the history already vouches for.
		verified, _ := u.verifiedHere(task, object)
		if verified {
			u.Log.Info().Str("object", object).
				Msg("shared object verified previously; skipping stream")
			return ManifestFile{
				Name:       file.Name,
				Object:     objectName,
				SHA256:     file.SHA256,
				Size:       apparent,
				PackedSize: PackedSize(extents),
				Extents:    extents,
			}, 0, nil
		}
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
		return ManifestFile{}, 0, storeError{err}
	}
	if created {
		// The store finalized a new object from this stream; these bytes
		// are real upload traffic even when verification below rejects
		// the generation.
		shipped = hasher.consumed
		// The store wrote exactly the bytes that flowed through the
		// hasher; anything short of full consumption with a matching
		// digest means the stored object is not what the manifest would
		// claim.
		sum, complete := hasher.finish()
		if !complete || sum != file.SHA256 {
			u.Log.Warn().Str("path", file.Path).Str("want", file.SHA256).Str("got", sum).
				Bool("fully_streamed", complete).
				Msg("backup source changed during upload; abandoning generation")
			return ManifestFile{}, shipped, errSourceChanged
		}
		// Persist that these exact object bytes were verified BEFORE any
		// further progress, both in the task (survives nacks) and in the
		// durable history (survives acks): a later retry or an unchanged
		// re-pause may then trust a dedupe of this object. The in-memory
		// task adopts the record only after the durable write commits:
		// trust that reached disk in neither place must not ride into the
		// Nack, or the retry would dedupe against history that does not
		// exist.
		verified := task.VerifiedObjects
		if !task.HasVerified(u.verificationKey(object)) {
			verified = append(append([]string(nil), task.VerifiedObjects...), u.verificationKey(object))
		}
		next := *task
		next.VerifiedObjects = verified
		// The object is finalized and stream-verified; losing this write
		// would make the retry see an unverified dedupe and abandon a
		// generation whose bytes are provably good. Retry the record a
		// few times before surrendering to the Nack: if BoltDB stays
		// down, the whole pipeline is down with it anyway.
		var recErr error
		for attempt, delay := 0, 100*time.Millisecond; attempt < 3; attempt, delay = attempt+1, delay*2 {
			if recErr = u.Journal.RecordVerification(next, u.verificationKey(object), u.clock()); recErr == nil {
				break
			}
			time.Sleep(delay)
		}
		if recErr != nil {
			return ManifestFile{}, shipped, fmt.Errorf("record verification of %s: %w", object, recErr)
		}
		task.VerifiedObjects = verified
	} else if file.Shared {
		// A shared object deduped against another host's upload has no
		// local verification history, and hosts cannot read the bucket
		// to check. Trust is structural instead: the name embeds the
		// content digest and packing fingerprint, this host just proved
		// its own bytes match that digest, and every conforming writer
		// either stream-verified what it stored or abandoned without
		// publishing a manifest. The residual case (a writer crashed or
		// mutated mid-stream, leaving torn bytes squatting the name) is
		// caught by restore's mandatory digest check, and an operator
		// re-uploads the base with admin credentials; write-only hosts
		// cannot self-serve that check by design. Record the dedupe in
		// the verification history so later generations skip the stream
		// instead of re-discovering the 412 the slow way.
		u.Log.Info().Str("object", object).
			Msg("shared object already present; trusting content-addressed dedupe")
		next := *task
		if !next.HasVerified(u.verificationKey(object)) {
			next.VerifiedObjects = append(append([]string(nil), task.VerifiedObjects...), u.verificationKey(object))
		}
		if err := u.Journal.RecordVerification(next, u.verificationKey(object), u.clock()); err != nil {
			return ManifestFile{}, 0, fmt.Errorf("record shared dedupe of %s: %w", object, err)
		}
		task.VerifiedObjects = next.VerifiedObjects
	} else if ok, err := u.verifiedHere(task, object); err != nil {
		return ManifestFile{}, 0, err
	} else if !ok {
		// The object already existed (dedupe). Stream consumption proves
		// nothing here: small objects buffer fully before the
		// precondition failure arrives. The object may be a completed
		// earlier upload (unchanged re-pause after the original task
		// acked) or the residue of a crash between finalize and
		// verification; the durable verification history is the only
		// discriminator, and without it the generation is abandoned
		// rather than completed over bytes nothing can vouch for (this
		// identity cannot read them back).
		task.logOwner(u.Log.Warn().Str("object", object)).
			Msg("deduped object has no verification history; abandoning generation")
		return ManifestFile{}, 0, errSourceChanged
	}
	return ManifestFile{
		Name:       file.Name,
		Object:     objectName,
		SHA256:     file.SHA256,
		BasePath:   file.BasePath,
		BaseSHA256: file.BaseSHA256,
		Size:       apparent,
		PackedSize: PackedSize(extents),
		Extents:    extents,
	}, shipped, nil
}

// HashFileApparent digests a file's full apparent content the sparse
// way: data extents are read from disk and holes are hashed as zeros
// without touching disk, producing exactly the digest a sequential read
// would while reading only the real bytes. A multi-GB overlay whose
// real data is tens of MB hashes in the time of the tens of MB (plus
// SHA over the zero runs), not the gigabytes.
func HashFileApparent(ctx context.Context, path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	extents, apparent, err := Extents(f)
	if err != nil {
		return "", 0, fmt.Errorf("extents %s: %w", path, err)
	}
	sum, err := hashApparent(ctx, f, extents, apparent)
	if err != nil {
		return "", 0, err
	}
	return sum, apparent, nil
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
		// The section reader is wrapped so cancellation lands between
		// reads of a large dense extent, not only between extents: the
		// shutdown join waits on this loop, and an uncancelable multi-GB
		// read on a slow filesystem would outlive the join's deadline and
		// leave the loop touching closed dependencies.
		if _, err := io.Copy(h, &ctxReader{ctx: ctx, r: io.NewSectionReader(f, e.Offset, e.Length)}); err != nil {
			return "", err
		}
		pos = e.Offset + e.Length
	}
	if err := writeZeros(apparent); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ctxReader fails the next Read once ctx is canceled, making plain
// readers (section readers over artifact files) cancelable mid-stream.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
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
