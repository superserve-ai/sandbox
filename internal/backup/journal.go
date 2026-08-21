package backup

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Priority orders upload work. Lower value uploads first: a pause or an
// on-demand snapshot is user-visible durability; template builds,
// periodic checkpoints, and (later) memory-tier components are
// recoverable or rebuildable and must never delay it. A multi-GiB
// template upload at pause priority would head-of-line block every pause
// backup for minutes at the bandwidth cap, and a pause is unique user
// data while a template can be rebuilt.
type Priority uint8

const (
	PriorityPause Priority = iota
	PriorityCheckpoint
	PriorityBestEffort
)

// TaskFile is one artifact within a generation's upload task. SHA256 is the
// digest of the full apparent content (what the pause manifest recorded);
// the packed upload carries only data extents, and restore verifies the
// digest after reconstructing the sparse file.
type TaskFile struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	// BasePath carries an overlay's base-image dependency through to the
	// generation manifest; empty for standalone files.
	BasePath string `json:"base_path,omitempty"`
	// BaseSHA256 is the base image's content digest: the dependency's
	// identity is its bytes, not its path, so a rebuilt base at the same
	// path yields a different generation.
	BaseSHA256 string `json:"base_sha256,omitempty"`
	// BaseStagedPath is where the uploader READS the base image when
	// staging snapshotted it; BasePath itself never mutates after the
	// generation key is computed, because it is key-covered and recorded
	// in the manifest, and rewriting it post-key would make restore's
	// key recomputation reject the generation.
	BaseStagedPath string `json:"base_staged_path,omitempty"`
	// Shared marks a content-addressed artifact stored once bucket-wide
	// (under the bases/ prefix) rather than inside the generation: base
	// images are multi-GB and common to every sandbox on the template,
	// so each base version uploads exactly once fleet-wide and every
	// generation's manifest points at the same immutable object.
	Shared bool `json:"shared,omitempty"`
	// Object is the exact bucket object path the upload wrote for this
	// entry (packing fingerprint included, and the full bases/ path for
	// shared entries). Captured from the store write itself when the
	// finalized manifest is banked on the outbox copy, so coverage
	// reports can name objects without re-deriving them. Empty on queue
	// rows and on outbox entries written before the field existed;
	// consumers must treat it as optional.
	Object string `json:"object,omitempty"`
}

// Task is one generation awaiting upload. Tasks are idempotent: the
// generation key is content-addressed, so re-running a task lands on the
// same object names and the bucket's create-only precondition makes
// duplicates a no-op.
//
// Exactly one owner is set: SandboxID for pause generations, TemplateID
// (always with the BuildID that produced the artifacts) for template
// builds. The owner picks the object prefix; see Task.objectName.
type Task struct {
	SandboxID  string     `json:"sandbox_id,omitempty"`
	TemplateID string     `json:"template_id,omitempty"`
	BuildID    string     `json:"build_id,omitempty"`
	Generation string     `json:"generation"`
	Files      []TaskFile `json:"files"`
	Priority   Priority   `json:"priority"`
	EnqueuedAt time.Time  `json:"enqueued_at"`
	Attempts   int        `json:"attempts"`
	// NotBefore delays retry after a failure (exponential backoff).
	NotBefore time.Time `json:"not_before,omitempty"`
	// VerifiedObjects records objects whose streamed bytes this task has
	// already digest-verified, persisted before further progress. On a
	// retry, a create-only dedupe is trusted ONLY for objects listed here:
	// an existing object this task never verified may be the residue of a
	// crash between finalize and verification, so the generation is
	// abandoned rather than completed over unverifiable bytes.
	VerifiedObjects []string `json:"verified_objects,omitempty"`
	// Staged records that every file path (bases included) points into
	// the uploader-owned staging tree; the dedupe upgrade in Enqueue is
	// one-way toward staged.
	Staged bool `json:"staged,omitempty"`
	// ClaimToken fences resolution against lease steals: Next stamps the
	// claim's token here, and Ack/Nack refuse to touch a row whose live
	// claim carries a different token (the lease expired and another
	// worker took over; its resolution supersedes this one). Never
	// persisted — claims are process-local, and a serialized token would
	// outlive the claim table it indexes into.
	ClaimToken uint64 `json:"-"`
	// VerifiedBucket names the store identity this completion was
	// verified against. Set only on the outbox copy at ack time: a
	// notification delivered after a restart with a different
	// BACKUP_BUCKET must report the bucket that actually holds the
	// bytes, not the newly configured one. Empty on queue rows and on
	// outbox entries written before the field existed (consumers fall
	// back to the current bucket, the pre-field behavior).
	VerifiedBucket string `json:"verified_bucket,omitempty"`
	// FilesFinal marks Files as the finalized reportable manifest,
	// captured at upload completion with authoritative sizes; consumers
	// use it verbatim instead of re-synthesizing shared entries from
	// local paths that ack-time cleanup may have removed.
	FilesFinal bool `json:"files_final,omitempty"`
	// VerifiedAt is when the upload verified, pinned on the outbox copy
	// alongside VerifiedBucket: deliveries run in outbox key order (owner
	// and content hash, not chronology), so stamping delivery time would
	// let an older generation delivered later rank as the newest backup.
	VerifiedAt time.Time `json:"verified_at,omitempty"`
}

// filesCarryObjects reports whether any entry records its exact bucket
// object path.
func filesCarryObjects(files []TaskFile) bool {
	for _, f := range files {
		if f.Object != "" {
			return true
		}
	}
	return false
}

// HasVerified reports whether this task already verified object.
func (t *Task) HasVerified(object string) bool {
	for _, o := range t.VerifiedObjects {
		if o == object {
			return true
		}
	}
	return false
}

// Journal is the crash-safe upload queue. Enqueue is called in the pause
// path after artifacts are finalized; Ack only after the upload is verified.
// Everything in between survives a vmd restart: on boot the uploader drains
// whatever the journal holds. Ack is also the signal that makes local
// staging deletable, so it must never fire early.
type Journal struct {
	db *bolt.DB

	// mu guards claims AND spans every claim-coupled row mutation: Next's
	// whole scan-and-claim, and the ownership check plus bolt write in
	// Ack/Nack. Holding it across the writes is what makes the fencing
	// airtight — a stale worker's resolution and a thief's cannot
	// interleave against the same row, because whichever acquires mu
	// second sees the full effect of the first.
	mu sync.Mutex
	// claims marks queue keys handed out by Next and not yet resolved by
	// Ack or Nack, so concurrent workers each receive a distinct task.
	// Deliberately in-memory: bolt's exclusive file lock makes the journal
	// single-process, so a claim can only ever be held by this process,
	// and a crash releases every claim by construction — persisting them
	// would instead make a restarted vmd wait out stale leases before
	// resuming in-flight work. The expiry is a backstop for a worker
	// goroutine wedged past any plausible upload; the token fences the
	// wedged worker's late resolution if it ever resumes after a steal.
	claims map[string]claim
	// claimSeq issues claim tokens, under mu. Starts from 1 so a zero
	// ClaimToken (a task never handed out by Next, e.g. direct test
	// calls) can never match a live claim.
	claimSeq uint64
}

// claim is one outstanding lease: when it lapses and who holds it.
type claim struct {
	until time.Time
	token uint64
}

var (
	journalBucket = []byte("backup_upload_queue")
	// indexBucket maps sandbox/generation identity to the pending queue
	// key, so enqueue dedupe is one point lookup instead of a scan of the
	// whole backlog (which grows during bucket outages, and the scan held
	// a write transaction that blocked uploader acks).
	indexBucket = []byte("backup_upload_index")
	// outboxBucket holds completed tasks whose OnVerified notification
	// has not yet been delivered. Written in the same transaction as the
	// ack that deletes the task, so no crash window exists in which the
	// generation is complete but the completion signal is lost; entries
	// are deleted only after the callback returns, making delivery
	// at-least-once (consumers must be idempotent).
	outboxBucket = []byte("backup_verified_outbox")
	// verifiedBucket records object names whose streamed bytes were
	// digest-verified, OUTLIVING the tasks that verified them: an
	// unchanged re-pause re-enqueues an already-completed generation, and
	// its dedupes must be distinguishable from crash residue after the
	// original task was acked. Entries carry a timestamp and are pruned
	// lazily on ack.
	verifiedBucket = []byte("backup_verified_objects")
	// completionsBucket records owner+generation pairs whose generation
	// fully reached the bucket (manifest object written, task acked as
	// completed). Kept indefinitely: rows are tiny, and this record is
	// what lets recovery sweeps distinguish "already durable, skip" from
	// "never made it, reconcile", without which a swept owner would be
	// re-uploaded on every pass after its task was acked away.
	completionsBucket = []byte("backup_completed_generations")
	// seededBucket records, per completion key, the completion VALUE (the
	// ack instant) whose notification signal was banked in the outbox (by
	// the ack itself, or by a seed). The seed skips an entry only when
	// the banked value matches the current one, which makes seeding track
	// acknowledgments rather than keys: an older uploader's rollback-window
	// ack of the SAME generation overwrites the completion value without
	// touching this record, and the mismatch re-seeds the newer instant.
	seededBucket = []byte("backup_outbox_seeded")
)

// verifiedRetention bounds how long verification history is kept. Long
// enough to cover any plausible re-enqueue of an unchanged generation;
// after expiry a dedupe degrades to abandonment, which is safe (the
// generation is already complete in the bucket).
const verifiedRetention = 14 * 24 * time.Hour

// pruneExamineLimit bounds verification-history entries examined per ack.
const pruneExamineLimit = 64

// pruneCursorKey persists the prune resume position inside the bucket
// (prefixed so it sorts apart from object names, which never start NUL).
var pruneCursorKey = []byte("\x00prune_cursor")

// claimTTL bounds how long an unresolved claim excludes its task from
// Next. Sized above the slowest plausible upload at the bandwidth cap (a
// multi-GB shared base at 100 Mbit/s runs tens of minutes), so expiry
// only ever fires on a genuinely wedged worker; the steal it then permits
// is safe, just redundant.
const claimTTL = time.Hour

// NewJournal opens (creating if needed) the journal bucket in db. The
// caller owns the bolt DB; sharing vmd's state DB keeps one fsync domain.
func NewJournal(db *bolt.DB) (*Journal, error) {
	err := db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{journalBucket, indexBucket, verifiedBucket, outboxBucket, completionsBucket, seededBucket} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("create journal bucket: %w", err)
	}
	return &Journal{db: db, claims: make(map[string]claim)}, nil
}

// readyAt is when the task becomes runnable: its enqueue time until a
// Nack defers it. Keys sort by it so Next never scans deferred work.
func (t *Task) readyAt() time.Time {
	if t.NotBefore.After(t.EnqueuedAt) {
		return t.NotBefore
	}
	return t.EnqueuedAt
}

// owner is the task's full owner identity: the sandbox id for pause
// generations, the template/build pair for template builds. NUL-joined so
// the pair can never alias a sandbox id or another template's pair.
func (t *Task) owner() string {
	if t.TemplateID != "" {
		return t.TemplateID + "\x00" + t.BuildID
	}
	return t.SandboxID
}

// key orders the queue: priority, then READINESS time, then the owner
// and generation for uniqueness. Readiness rather than enqueue time is
// load-bearing for outage backlogs: deferred tasks sort behind runnable
// ones within their priority, so Next examines at most one entry per
// priority instead of scanning every deferred entry on each drain and
// idle tick. The owner segment is load-bearing too: generations are
// content-addressed, so two untouched sandboxes cloned from one template
// (or two template builds producing identical artifacts) share a
// generation, and without the owner a same-tick enqueue would collide
// keys and silently drop one owner's backup.
func (t *Task) key() []byte {
	return []byte(fmt.Sprintf("%d/%020d/%s/%s", t.Priority, t.readyAt().UnixNano(), t.owner(), t.Generation))
}

// indexKey is the pending-generation identity for the dedupe index. The
// owner segment is the sandbox id or the template/build pair, so template
// tasks dedupe on their own identity and can never collide with a sandbox
// task sharing a generation key.
func (t *Task) indexKey() []byte {
	return []byte(t.owner() + "\x00" + t.Generation)
}

// Enqueue adds a task. A task for the same generation that is already
// pending is not enqueued again: content addressing makes the duplicate
// upload harmless, but there is no reason to do the work twice (idempotent
// pause retries re-enqueue the identical generation).
func (j *Journal) Enqueue(task Task) error {
	if task.Generation == "" {
		return fmt.Errorf("task missing generation: %+v", task)
	}
	if (task.SandboxID == "") == (task.TemplateID == "") {
		return fmt.Errorf("task must identify exactly one of sandbox or template: %+v", task)
	}
	if task.TemplateID != "" && task.BuildID == "" {
		return fmt.Errorf("template task missing build id: %+v", task)
	}
	if task.EnqueuedAt.IsZero() {
		task.EnqueuedAt = time.Now().UTC()
	}
	val, err := json.Marshal(task)
	if err != nil {
		return err
	}
	// Under mu for the claim move below: a promotion that re-keys a row
	// a worker is actively uploading must move the claim in the same
	// critical section, or the scan would see the re-keyed row as
	// unclaimed and hand it to a second worker mid-upload.
	j.mu.Lock()
	defer j.mu.Unlock()
	var moveFrom, moveTo []byte
	uerr := j.db.Update(func(tx *bolt.Tx) error {
		queue := tx.Bucket(journalBucket)
		idx := tx.Bucket(indexBucket)
		// One point lookup; a stale index entry (its queue key gone, e.g.
		// the entry was dropped as corrupt) self-heals by overwriting.
		if qk := idx.Get(task.indexKey()); qk != nil {
			if existing := queue.Get(qk); existing != nil {
				// Dedupe, with a path upgrade: a first enqueue can carry
				// mutable original paths (staging proof failed on the
				// pause path) and a later at-rest retry the staged ones.
				// The generation is content-addressed, so the digests are
				// identical either way; adopting the STAGED paths makes
				// the queued upload survive teardown, and the guard is
				// one-way so a later mutable-path enqueue never
				// downgrades a staged row. Scheduling state (attempts,
				// NotBefore, position) stays with the row.
				var cur Task
				if err := json.Unmarshal(existing, &cur); err != nil {
					// An undecodable row must not swallow the incoming
					// task as a silent dedupe: replace it — under the
					// incoming task's OWN key, never the corrupt row's.
					// Every row living at exactly its task's key is what
					// resolution fencing leans on for durable ownership
					// evidence; a row parked under a foreign key could be
					// claimed but never acked.
					if err := queue.Delete(qk); err != nil {
						return err
					}
					if err := queue.Put(task.key(), val); err != nil {
						return err
					}
					return idx.Put(task.indexKey(), task.key())
				}
				changed := false
				if task.Staged && !cur.Staged {
					cur.Files = task.Files
					cur.Staged = true
					changed = true
				}
				// Priority promotion, one-way toward more urgent: a live
				// pause re-enqueueing a generation the backfill queued at
				// best-effort must not leave it waiting behind checkpoint
				// traffic. The queue key embeds the priority, so promotion
				// re-keys the row; attempts and NotBefore stay with it.
				if task.Priority < cur.Priority {
					cur.Priority = task.Priority
					changed = true
				}
				if !changed {
					return nil
				}
				upgraded, err := json.Marshal(cur)
				if err != nil {
					return err
				}
				nk := cur.key()
				if !bytes.Equal(nk, qk) {
					if err := queue.Delete(qk); err != nil {
						return err
					}
					moveFrom = append([]byte(nil), qk...)
					moveTo = append([]byte(nil), nk...)
				}
				if err := queue.Put(nk, upgraded); err != nil {
					return err
				}
				return idx.Put(cur.indexKey(), nk)
			}
		}
		if err := queue.Put(task.key(), val); err != nil {
			return err
		}
		return idx.Put(task.indexKey(), task.key())
	})
	if uerr == nil && moveFrom != nil {
		// The promotion re-keyed the row; a live claim moves with it so
		// the holder's resolution still finds its own claim and the scan
		// keeps skipping the row.
		if c, held := j.claims[string(moveFrom)]; held {
			j.claims[string(moveTo)] = c
			delete(j.claims, string(moveFrom))
		}
	}
	return uerr
}

// Next returns the highest-priority runnable task (NotBefore in the past)
// and claims it until Ack or Nack resolves it, or ok=false when the queue
// has nothing runnable and unclaimed. Keys sort by readiness within each
// priority, so the first decodable UNCLAIMED entry of a priority answers
// for the whole priority: claimed entries were ready when claimed and so
// sort with the ready entries at the front of their tier, meaning they
// are skipped individually (ownership is not readiness — the entry behind
// a claimed one may be free), while a deferred entry still proves nothing
// behind it in the tier is ready and the cursor seeks straight to the
// next priority. A corrupt entry must never wedge the queue: it is
// deleted (self-healing) rather than surfaced as a permanent error, and
// the scan continues past it.
func (j *Journal) Next(now time.Time) (Task, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	// Expired claims (a worker wedged past claimTTL) become claimable
	// again here; no separate reaper. The token check in Ack/Nack fences
	// the original holder if it ever resumes after the steal.
	for k, c := range j.claims {
		if !c.until.After(now) {
			delete(j.claims, k)
		}
	}
	var task Task
	var claimKey string
	var corrupt [][]byte
	found := false
	err := j.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(journalBucket).Cursor()
		for k, v := c.First(); k != nil; {
			var t Task
			if err := json.Unmarshal(v, &t); err != nil {
				corrupt = append(corrupt, append([]byte(nil), k...))
				k, v = c.Next()
				continue
			}
			if _, claimed := j.claims[string(k)]; claimed {
				k, v = c.Next()
				continue
			}
			if !t.NotBefore.After(now) {
				task = t
				// The stored key and task.key() agree by invariant (every
				// write path stores a row under exactly its task's key);
				// claim under the stored key so the scan's own view is
				// what the claim indexes.
				claimKey = string(k)
				found = true
				break
			}
			// Earliest unclaimed entry of this priority is deferred: skip
			// the whole priority.
			k, v = c.Seek(append([]byte(fmt.Sprintf("%d", t.Priority+1)), '/'))
		}
		return nil
	})
	if err != nil {
		return Task{}, false, err
	}
	if len(corrupt) > 0 {
		err = j.db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket(journalBucket)
			idx := tx.Bucket(indexBucket)
			for _, k := range corrupt {
				// The key embeds priority/readyAt/sandbox/generation;
				// the dangling index entry would otherwise pin staged
				// files (HasPending true) forever.
				if parts := strings.SplitN(string(k), "/", 4); len(parts) == 4 {
					if derr := idx.Delete([]byte(parts[2] + "\x00" + parts[3])); derr != nil {
						return derr
					}
				}
				if derr := b.Delete(k); derr != nil {
					return derr
				}
			}
			return nil
		})
		if err != nil {
			return Task{}, false, fmt.Errorf("drop corrupt journal entries: %w", err)
		}
	}
	if found {
		j.claimSeq++
		j.claims[claimKey] = claim{until: now.Add(claimTTL), token: j.claimSeq}
		task.ClaimToken = j.claimSeq
	}
	return task, found, nil
}

// errClaimStolen reports a resolution refused because the caller's lease
// expired and another worker claimed the task; the thief's eventual Ack
// or Nack is authoritative, and the stale caller's completed work is
// safe to discard unresolved (objects are content-addressed and
// create-only, and any verification it recorded is already durable).
var errClaimStolen = fmt.Errorf("backup task claim expired and was reclaimed by another worker")

// currentKey resolves the task's live queue key through the dedupe
// index: a concurrent enqueue can promote and re-key the row while an
// attempt is in flight, so the caller's snapshot must never be trusted
// to name the stored row. Falls back to the snapshot's own key when the
// index has no entry.
func currentKey(tx *bolt.Tx, task *Task) []byte {
	if qk := tx.Bucket(indexBucket).Get(task.indexKey()); qk != nil {
		return append([]byte(nil), qk...)
	}
	return task.key()
}

// resolveOwned locates task's live row inside tx and verifies the caller
// still owns it, returning the row's current key and stored value.
// Callers hold mu. Ownership is three checks, each covering a window the
// others cannot:
//
//   - a live claim on the current key must carry the caller's token —
//     catches a steal while the thief is still working;
//   - the row must exist at its current key — catches a thief's Ack,
//     which deletes row and index (currentKey then falls back to a
//     snapshot key with no row under it);
//   - the stored Attempts must equal the snapshot's — catches a thief's
//     Nack after its claim was dropped: the reschedule incremented
//     Attempts, durable evidence no live claim can carry. Promotion
//     re-keys but never touches Attempts, so a legitimate holder whose
//     row was promoted mid-flight still passes.
func (j *Journal) resolveOwned(tx *bolt.Tx, task *Task) ([]byte, []byte, error) {
	qk := currentKey(tx, task)
	existing := tx.Bucket(journalBucket).Get(qk)
	if existing == nil {
		return nil, nil, errClaimStolen
	}
	if c, held := j.claims[string(qk)]; held && c.token != task.ClaimToken {
		return nil, nil, errClaimStolen
	}
	var cur Task
	if err := json.Unmarshal(existing, &cur); err == nil && cur.Attempts != task.Attempts {
		return nil, nil, errClaimStolen
	}
	return qk, existing, nil
}

// Release frees task's claim without resolving it, for the one drain
// outcome that is neither an Ack nor a Nack: an abandoned mutable-path
// attempt whose row a concurrent dedupe upgraded to staged snapshots.
// The row is deliberately left queued for the next drain, and without
// this release it would sit invisibly claimed until the TTL expired.
// Token-checked like every resolution (a stale caller must not free a
// claim a thief now holds), and resolved through the index: a promotion
// may have moved the row, and the claim moved with it.
func (j *Journal) Release(task Task) {
	j.mu.Lock()
	defer j.mu.Unlock()
	qk := task.key()
	_ = j.db.View(func(tx *bolt.Tx) error {
		qk = currentKey(tx, &task)
		return nil
	})
	key := string(qk)
	if c, held := j.claims[key]; held && c.token == task.ClaimToken {
		delete(j.claims, key)
	}
}

// RecordVerification persists BOTH verification records in one
// transaction: the task's own progress (survives nacks) and the durable
// history (survives acks). Atomicity is the point: a crash between two
// separate writes would leave a task that trusts its dedupe while the
// history never learns of the object, silently degrading later unchanged
// re-pauses to abandonment.
// Fenced like every row write, but WITHOUT dropping the claim — this is
// mid-flight progress, not resolution. An unfenced write here would
// recreate the row a replacement worker already resolved, forging
// exactly the durable row-presence evidence Ack and Nack fence on.
// The fence rejects only the ROW half: the history entry records that
// these exact object bytes were stream-verified, which is object-level
// truth independent of who owns the row now — and it must survive the
// steal, because the replacement's own upload of a non-shared object
// this caller already finalized dedupes against it and, per the strict
// no-history rule, would otherwise abandon a generation whose bytes are
// provably good. History-without-row-progress is the safe direction of
// the usual atomicity concern (the caller adopts in-memory trust only
// on full success), so the stolen path still returns errClaimStolen
// after recording it.
func (j *Journal) RecordVerification(task Task, object string, now time.Time) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	var qk, nk []byte
	err := j.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(journalBucket)
		existing, rerr := []byte(nil), error(nil)
		qk, existing, rerr = j.resolveOwned(tx, &task)
		if rerr != nil {
			return rerr
		}
		mergeRow(existing, &task)
		val, err := json.Marshal(task)
		if err != nil {
			return err
		}
		// mergeRow may have adopted a promoted priority, moving the
		// row's key; write exactly one row and keep the index on it.
		nk = task.key()
		if !bytes.Equal(qk, nk) {
			if err := b.Delete(qk); err != nil {
				return err
			}
		}
		if err := b.Put(nk, val); err != nil {
			return err
		}
		if err := tx.Bucket(indexBucket).Put(task.indexKey(), nk); err != nil {
			return err
		}
		return tx.Bucket(verifiedBucket).Put([]byte(object), []byte(fmt.Sprintf("%d", now.UnixNano())))
	})
	if err == nil && nk != nil && !bytes.Equal(qk, nk) {
		// This write re-keyed the row; the caller's live claim moves
		// with it, or the scan would hand the row out to a second worker
		// mid-upload.
		if c, held := j.claims[string(qk)]; held {
			j.claims[string(nk)] = c
			delete(j.claims, string(qk))
		}
	}
	if errors.Is(err, errClaimStolen) {
		if herr := j.db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(verifiedBucket).Put([]byte(object), []byte(fmt.Sprintf("%d", now.UnixNano())))
		}); herr != nil {
			return herr
		}
	}
	return err
}

// PendingBaseSHAs returns the content hashes of every base image some
// queued task still depends on, for staged-base garbage collection.
func (j *Journal) PendingBaseSHAs() (map[string]bool, error) {
	out := map[string]bool{}
	err := j.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(journalBucket).ForEach(func(_, v []byte) error {
			var t Task
			if json.Unmarshal(v, &t) == nil {
				for _, f := range t.Files {
					if f.BaseSHA256 != "" {
						out[f.BaseSHA256] = true
					}
				}
			}
			return nil
		})
	})
	return out, err
}

// Load returns the current stored row for a task's identity, if any:
// the abandonment path re-reads it so a concurrent staged upgrade is
// retried from its snapshots instead of being acked away.
func (j *Journal) Load(task Task) (Task, bool, error) {
	var cur Task
	found := false
	err := j.db.View(func(tx *bolt.Tx) error {
		qk := tx.Bucket(indexBucket).Get(task.indexKey())
		if qk == nil {
			return nil
		}
		v := tx.Bucket(journalBucket).Get(qk)
		if v == nil {
			return nil
		}
		if json.Unmarshal(v, &cur) == nil {
			found = true
		}
		return nil
	})
	return cur, found, err
}

// HasPending reports whether a task for this generation is still queued.
func (j *Journal) HasPending(sandboxID, generation string) (bool, error) {
	var ok bool
	err := j.db.View(func(tx *bolt.Tx) error {
		t := Task{SandboxID: sandboxID, Generation: generation}
		ok = tx.Bucket(indexBucket).Get(t.indexKey()) != nil
		return nil
	})
	return ok, err
}

// WasCompleted reports whether this task's owner+generation was ever
// acked as completed (its generation fully verified in the bucket). Only
// the task's identity fields (owner and Generation) are consulted.
// completionKey scopes a completion record to the destination bucket:
// a completed generation in one bucket says nothing about another, and
// an unscoped record would suppress re-upload after BACKUP_BUCKET
// changes.
func completionKey(scope string, task Task) []byte {
	return append([]byte(scope+"\x00"), task.indexKey()...)
}

func (j *Journal) WasCompleted(scope string, task Task) (bool, error) {
	var ok bool
	err := j.db.View(func(tx *bolt.Tx) error {
		ok = tx.Bucket(completionsBucket).Get(completionKey(scope, task)) != nil
		return nil
	})
	return ok, err
}

// Covered reports whether this task's owner+generation needs no new
// enqueue against the given bucket: it is either still pending in the
// queue or already recorded as completed there. The recovery sweeps'
// gate.
func (j *Journal) Covered(scope string, task Task) (bool, error) {
	var ok bool
	err := j.db.View(func(tx *bolt.Tx) error {
		ok = tx.Bucket(indexBucket).Get(task.indexKey()) != nil ||
			tx.Bucket(completionsBucket).Get(completionKey(scope, task)) != nil
		return nil
	})
	return ok, err
}

// WasVerified reports whether any task ever digest-verified this object
// within the retention window.
func (j *Journal) WasVerified(object string, now time.Time) (bool, error) {
	var ok bool
	err := j.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(verifiedBucket).Get([]byte(object))
		if v == nil {
			return nil
		}
		var ns int64
		if _, err := fmt.Sscanf(string(v), "%d", &ns); err != nil {
			return nil // unparsable entry counts as absent
		}
		ok = now.Sub(time.Unix(0, ns)) <= verifiedRetention
		return nil
	})
	return ok, err
}

// Ack removes a finished task, reporting whether the row was actually
// cleared. Called only after every object of the generation is verified
// in the bucket (or the task was abandoned). completed records the
// owner+generation in the durable completions bucket within the SAME
// transaction: the ack deletes the queue row, so this record is the only
// survivor telling recovery sweeps the generation is already in the
// bucket. notify additionally records the task in the notification
// outbox, likewise transactionally: the ack that makes the task's
// completion otherwise unrecoverable is the last durable moment to
// remember that a completion signal is still owed.
//
// An ABANDONMENT (empty scope) whose stored row was upgraded since the
// attempt began (staged, or promoted to a more urgent tier by a live
// pause) clears nothing and returns false: the failure verdict belongs
// to the stale snapshot, and deleting the upgraded row would destroy a
// live pause's coverage and let removeStagedTask reap its staged files.
// The upgraded row retries on its own schedule. A completion ack always
// clears: the generation is durable regardless of what upgraded.
// Piggybacks a bounded lazy prune of expired verification history.
func (j *Journal) Ack(task Task, completedScope string, notify bool) (bool, error) {
	completed := completedScope != ""
	now := time.Now()
	j.mu.Lock()
	defer j.mu.Unlock()
	cleared := true
	var qk []byte
	err := j.db.Update(func(tx *bolt.Tx) error {
		// Resolution is ownership-checked (see resolveOwned) and resolved
		// through the index: a promotion re-keyed row must be deleted
		// where it lives, or the ack would drop only the index and leave
		// the row orphaned for Next to run again.
		var existing []byte
		var rerr error
		qk, existing, rerr = j.resolveOwned(tx, &task)
		if rerr != nil {
			return rerr
		}
		if !completed {
			var cur Task
			if json.Unmarshal(existing, &cur) == nil &&
				((cur.Staged && !task.Staged) || cur.Priority < task.Priority) {
				cleared = false
				return nil
			}
		}
		if err := tx.Bucket(journalBucket).Delete(qk); err != nil {
			return err
		}
		if err := tx.Bucket(indexBucket).Delete(task.indexKey()); err != nil {
			return err
		}
		if completed {
			if err := tx.Bucket(completionsBucket).Put(completionKey(completedScope, task), []byte(fmt.Sprintf("%d", now.UnixNano()))); err != nil {
				return err
			}
		}
		if notify {
			// The outbox copy pins the verified bucket and instant:
			// delivery may run under a future process configured against a
			// different store, and in an order that has nothing to do with
			// when each generation verified.
			nt := task
			nt.VerifiedBucket = completedScope
			nt.VerifiedAt = now.UTC()
			// An undelivered entry that carries object paths must not be
			// demoted by a pathless re-completion (an unchanged re-pause
			// whose manifest create deduped reports no paths, since the
			// published manifest is the path authority): mirror the seed's
			// refresh-in-place and keep the richer manifest under the new
			// instant, matching the control plane's own no-demotion rule.
			if existing := tx.Bucket(outboxBucket).Get(completionKey(completedScope, task)); existing != nil {
				var cur Task
				if json.Unmarshal(existing, &cur) == nil &&
					filesCarryObjects(cur.Files) && !filesCarryObjects(nt.Files) {
					nt.Files = cur.Files
					nt.FilesFinal = cur.FilesFinal
				}
			}
			val, err := json.Marshal(nt)
			if err != nil {
				return err
			}
			// Keyed by bucket + owner + generation: coverage is
			// bucket-scoped, so the same generation can legitimately
			// complete once per bucket after a repoint, and an unscoped
			// key would let the second ack overwrite the first bucket's
			// undelivered signal.
			if err := tx.Bucket(outboxBucket).Put(completionKey(completedScope, task), val); err != nil {
				return err
			}
			// Banked, recorded as THIS acknowledgment's value: the seed
			// re-seeds only if a later ack (a rollback interval's
			// re-pause) overwrites the completion instant.
			if err := tx.Bucket(seededBucket).Put(completionKey(completedScope, task), []byte(fmt.Sprintf("%d", now.UnixNano()))); err != nil {
				return err
			}
		}
		// Bounded incremental prune: examine at most pruneExamineLimit
		// entries per ack, resuming from a persisted cursor position and
		// wrapping, so every ack does O(1) work while the whole history
		// still gets swept over successive acks.
		vb := tx.Bucket(verifiedBucket)
		c := vb.Cursor()
		start := vb.Get(pruneCursorKey)
		var k, v []byte
		if start != nil {
			k, v = c.Seek(start)
		} else {
			k, v = c.First()
		}
		// seen counts every visited key (cursor sentinel included) so the
		// loop terminates even when only the sentinel remains.
		for seen := 0; seen < pruneExamineLimit; seen++ {
			if k == nil {
				k, v = c.First()
				if k == nil {
					break
				}
			}
			if string(k) != string(pruneCursorKey) {
				var ns int64
				if _, err := fmt.Sscanf(string(v), "%d", &ns); err != nil || now.Sub(time.Unix(0, ns)) > verifiedRetention {
					if err := c.Delete(); err != nil {
						return err
					}
				}
			}
			k, v = c.Next()
		}
		var next []byte
		if k != nil {
			next = append([]byte(nil), k...)
		}
		if next == nil {
			return vb.Delete(pruneCursorKey)
		}
		return vb.Put(pruneCursorKey, next)
	})
	// Drop the claim on every outcome except a steal (the claim then
	// belongs to the thief). A retained upgraded row (cleared=false)
	// must be immediately drainable, and a failed transaction leaves the
	// row intact for any worker to retry promptly instead of waiting out
	// the TTL.
	if !errors.Is(err, errClaimStolen) && qk != nil {
		delete(j.claims, string(qk))
	}
	return cleared, err
}

// Nack records a failed attempt and reschedules with exponential backoff
// (capped), keeping the task durable for retry across restarts. The
// stored row is the authority for Files, Staged, and accumulated
// verification: a concurrent dedupe may have upgraded the row's paths
// to staged snapshots while this attempt ran on the pre-upgrade copy,
// and persisting the caller's snapshot verbatim would silently undo the
// upgrade after its marker was already cleared.
func (j *Journal) Nack(task Task, now time.Time) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	var qk []byte
	err := j.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(journalBucket)
		// Ownership-checked against the PRE-reschedule snapshot (the
		// Attempts increment below is this resolution's own edit), and
		// resolved through the index, not the caller's snapshot: a
		// concurrent promotion re-keyed the row, and deleting the stale
		// key while writing a snapshot-keyed retry would fork the task
		// into two rows.
		var existing []byte
		var rerr error
		qk, existing, rerr = j.resolveOwned(tx, &task)
		if rerr != nil {
			return rerr
		}
		task.Attempts++
		backoff := time.Duration(1<<min(task.Attempts, 8)) * time.Second
		const maxBackoff = 10 * time.Minute
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
		task.NotBefore = now.Add(backoff)
		mergeRow(existing, &task)
		val, err := json.Marshal(task)
		if err != nil {
			return err
		}
		if err := b.Delete(qk); err != nil {
			return err
		}
		if err := b.Put(task.key(), val); err != nil {
			return err
		}
		// The deferral re-keyed the row; the dedupe index must follow.
		return tx.Bucket(indexBucket).Put(task.indexKey(), task.key())
	})
	// Drop the claim on every outcome except a steal (the claim then
	// belongs to the thief): the deferred row must not stay invisibly
	// claimed, and a failed transaction leaves the row intact for any
	// worker to retry promptly instead of waiting out the TTL.
	if !errors.Is(err, errClaimStolen) && qk != nil {
		delete(j.claims, string(qk))
	}
	return err
}

// mergeRow folds the stored row's authoritative fields into the
// caller's task snapshot: Files and Staged always come from the row
// when it holds a staged upgrade, and verification history is unioned.
func mergeRow(existing []byte, task *Task) {
	if existing == nil {
		return
	}
	var cur Task
	if json.Unmarshal(existing, &cur) != nil {
		return
	}
	if cur.Staged && !task.Staged {
		task.Files = cur.Files
		task.Staged = true
	}
	// A promotion that landed while this attempt ran must survive the
	// write-back, or the retry would demote the row to the snapshot's
	// stale priority.
	if cur.Priority < task.Priority {
		task.Priority = cur.Priority
	}
	seen := make(map[string]bool, len(task.VerifiedObjects))
	for _, o := range task.VerifiedObjects {
		seen[o] = true
	}
	for _, o := range cur.VerifiedObjects {
		if !seen[o] {
			task.VerifiedObjects = append(task.VerifiedObjects, o)
		}
	}
}

// OldestEnqueuedAtByPriority returns the earliest EnqueuedAt among
// queued tasks per priority tier. Age is measured from enqueue, not
// readiness: a nacked task in backoff is still unmet backlog. Per-tier
// resolution exists because the tiers have opposite service
// expectations: a pause generation should ship in seconds, while a
// best-effort backfill backlog is deliberately patient and must not
// trip the pause tier's freshness alerting.
func (j *Journal) OldestEnqueuedAtByPriority() (map[Priority]time.Time, error) {
	oldest := map[Priority]time.Time{}
	err := j.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(journalBucket).ForEach(func(_, v []byte) error {
			var t Task
			if json.Unmarshal(v, &t) != nil {
				return nil
			}
			if cur, ok := oldest[t.Priority]; !ok || t.EnqueuedAt.Before(cur) {
				oldest[t.Priority] = t.EnqueuedAt
			}
			return nil
		})
	})
	return oldest, err
}

// OutboxDepth reports how many completed tasks still owe their
// completion notification. NUL-prefixed keys are internal markers (the
// per-scope completion-seed guard), not notifications: counting them
// would pin the depth gauge above zero forever and hold the
// outbox-stalled alert permanently firing on every seeded host.
func (j *Journal) OutboxDepth() (int, error) {
	n := 0
	err := j.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(outboxBucket).ForEach(func(k, _ []byte) error {
			if len(k) > 0 && k[0] == 0 {
				return nil
			}
			n++
			return nil
		})
	})
	return n, err
}

// Pending reports queue depth per priority, the uploader's lag gauge.
func (j *Journal) Pending() (map[Priority]int, error) {
	counts := map[Priority]int{}
	err := j.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(journalBucket).ForEach(func(_, v []byte) error {
			var t Task
			if err := json.Unmarshal(v, &t); err != nil {
				return nil // corrupt entries are dropped by Next, not counted
			}
			counts[t.Priority]++
			return nil
		})
	})
	return counts, err
}

// verifiedScopeKey marks the verification history as scoped: its value
// is the bucket the pre-scoping records were claimed for.
var verifiedScopeKey = []byte("\x00verified_scope")

// MigrateVerificationScope claims every unscoped (pre-upgrade)
// verification record for the given bucket, exactly once. Pre-scoping
// binaries only ever verified against the host's single configured
// bucket, and the deploy that introduces scoping changes no buckets, so
// claiming at first boot is sound; afterwards lookups are purely scoped
// and a bucket change misses everything, as it must. Queued tasks'
// VerifiedObjects entries are rewritten in the same transaction.
func (j *Journal) MigrateVerificationScope(scope string) error {
	return j.db.Update(func(tx *bolt.Tx) error {
		vb := tx.Bucket(verifiedBucket)
		if vb.Get(verifiedScopeKey) != nil {
			return nil
		}
		type kv struct{ k, v []byte }
		var moves []kv
		c := vb.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if len(k) > 0 && k[0] != 0 && !strings.Contains(string(k), "\x00") {
				moves = append(moves, kv{append([]byte(nil), k...), append([]byte(nil), v...)})
			}
		}
		for _, m := range moves {
			if err := vb.Put([]byte(scope+"\x00"+string(m.k)), m.v); err != nil {
				return err
			}
			if err := vb.Delete(m.k); err != nil {
				return err
			}
		}
		qb := tx.Bucket(journalBucket)
		qc := qb.Cursor()
		for k, v := qc.First(); k != nil; k, v = qc.Next() {
			var t Task
			if json.Unmarshal(v, &t) != nil || len(t.VerifiedObjects) == 0 {
				continue
			}
			changed := false
			for i, o := range t.VerifiedObjects {
				if !strings.Contains(o, "\x00") {
					t.VerifiedObjects[i] = scope + "\x00" + o
					changed = true
				}
			}
			if changed {
				nv, err := json.Marshal(t)
				if err != nil {
					return err
				}
				if err := qb.Put(append([]byte(nil), k...), nv); err != nil {
					return err
				}
			}
		}
		return vb.Put(verifiedScopeKey, []byte(scope))
	})
}

// PendingNotifications returns up to limit completed tasks whose
// OnVerified signal has not been confirmed delivered (limit <= 0 means
// all). Corrupt entries are skipped (and swept by ClearNotification when
// their key is next written); NUL-prefixed keys are internal markers,
// not notifications.
func (j *Journal) PendingNotifications(limit int) ([]Task, error) {
	var tasks []Task
	err := j.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(outboxBucket).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if len(k) > 0 && k[0] == 0 {
				continue
			}
			var t Task
			if json.Unmarshal(v, &t) == nil {
				tasks = append(tasks, t)
				if limit > 0 && len(tasks) >= limit {
					return nil
				}
			}
		}
		return nil
	})
	return tasks, err
}

// seedChunkLimit bounds completions examined per seed transaction
// (seeded skips included), so no single write transaction on the shared
// DB scales with history size; a full pass paginates across drain
// iterations.
const seedChunkLimit = 256

// SeedOutboxFromCompletions backfills one bounded chunk of the
// notification outbox from the durable completions record, returning
// done=false while more work may remain. Completions acked without
// outbox entries (pre-wiring history, or a rollback window running an
// older uploader) have no other path to control-plane coverage: Covered
// suppresses their re-enqueue and their sandboxes may never pause
// again. Seeded-ness is structural, not clock-based: every banked
// signal (ack-time or seed-time) records the completion key in the
// seeded set within the same transaction, and the seed processes
// exactly the completions absent from that set, so a rollback window's
// acks are caught regardless of clock direction and nothing ever
// re-seeds.
//
// Convergence: done only when a COMPLETE pass from the bucket top finds
// zero unseeded entries. A paginated or resumed pass always restarts
// from the top after finishing, because completions written during an
// interruption (a rollback interval) can sort before the resume cursor;
// the restarted pass is cheap skips and reaches the fixed point on the
// first pass that finds nothing new. The cursor persists pagination
// position and whether the current pass has found work.
// ResetSeedCursor drops any persisted pagination cursor. Called once at
// uploader startup: a cursor surviving a process restart could resume a
// pass whose already-scanned region predates completions an older
// binary wrote during a rollback interval, declaring a clean pass over
// keys it never examined. A fresh process always starts its first pass
// at the top; within a process, in-process acks bank and mark
// themselves, so resumed passes are sound.
func (j *Journal) ResetSeedCursor() error {
	return j.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(outboxBucket).Delete(seedCursorKey)
	})
}

var seedCursorKey = []byte("\x00completions_seed_cursor")

func (j *Journal) SeedOutboxFromCompletions() (bool, error) {
	cursorKey := seedCursorKey
	done := false
	err := j.db.Update(func(tx *bolt.Tx) error {
		ob := tx.Bucket(outboxBucket)
		seeded := tx.Bucket(seededBucket)
		c := tx.Bucket(completionsBucket).Cursor()
		var k, v []byte
		// Both pass properties persist across pagination: whether the
		// pass began at the bucket top (a resumed chunk continues its
		// pass, it does not start a new one) and whether the pass has
		// found unseeded work. In-process acks bank and mark themselves,
		// so entries appearing mid-pass are impossible within a process,
		// and cross-boot additions always get a fresh top pass.
		passFromTop := true
		hadWork := false
		if cur := ob.Get(cursorKey); cur != nil && len(cur) >= 3 {
			passFromTop = cur[0] == '1'
			hadWork = cur[1] == '1'
			// The cursor names the first unprocessed key: resume at it.
			k, v = c.Seek(cur[3:])
		} else {
			k, v = c.First()
		}
		// The scan covers EVERY recorded bucket identity, not just the
		// configured one: pre-reporter completions scoped to an earlier
		// BACKUP_BUCKET still name real objects in that bucket, and each
		// seeded task pins the scope parsed from its own key.
		examined := 0
		for ; k != nil; k, v = c.Next() {
			key := append([]byte(nil), k...)
			if examined >= seedChunkLimit {
				top, work := byte('0'), byte('0')
				if passFromTop {
					top = '1'
				}
				if hadWork {
					work = '1'
				}
				return ob.Put(cursorKey, append([]byte{top, work, 0}, key...))
			}
			examined++
			if sv := seeded.Get(key); sv != nil && string(sv) == string(v) {
				continue
			}
			hadWork = true
			parts := string(key)
			si := strings.IndexByte(parts, 0)
			if si < 0 {
				continue
			}
			scope, rest := parts[:si], parts[si+1:]
			i := strings.LastIndexByte(rest, 0)
			if i < 0 {
				continue
			}
			owner, gen := rest[:i], rest[i+1:]
			t := Task{Generation: gen, VerifiedBucket: scope}
			var ns int64
			if _, err := fmt.Sscanf(string(v), "%d", &ns); err == nil {
				t.VerifiedAt = time.Unix(0, ns).UTC()
			}
			if sep := strings.IndexByte(owner, 0); sep >= 0 {
				t.TemplateID, t.BuildID = owner[:sep], owner[sep+1:]
			} else {
				t.SandboxID = owner
			}
			if existing := ob.Get(key); existing != nil {
				// An undelivered entry survives a rollback re-ack with
				// its stale instant; refresh the instant in place while
				// preserving any file manifest the entry carries, which
				// a coverage-only seed could not reconstruct.
				var cur Task
				if json.Unmarshal(existing, &cur) == nil {
					cur.VerifiedAt = t.VerifiedAt
					t = cur
				}
			}
			val, err := json.Marshal(t)
			if err != nil {
				return err
			}
			if err := ob.Put(key, val); err != nil {
				return err
			}
			if err := seeded.Put(key, append([]byte(nil), v...)); err != nil {
				return err
			}
		}
		// End of bucket: the fixed point is a complete pass from the top
		// that found nothing unseeded. A pass that found work restarts
		// from the top on the next call (cursor deleted), which is cheap
		// skips, and reaches the fixed point one pass later.
		done = passFromTop && !hadWork
		return ob.Delete(cursorKey)
	})
	if err != nil {
		return false, err
	}
	return done, nil
}

// ClearNotification confirms delivery of a task's completion signal.
func (j *Journal) ClearNotification(task Task) error {
	return j.db.Update(func(tx *bolt.Tx) error {
		// Each entry is deleted under exactly the key shape it was
		// written with: entries from before the key carried the bucket
		// have no pinned VerifiedBucket and live under the unscoped key,
		// everything since lives under the scoped one. Deleting only the
		// cleared entry's own shape means a still-undelivered legacy
		// entry survives a scoped clear for the same owner/generation.
		b := tx.Bucket(outboxBucket)
		if task.VerifiedBucket == "" {
			return b.Delete(task.indexKey())
		}
		return b.Delete(completionKey(task.VerifiedBucket, task))
	})
}
