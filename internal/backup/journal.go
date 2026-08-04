package backup

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Priority orders upload work. Lower value uploads first: a pause or an
// on-demand snapshot is user-visible durability; periodic checkpoints and
// (later) memory-tier components are opportunistic and must never delay it.
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
}

// Task is one generation awaiting upload. Tasks are idempotent: the
// generation key is content-addressed, so re-running a task lands on the
// same object names and the bucket's create-only precondition makes
// duplicates a no-op.
type Task struct {
	SandboxID  string     `json:"sandbox_id"`
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

// NewJournal opens (creating if needed) the journal bucket in db. The
// caller owns the bolt DB; sharing vmd's state DB keeps one fsync domain.
func NewJournal(db *bolt.DB) (*Journal, error) {
	err := db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{journalBucket, indexBucket, verifiedBucket, outboxBucket} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("create journal bucket: %w", err)
	}
	return &Journal{db: db}, nil
}

// readyAt is when the task becomes runnable: its enqueue time until a
// Nack defers it. Keys sort by it so Next never scans deferred work.
func (t *Task) readyAt() time.Time {
	if t.NotBefore.After(t.EnqueuedAt) {
		return t.NotBefore
	}
	return t.EnqueuedAt
}

// key orders the queue: priority, then READINESS time, then the owner
// and generation for uniqueness. Readiness rather than enqueue time is
// load-bearing for outage backlogs: deferred tasks sort behind runnable
// ones within their priority, so Next examines at most one entry per
// priority instead of scanning every deferred entry on each drain and
// idle tick. The owner segment is load-bearing too: generations are
// content-addressed, so two untouched sandboxes cloned from one template
// share a generation, and without the owner a same-tick enqueue would
// collide keys and silently drop one sandbox's backup.
func (t *Task) key() []byte {
	return []byte(fmt.Sprintf("%d/%020d/%s/%s", t.Priority, t.readyAt().UnixNano(), t.SandboxID, t.Generation))
}

// indexKey is the pending-generation identity for the dedupe index.
func (t *Task) indexKey() []byte {
	return []byte(t.SandboxID + "\x00" + t.Generation)
}

// Enqueue adds a task. A task for the same generation that is already
// pending is not enqueued again: content addressing makes the duplicate
// upload harmless, but there is no reason to do the work twice (idempotent
// pause retries re-enqueue the identical generation).
func (j *Journal) Enqueue(task Task) error {
	if task.Generation == "" || task.SandboxID == "" {
		return fmt.Errorf("task missing identity: %+v", task)
	}
	if task.EnqueuedAt.IsZero() {
		task.EnqueuedAt = time.Now().UTC()
	}
	val, err := json.Marshal(task)
	if err != nil {
		return err
	}
	return j.db.Update(func(tx *bolt.Tx) error {
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
					// task as a silent dedupe: replace it.
					if err := queue.Put(qk, val); err != nil {
						return err
					}
					return idx.Put(task.indexKey(), qk)
				}
				if task.Staged && !cur.Staged {
					cur.Files = task.Files
					cur.Staged = true
					upgraded, err := json.Marshal(cur)
					if err != nil {
						return err
					}
					return queue.Put(qk, upgraded)
				}
				return nil
			}
		}
		if err := queue.Put(task.key(), val); err != nil {
			return err
		}
		return idx.Put(task.indexKey(), task.key())
	})
}

// Next returns the highest-priority runnable task (NotBefore in the past),
// or ok=false when the queue has nothing runnable. Keys sort by
// readiness within each priority, so the first decodable entry of a
// priority answers for the whole priority: not ready means nothing
// behind it is ready either, and the cursor seeks straight to the next
// priority. A corrupt entry must never wedge the queue: it is deleted
// (self-healing) rather than surfaced as a permanent error, and the scan
// continues past it.
func (j *Journal) Next(now time.Time) (Task, bool, error) {
	var task Task
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
			if !t.NotBefore.After(now) {
				task = t
				found = true
				break
			}
			// Earliest entry of this priority is deferred: skip the
			// whole priority.
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
	return task, found, nil
}

// RecordVerification persists BOTH verification records in one
// transaction: the task's own progress (survives nacks) and the durable
// history (survives acks). Atomicity is the point: a crash between two
// separate writes would leave a task that trusts its dedupe while the
// history never learns of the object, silently degrading later unchanged
// re-pauses to abandonment.
func (j *Journal) RecordVerification(task Task, object string, now time.Time) error {
	return j.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(journalBucket)
		mergeRow(b.Get(task.key()), &task)
		val, err := json.Marshal(task)
		if err != nil {
			return err
		}
		if err := b.Put(task.key(), val); err != nil {
			return err
		}
		return tx.Bucket(verifiedBucket).Put([]byte(object), []byte(fmt.Sprintf("%d", now.UnixNano())))
	})
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

// Ack removes a finished task. Called only after every object of the
// generation is verified in the bucket (or the task was abandoned).
// notify additionally records the task in the notification outbox within
// the SAME transaction: the ack that makes the task's completion
// otherwise unrecoverable is the last durable moment to remember that a
// completion signal is still owed. Piggybacks a bounded lazy prune of
// expired verification history.
func (j *Journal) Ack(task Task, notify bool) error {
	now := time.Now()
	return j.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(journalBucket).Delete(task.key()); err != nil {
			return err
		}
		if err := tx.Bucket(indexBucket).Delete(task.indexKey()); err != nil {
			return err
		}
		if notify {
			val, err := json.Marshal(task)
			if err != nil {
				return err
			}
			if err := tx.Bucket(outboxBucket).Put(task.indexKey(), val); err != nil {
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
}

// Nack records a failed attempt and reschedules with exponential backoff
// (capped), keeping the task durable for retry across restarts. The
// stored row is the authority for Files, Staged, and accumulated
// verification: a concurrent dedupe may have upgraded the row's paths
// to staged snapshots while this attempt ran on the pre-upgrade copy,
// and persisting the caller's snapshot verbatim would silently undo the
// upgrade after its marker was already cleared.
func (j *Journal) Nack(task Task, now time.Time) error {
	old := task.key()
	task.Attempts++
	backoff := time.Duration(1<<min(task.Attempts, 8)) * time.Second
	const maxBackoff = 10 * time.Minute
	if backoff > maxBackoff {
		backoff = maxBackoff
	}
	task.NotBefore = now.Add(backoff)
	return j.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(journalBucket)
		mergeRow(b.Get(old), &task)
		val, err := json.Marshal(task)
		if err != nil {
			return err
		}
		if err := b.Delete(old); err != nil {
			return err
		}
		if err := b.Put(task.key(), val); err != nil {
			return err
		}
		// The deferral re-keyed the row; the dedupe index must follow.
		return tx.Bucket(indexBucket).Put(task.indexKey(), task.key())
	})
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

// PendingNotifications returns completed tasks whose OnVerified signal
// has not been confirmed delivered. Corrupt entries are skipped (and
// swept by ClearNotification when their key is next written).
func (j *Journal) PendingNotifications() ([]Task, error) {
	var tasks []Task
	err := j.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(outboxBucket).ForEach(func(k, v []byte) error {
			var t Task
			if json.Unmarshal(v, &t) == nil {
				tasks = append(tasks, t)
			}
			return nil
		})
	})
	return tasks, err
}

// ClearNotification confirms delivery of a task's completion signal.
func (j *Journal) ClearNotification(task Task) error {
	return j.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(outboxBucket).Delete(task.indexKey())
	})
}
