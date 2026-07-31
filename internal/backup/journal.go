package backup

import (
	"encoding/json"
	"fmt"
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

// NewJournal opens (creating if needed) the journal bucket in db. The
// caller owns the bolt DB; sharing vmd's state DB keeps one fsync domain.
func NewJournal(db *bolt.DB) (*Journal, error) {
	err := db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{journalBucket, indexBucket, verifiedBucket} {
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

// key orders the queue: priority, then enqueue time, then generation for
// uniqueness. Bolt iterates keys in byte order, so Next is a prefix scan.
func (t *Task) key() []byte {
	return []byte(fmt.Sprintf("%d/%020d/%s", t.Priority, t.EnqueuedAt.UnixNano(), t.Generation))
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
		if qk := idx.Get(task.indexKey()); qk != nil && queue.Get(qk) != nil {
			return nil
		}
		if err := queue.Put(task.key(), val); err != nil {
			return err
		}
		return idx.Put(task.indexKey(), task.key())
	})
}

// Next returns the highest-priority runnable task (NotBefore in the past),
// or ok=false when the queue has nothing runnable. A corrupt entry must
// never wedge the queue: it is deleted (self-healing) rather than surfaced
// as a permanent error, and the scan continues past it.
func (j *Journal) Next(now time.Time) (Task, bool, error) {
	var task Task
	var corrupt [][]byte
	found := false
	err := j.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(journalBucket).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var t Task
			if err := json.Unmarshal(v, &t); err != nil {
				corrupt = append(corrupt, append([]byte(nil), k...))
				continue
			}
			if t.NotBefore.After(now) {
				continue
			}
			task = t
			found = true
			// Stop here: decoding the rest of a large outage backlog per
			// drain would make draining quadratic. Corrupt entries sorted
			// after this point are dropped by later calls as the queue
			// empties toward them.
			break
		}
		return nil
	})
	if err != nil {
		return Task{}, false, err
	}
	if len(corrupt) > 0 {
		err = j.db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket(journalBucket)
			for _, k := range corrupt {
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

// Update rewrites a pending task in place (same key: identity fields are
// immutable). Used to persist per-object verification progress so a retry
// after a crash knows which deduped objects it may trust.
func (j *Journal) Update(task Task) error {
	val, err := json.Marshal(task)
	if err != nil {
		return err
	}
	return j.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(journalBucket).Put(task.key(), val)
	})
}

// MarkVerified durably records that an object's streamed bytes were
// digest-verified, surviving task completion.
func (j *Journal) MarkVerified(object string, now time.Time) error {
	return j.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(verifiedBucket).Put([]byte(object), []byte(fmt.Sprintf("%d", now.UnixNano())))
	})
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

// Ack removes a completed task. Called only after every object of the
// generation is verified in the bucket. Piggybacks a bounded lazy prune
// of expired verification history.
func (j *Journal) Ack(task Task) error {
	now := time.Now()
	return j.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(journalBucket).Delete(task.key()); err != nil {
			return err
		}
		if err := tx.Bucket(indexBucket).Delete(task.indexKey()); err != nil {
			return err
		}
		vb := tx.Bucket(verifiedBucket)
		c := vb.Cursor()
		pruned := 0
		for k, v := c.First(); k != nil && pruned < 128; k, v = c.Next() {
			var ns int64
			if _, err := fmt.Sscanf(string(v), "%d", &ns); err != nil || now.Sub(time.Unix(0, ns)) > verifiedRetention {
				if err := c.Delete(); err != nil {
					return err
				}
				pruned++
			}
		}
		return nil
	})
}

// Nack records a failed attempt and reschedules with exponential backoff
// (capped), keeping the task durable for retry across restarts.
func (j *Journal) Nack(task Task, now time.Time) error {
	old := task.key()
	task.Attempts++
	backoff := time.Duration(1<<min(task.Attempts, 8)) * time.Second
	const maxBackoff = 10 * time.Minute
	if backoff > maxBackoff {
		backoff = maxBackoff
	}
	task.NotBefore = now.Add(backoff)
	val, err := json.Marshal(task)
	if err != nil {
		return err
	}
	return j.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(journalBucket)
		if err := b.Delete(old); err != nil {
			return err
		}
		return b.Put(task.key(), val)
	})
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
