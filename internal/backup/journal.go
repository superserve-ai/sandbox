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
}

// Journal is the crash-safe upload queue. Enqueue is called in the pause
// path after artifacts are finalized; Ack only after the upload is verified.
// Everything in between survives a vmd restart: on boot the uploader drains
// whatever the journal holds. Ack is also the signal that makes local
// staging deletable, so it must never fire early.
type Journal struct {
	db *bolt.DB
}

var journalBucket = []byte("backup_upload_queue")

// NewJournal opens (creating if needed) the journal bucket in db. The
// caller owns the bolt DB; sharing vmd's state DB keeps one fsync domain.
func NewJournal(db *bolt.DB) (*Journal, error) {
	err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(journalBucket)
		return err
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
		b := tx.Bucket(journalBucket)
		duplicate := false
		_ = b.ForEach(func(_, v []byte) error {
			var t Task
			if json.Unmarshal(v, &t) == nil && t.Generation == task.Generation && t.SandboxID == task.SandboxID {
				duplicate = true
			}
			return nil
		})
		if duplicate {
			return nil
		}
		return b.Put(task.key(), val)
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
			if !found {
				task = t
				found = true
			}
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

// Ack removes a completed task. Called only after every object of the
// generation is verified in the bucket.
func (j *Journal) Ack(task Task) error {
	return j.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(journalBucket).Delete(task.key())
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
