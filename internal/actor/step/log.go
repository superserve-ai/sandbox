// Package step implements the $ACTOR_STEP durable-step protocol (Epic 5.9) — the
// fiber primitive that lets a harness mark resumable work so an Actor resumes
// from the exact interrupted step after a crash, instead of redoing everything.
//
// The model (SPEC §7): a harness wraps work in step("name", fn). The first time,
// fn runs and its result is appended to a durable journal on /state. On replay
// (after a crash/restart), the recorded result is recalled and fn is skipped —
// so external effects already done are not repeated and the harness fast-forwards
// to where it stopped. This is the one durability mechanism no harness can bring
// itself, because it must be memoized to the platform's durable /state and
// survive the process dying mid-step.
//
// The Log here is the storage; server.go serves it over a unix socket (the
// $ACTOR_STEP address) so harnesses in any language can use it; client.go is the
// Go side with a Step(name, fn) helper.
package step

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// record is one journaled step. Value is the raw JSON the harness recorded.
type record struct {
	Seq   int             `json:"seq"`
	Step  string          `json:"step"`
	Value json.RawMessage `json:"value"`
}

// Log is an append-only, crash-safe memoization journal keyed by step name.
// It lives under a directory on the durable /state filesystem; reopening the
// same directory replays the journal so prior steps are recalled, not re-run.
//
// Keying: the FIRST recorded value for a name wins on replay — a step name
// identifies a unit of work, and re-recording the same name after replay is a
// no-op (idempotent), which is exactly the "skip already-done work" semantic.
type Log struct {
	mu    sync.Mutex
	path  string
	f     *os.File
	index map[string]json.RawMessage
	order []string // record order, for deterministic listing
	seq   int
}

// JournalName is the on-disk journal file within the step directory.
const JournalName = "steps.journal"

// OpenLog opens (creating if needed) the durable step journal under dir and
// replays any existing records into memory. dir is typically a path under the
// Actor's /state mount, e.g. /state/.actor/steps/<run-id>.
func OpenLog(dir string) (*Log, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("step: mkdir %s: %w", dir, err)
	}
	path := filepath.Join(dir, JournalName)
	l := &Log{path: path, index: map[string]json.RawMessage{}}
	if err := l.replay(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("step: open journal: %w", err)
	}
	l.f = f
	return l, nil
}

// replay reads the existing journal (if any) into the in-memory index. A
// truncated trailing line (from a crash mid-append) is tolerated and ignored —
// only fully-written records are recalled.
func (l *Log) replay() error {
	f, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("step: open for replay: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		var r record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			// Partial/corrupt trailing line from a crash — stop replaying here.
			break
		}
		if _, seen := l.index[r.Step]; !seen {
			l.index[r.Step] = r.Value
			l.order = append(l.order, r.Step)
		}
		if r.Seq > l.seq {
			l.seq = r.Seq
		}
	}
	return nil
}

// Recall returns the memoized value for step name and whether it was found.
func (l *Log) Recall(name string) (json.RawMessage, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	v, ok := l.index[name]
	return v, ok
}

// Record memoizes value under name durably (append + fsync). If name is already
// recorded it is a no-op and returns the existing value — idempotent, so a
// replayed harness that re-records a completed step doesn't double-write or
// diverge.
func (l *Log) Record(name string, value json.RawMessage) (json.RawMessage, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if existing, ok := l.index[name]; ok {
		return existing, nil
	}
	l.seq++
	if len(value) == 0 {
		value = json.RawMessage("null")
	}
	line, err := json.Marshal(record{Seq: l.seq, Step: name, Value: value})
	if err != nil {
		return nil, fmt.Errorf("step: marshal record: %w", err)
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return nil, fmt.Errorf("step: append: %w", err)
	}
	// Durable-on-fsync: the whole point is surviving a crash, so flush before
	// telling the harness the step is committed.
	if err := l.f.Sync(); err != nil {
		return nil, fmt.Errorf("step: fsync: %w", err)
	}
	l.index[name] = value
	l.order = append(l.order, name)
	return value, nil
}

// Steps returns the recorded step names in record order (for inspection/tests).
func (l *Log) Steps() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.order))
	copy(out, l.order)
	return out
}

// Close closes the underlying journal file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}
