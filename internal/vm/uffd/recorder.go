package uffd

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
)

// Recorder collects page-fault offsets in observation order for later
// replay by the prefetcher. Safe for concurrent Record calls; capture
// order approximates guest first-touch order under our worker pool.
type Recorder struct {
	mu      sync.Mutex
	seen    map[uint64]struct{}
	ordered []uint64
}

func NewRecorder() *Recorder {
	return &Recorder{seen: make(map[uint64]struct{})}
}

func (r *Recorder) Record(offset uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.seen[offset]; ok {
		return
	}
	r.seen[offset] = struct{}{}
	r.ordered = append(r.ordered, offset)
}

func (r *Recorder) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.ordered)
}

// Flush writes recorded offsets to path, one per line. sortAscending=true
// emits numerical order instead of capture order — use when parallel
// workers make capture order unreliable.
func (r *Recorder) Flush(path string, sortAscending bool) error {
	r.mu.Lock()
	out := make([]uint64, len(r.ordered))
	copy(out, r.ordered)
	r.mu.Unlock()

	if sortAscending {
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	}

	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	w := bufio.NewWriter(f)
	for _, off := range out {
		if _, err := w.WriteString(strconv.FormatUint(off, 10) + "\n"); err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return fmt.Errorf("write: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("flush: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
