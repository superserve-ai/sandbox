// Package mining owns host incident delivery independently of best-effort flow logs.
package mining

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/superserve-ai/sandbox/internal/abuse"
)

var ErrSpoolFull = errors.New("mining incident spool full")

// ErrCleanupPending retains an incident while another effective restriction
// still requires its local gate. This is ordinary reconciliation, not failure.
var ErrCleanupPending = abuse.ErrMiningCleanupPending

// ErrLocalCleanupComplete acknowledges a confirmed retired assignment after
// its gate is cleared. It retires only the host spool; durable quarantine stays.
var ErrLocalCleanupComplete = abuse.ErrMiningLocalCleanupComplete

const maxRecordBytes = 8192

type ReceiptHandler func(context.Context, abuse.MiningIncident, abuse.IncidentReceipt) error

// Only the trusted host store implements this boundary. The capture marker is
// local provenance, not authentication for a remote or tenant-supplied request.
type captureStore interface {
	CaptureObservation(abuse.MiningIncident) (string, error)
	RecordCapturedIncident(context.Context, abuse.MiningIncident, string) (abuse.IncidentReceipt, error)
}

type entry struct {
	Incident abuse.MiningIncident   `json:"incident"`
	Receipt  *abuse.IncidentReceipt `json:"receipt,omitempty"`
	Capture  string                 `json:"capture,omitempty"`
	next     time.Time
	attempts int
}

// Delivery has one bounded serial background worker. Submit durably records a
// host observation before acknowledgement; no lifecycle path calls Submit.
// Applied receipts remain on disk until current-state cleanup is acknowledged.
type Delivery struct {
	mu         sync.Mutex
	dir        string
	limit      int
	store      abuse.MiningIncidentStore
	callback   ReceiptHandler
	pending    map[uuid.UUID]*entry
	wake       chan struct{}
	degraded   bool
	lastReport time.Time
	retries    uint64
	rejected   uint64
	lastReject time.Time
}

func NewDelivery(dir string, limit int, store abuse.MiningIncidentStore, callback ReceiptHandler) (*Delivery, error) {
	if dir == "" || limit <= 0 || store == nil || callback == nil {
		return nil, errors.New("invalid mining delivery configuration")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	d := &Delivery{dir: dir, limit: limit, store: store, callback: callback, pending: make(map[uuid.UUID]*entry), wake: make(chan struct{}, 1)}
	directory, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	// Bound recovery too. Unexpected/corrupt state is surfaced, never silently lost.
	for {
		files, err := directory.ReadDir(128)
		for _, file := range files {
			if strings.HasPrefix(file.Name(), ".pending-") {
				if err := os.Remove(filepath.Join(dir, file.Name())); err != nil {
					return nil, err
				}
				continue
			}
			if !strings.HasSuffix(file.Name(), ".json") {
				continue
			}
			if len(d.pending) >= limit {
				return nil, ErrSpoolFull
			}
			id, err := uuid.Parse(strings.TrimSuffix(file.Name(), ".json"))
			if err != nil {
				return nil, fmt.Errorf("invalid incident filename")
			}
			f, err := os.Open(filepath.Join(dir, file.Name()))
			if err != nil {
				return nil, err
			}
			b, err := io.ReadAll(io.LimitReader(f, maxRecordBytes+1))
			f.Close()
			if err != nil {
				return nil, err
			}
			if len(b) > maxRecordBytes {
				return nil, errors.New("oversized incident record")
			}
			var e entry
			if err := json.Unmarshal(b, &e); err != nil {
				return nil, fmt.Errorf("corrupt mining incident: %w", err)
			}
			if e.Incident.ID != id {
				return nil, errors.New("incident filename/body mismatch")
			}
			d.pending[id] = &e
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return d, nil
}

func (d *Delivery) Submit(i abuse.MiningIncident) error {
	if i.ID == uuid.Nil {
		return abuse.ErrInvalidIncident
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if previous, ok := d.pending[i.ID]; ok {
		a, _ := json.Marshal(previous.Incident)
		b, _ := json.Marshal(i)
		if string(a) != string(b) {
			return abuse.ErrInvalidIncident
		}
		return nil
	}
	if len(d.pending) >= d.limit {
		d.degrade("spool_full")
		return ErrSpoolFull
	}
	e := &entry{Incident: i}
	if store, ok := d.store.(captureStore); ok {
		capture, err := store.CaptureObservation(i)
		if err != nil {
			return err
		}
		if capture == "" {
			return errors.New("missing mining capture provenance")
		}
		e.Capture = capture
	}
	if err := d.write(e); err != nil {
		// Rename may have succeeded before directory fsync failed. Account for
		// that file so repeated storage failures cannot exceed the spool bound.
		if _, statErr := os.Stat(filepath.Join(d.dir, i.ID.String()+".json")); statErr == nil {
			d.pending[i.ID] = e
			select {
			case d.wake <- struct{}{}:
			default:
			}
		}
		d.degrade("spool_write_failed")
		return err
	}
	d.pending[i.ID] = e
	select {
	case d.wake <- struct{}{}:
	default:
	}
	return nil
}

func (d *Delivery) write(e *entry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if len(b) > maxRecordBytes {
		return errors.New("incident too large")
	}
	f, err := os.CreateTemp(d.dir, ".pending-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, filepath.Join(d.dir, e.Incident.ID.String()+".json")); err != nil {
		return err
	}
	return syncDirectory(d.dir)
}
func syncDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (d *Delivery) degrade(reason string) {
	if d.lastReport.IsZero() || time.Since(d.lastReport) >= time.Minute {
		oldest := time.Duration(0)
		for _, e := range d.pending {
			if age := time.Since(e.Incident.ObservedAt); age > oldest {
				oldest = age
			}
		}
		log.Warn().Str("reason", reason).Int("pending", len(d.pending)).Uint64("retries", d.retries).Dur("oldest_pending", oldest).Msg("mining incident delivery degraded")
		d.lastReport = time.Now()
	}
	d.degraded = true
}

func (d *Delivery) Run(ctx context.Context) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		d.deliver(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-d.wake:
		}
	}
}

func (d *Delivery) deliver(ctx context.Context) {
	d.mu.Lock()
	ids := make([]uuid.UUID, 0, len(d.pending))
	now := time.Now()
	for id, e := range d.pending {
		if !e.next.After(now) {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return d.pending[ids[i]].next.Before(d.pending[ids[j]].next) })
	if len(ids) > 64 {
		ids = ids[:64]
	}
	d.mu.Unlock()
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		d.mu.Lock()
		current, ok := d.pending[id]
		if !ok {
			d.mu.Unlock()
			continue
		}
		e := *current
		d.mu.Unlock()
		callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		var receipt abuse.IncidentReceipt
		var err error
		if e.Receipt == nil {
			if e.Capture == "" {
				receipt, err = d.store.RecordIncident(callCtx, e.Incident)
			} else if store, ok := d.store.(captureStore); ok {
				receipt, err = store.RecordCapturedIncident(callCtx, e.Incident, e.Capture)
			} else {
				err = errors.New("mining store cannot replay captured observations")
			}
		} else {
			receipt, err = d.store.IncidentStatus(callCtx, id)
		}
		// Invalid ownership/body evidence is never retried into a different victim.
		rejected := errors.Is(err, abuse.ErrInvalidIncident)
		if rejected {
			receipt = abuse.IncidentReceipt{IncidentID: id, Disposition: abuse.IncidentIgnored}
			err = nil
		}
		if err == nil {
			if receipt.IncidentID != id || (receipt.Disposition != abuse.IncidentApplied && receipt.Disposition != abuse.IncidentReleased && receipt.Disposition != abuse.IncidentExempt && receipt.Disposition != abuse.IncidentIgnored) {
				err = errors.New("invalid incident receipt")
			} else {
				err = d.callback(callCtx, e.Incident, receipt)
			}
		}
		retired := errors.Is(err, ErrLocalCleanupComplete)
		if retired {
			err = nil
		}
		cancel()
		d.mu.Lock()
		if rejected {
			d.rejected++
			if d.lastReject.IsZero() || time.Since(d.lastReject) >= time.Minute {
				log.Warn().Uint64("rejected", d.rejected).Msg("mining incident rejected: invalid or stale attribution")
				d.lastReject = time.Now()
			}
		}
		if err == nil {
			if receipt.Disposition == abuse.IncidentApplied && !retired {
				if current.Receipt == nil {
					current.Receipt = &receipt
					err = d.write(current)
					if err != nil {
						current.Receipt = nil
					}
				}
				current.next = time.Now().Add(5 * time.Second)
			} else {
				err = os.Remove(filepath.Join(d.dir, id.String()+".json"))
				if errors.Is(err, os.ErrNotExist) {
					err = nil
				}
				if err == nil {
					err = syncDirectory(d.dir)
				}
				if err == nil {
					delete(d.pending, id)
				}
			}
		}
		if errors.Is(err, ErrCleanupPending) {
			current.next = time.Now().Add(5 * time.Second)
			current.attempts = 0
		} else if err != nil {
			d.retries++
			current.attempts++
			shift := current.attempts
			if shift > 6 {
				shift = 6
			}
			current.next = time.Now().Add(time.Duration(1<<shift) * time.Second)
			d.degrade("delivery_or_cleanup_failed")
		} else {
			current.attempts = 0
			healthy := len(d.pending) < d.limit
			for _, remaining := range d.pending {
				if remaining.attempts > 0 {
					healthy = false
					break
				}
			}
			if d.degraded && healthy {
				log.Info().Int("pending", len(d.pending)).Msg("mining incident delivery recovered")
				d.degraded = false
			}
		}
		d.mu.Unlock()
	}
}

func (d *Delivery) Pending() int { d.mu.Lock(); defer d.mu.Unlock(); return len(d.pending) }
