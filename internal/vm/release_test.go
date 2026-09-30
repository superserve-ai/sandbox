package vm

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// A thaw that timed out is asked again: the guest may still be catching up
// on a resume Firecracker answered late. A refusal is final at once.
func TestReleaseOfAFrozenGuestRetriesOnlyAThawThatTimedOut(t *testing.T) {
	origUnpause, origThaw, origBudget := fcUnpauseVM, boxdThawGuest, releaseThawBudget
	t.Cleanup(func() { fcUnpauseVM, boxdThawGuest, releaseThawBudget = origUnpause, origThaw, origBudget })
	releaseThawBudget = 2 * time.Second
	fcUnpauseVM = func(context.Context, string) error { return nil }
	m := &Manager{log: zerolog.Nop()}

	attempts := 0
	boxdThawGuest = func(context.Context, string, string) error {
		attempts++
		if attempts < 3 {
			return context.DeadlineExceeded
		}
		return nil
	}
	if err := m.releaseFrozenGuest(context.Background(), "/run/vm.sock", "10.0.0.2", "tok"); err != nil || attempts != 3 {
		t.Fatalf("err=%v attempts=%d; want the third thaw to release", err, attempts)
	}

	attempts = 0
	boxdThawGuest = func(context.Context, string, string) error { attempts++; return errors.New("connection refused") }
	if err := m.releaseFrozenGuest(context.Background(), "/run/vm.sock", "10.0.0.2", "tok"); err == nil || attempts != 1 {
		t.Fatalf("err=%v attempts=%d; a refusal is not retried", err, attempts)
	}
}

// A thaw that never answers gives up within its budget, and the error names
// the unpause that failed before it.
func TestReleaseOfAFrozenGuestGivesUpWithinItsBudget(t *testing.T) {
	origUnpause, origThaw, origBudget := fcUnpauseVM, boxdThawGuest, releaseThawBudget
	t.Cleanup(func() { fcUnpauseVM, boxdThawGuest, releaseThawBudget = origUnpause, origThaw, origBudget })
	releaseThawBudget = 300 * time.Millisecond
	fcUnpauseVM = func(context.Context, string) error { return errors.New("unpause VM: status 500: busy") }
	attempts := 0
	boxdThawGuest = func(context.Context, string, string) error { attempts++; return context.DeadlineExceeded }
	m := &Manager{log: zerolog.Nop()}
	start := time.Now()
	err := m.releaseFrozenGuest(context.Background(), "/run/vm.sock", "10.0.0.2", "tok")
	if err == nil || attempts < 2 || time.Since(start) > 3*time.Second {
		t.Fatalf("err=%v attempts=%d took=%v; want repeated thaws bounded by the budget", err, attempts, time.Since(start))
	}
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("err=%v; want the thaw's timeout and the unpause's failure both named", err)
	}
}
