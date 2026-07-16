package vm

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A job result buffered at deadline-time must win over the wait error — the
// select in stopUnit can wake on either when both are ready.
func TestSettleExpiredStopWait_DrainsBufferedResult(t *testing.T) {
	ch := make(chan string, 1)
	ch <- "done"
	if err := settleExpiredStopWait(context.Background(), "u.service", ch, errors.New("deadline")); err != nil {
		t.Fatalf("buffered done should win over the wait error: %v", err)
	}

	ch2 := make(chan string, 1)
	ch2 <- "failed"
	err := settleExpiredStopWait(context.Background(), "u.service", ch2, errors.New("deadline"))
	if err == nil || !strings.Contains(err.Error(), `job result "failed"`) {
		t.Fatalf("buffered failure should surface the job result, got %v", err)
	}
}

func TestLingeringState(t *testing.T) {
	for _, s := range []string{"active", "activating", "deactivating"} {
		if !lingeringState(s) {
			t.Errorf("%s should linger", s)
		}
	}
	for _, s := range []string{"inactive", "failed", "reloading", ""} {
		if lingeringState(s) {
			t.Errorf("%s should not linger", s)
		}
	}
}
