package telemetry

import (
	"testing"
	"time"
)

func TestSafeResultBoundsValues(t *testing.T) {
	for _, result := range []string{ResultSuccess, ResultError, ResultConflict, ResultTimeout} {
		if got := safeResult(result); got != result {
			t.Fatalf("safeResult(%q) = %q", result, got)
		}
	}
	if got := safeResult("raw error: secret token leaked"); got != ResultError {
		t.Fatalf("unexpected fallback result: %q", got)
	}
}

func TestSafeOperationBoundsValues(t *testing.T) {
	for _, op := range []string{"create", "pause", "resume", "delete", "fail", "timeout_pause"} {
		if got := safeOperation(op); got != op {
			t.Fatalf("safeOperation(%q) = %q", op, got)
		}
	}
	if got := safeOperation("sandbox_id=abc"); got != "unknown" {
		t.Fatalf("unexpected fallback operation: %q", got)
	}
}

func TestSafeMethodBoundsValues(t *testing.T) {
	for _, method := range []string{"CreateVM", "PauseVM", "ResumeVM", "DeleteVM", "BuildTemplate", "GetBuildStatus", "CancelBuild"} {
		if got := safeMethod(method); got != method {
			t.Fatalf("safeMethod(%q) = %q", method, got)
		}
	}
	if got := safeMethod("https://raw-url.example/vm/123"); got != "unknown" {
		t.Fatalf("unexpected fallback method: %q", got)
	}
	if got := safeMethod("RestoreSnapshot"); got != "CreateVM" {
		t.Fatalf("safeMethod(%q) = %q", "RestoreSnapshot", got)
	}
}

func TestDeltasNeverNegative(t *testing.T) {
	if got := nonNegativeDelta(10, 7); got != 3 {
		t.Fatalf("delta = %d", got)
	}
	if got := nonNegativeDelta(1, 7); got != 0 {
		t.Fatalf("reset delta = %d", got)
	}
	if got := nonNegativeDurationDelta(10*time.Second, 7*time.Second); got != 3*time.Second {
		t.Fatalf("duration delta = %s", got)
	}
	if got := nonNegativeDurationDelta(time.Second, 7*time.Second); got != 0 {
		t.Fatalf("reset duration delta = %s", got)
	}
}

func TestDBPoolDeltasSeedFromFirstSample(t *testing.T) {
	acquire, emptyAcquire, canceledAcquire, acquireDuration := dbPoolDeltas(
		false,
		10, 0,
		4, 0,
		2, 0,
		15*time.Second, 0,
	)
	if acquire != 0 || emptyAcquire != 0 || canceledAcquire != 0 || acquireDuration != 0 {
		t.Fatalf("first sample deltas = (%d, %d, %d, %s), want all zero", acquire, emptyAcquire, canceledAcquire, acquireDuration)
	}

	acquire, emptyAcquire, canceledAcquire, acquireDuration = dbPoolDeltas(
		true,
		15, 10,
		6, 4,
		3, 2,
		21*time.Second, 15*time.Second,
	)
	if acquire != 5 || emptyAcquire != 2 || canceledAcquire != 1 || acquireDuration != 6*time.Second {
		t.Fatalf("seeded sample deltas = (%d, %d, %d, %s)", acquire, emptyAcquire, canceledAcquire, acquireDuration)
	}
}

func TestHostCapacityQueryTimeoutIndependentOfInterval(t *testing.T) {
	for _, interval := range []time.Duration{500 * time.Millisecond, 2 * time.Second, 15 * time.Second} {
		if got := hostCapacityQueryTimeoutForInterval(interval); got != hostCapacityQueryTimeout {
			t.Fatalf("timeout(%s) = %s, want %s", interval, got, hostCapacityQueryTimeout)
		}
	}
}
