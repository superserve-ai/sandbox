package supervisor

import (
	"github.com/superserve-ai/sandbox/internal/db"
	"testing"
	"time"
)

func TestExecutionBudgetDoesNotResetForRetryOrPublication(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	first := now.Add(-30 * time.Minute)
	for _, reason := range []string{"waiting for eligible host/capacity", "waiting for verified durable publication"} {
		e := db.BuildExecution{FirstStartedAt: &first, Reason: reason, Attempts: 2}
		if executionExpired(e, now.Add(-time.Hour), now) == "" {
			t.Fatalf("%s reset deadline", reason)
		}
	}
	if executionExpired(db.BuildExecution{}, now.Add(-2*time.Minute), now) == "" {
		t.Fatal("initial queue deadline not enforced")
	}
	fresh := now.Add(-time.Minute)
	if executionExpired(db.BuildExecution{FirstStartedAt: &fresh}, now.Add(-time.Hour), now) != "" {
		t.Fatal("replacement waiting inherited initial queue deadline")
	}
}
