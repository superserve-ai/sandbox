package api

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/telemetry"
)

// A replica that does not hold the sweep lease reports an empty backlog, so a
// former holder's last measurement does not keep being exported.
func TestTrialEligibilitySweepNonHolderRecordsZeroBacklog(t *testing.T) {
	rec := &captureTelemetryRecorder{}
	SetTelemetryRecorder(rec)
	t.Cleanup(func() { SetTelemetryRecorder(nil) })
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row {
			return &mockRow{scanFn: func(...any) error { return pgx.ErrNoRows }}
		},
	}
	h := &Handlers{DB: db.New(mock)}
	h.refreshActiveTrialEligibility(t.Context())
	if len(rec.backlogs) != 1 || rec.backlogs[0] != (telemetry.TrialEligibilityBacklog{}) {
		t.Fatalf("non-holder must record one empty backlog, got %v", rec.backlogs)
	}
}
