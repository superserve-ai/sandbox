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

// The backlog sample must survive a tick whose page consumed the deadline.
func TestTrialEligibilityBacklogSampledAfterTickDeadline(t *testing.T) {
	rec := &captureTelemetryRecorder{}
	SetTelemetryRecorder(rec)
	t.Cleanup(func() { SetTelemetryRecorder(nil) })
	var queryErr error = context.Canceled
	mock := &mockDBTX{
		queryRowFn: func(ctx context.Context, _ string, _ ...any) pgx.Row {
			queryErr = ctx.Err()
			return &mockRow{scanFn: func(dest ...any) error {
				*dest[0].(*int32) = 2
				*dest[1].(*int32) = 1
				return nil
			}}
		},
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	h := &Handlers{DB: db.New(mock)}
	h.recordTrialEligibilityBacklog(ctx)
	if queryErr != nil {
		t.Fatalf("count query ran on the canceled tick context: %v", queryErr)
	}
	want := telemetry.TrialEligibilityBacklog{Consuming: 2, Idle: 1}
	if len(rec.backlogs) != 1 || rec.backlogs[0] != want {
		t.Fatalf("backlog = %v, want [%v]", rec.backlogs, want)
	}
}
