package supervisor

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

type cleanupSchedulingDB struct {
	buildID       uuid.UUID
	incarnationID uuid.UUID
	cancelStarted chan struct{}
	claimReached  chan struct{}
}

type timeoutCleanupClient struct {
	vmdclient.Client
	cancelStarted chan struct{}
}

type fairCleanupClient struct {
	vmdclient.Client
	stalled       bool
	cancelStarted chan struct{}
}

func (c fairCleanupClient) CancelBuild(ctx context.Context, _ string) error {
	if c.stalled {
		select {
		case c.cancelStarted <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

func (c fairCleanupClient) DeleteBuildArtifacts(context.Context, string, string) error {
	return nil
}

func (c timeoutCleanupClient) CancelBuild(ctx context.Context, _ string) error {
	select {
	case c.cancelStarted <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return ctx.Err()
}

func (m *cleanupSchedulingDB) Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (m *cleanupSchedulingDB) Query(ctx context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
	if strings.Contains(sql, "WHERE cleanup_pending") {
		return &cleanupAttemptRows{incarnationID: m.incarnationID}, nil
	}
	return &singleBuildRow{buildID: m.buildID}, nil
}

func (m *cleanupSchedulingDB) QueryRow(_ context.Context, sql string, _ ...interface{}) pgx.Row {
	switch {
	case strings.Contains(sql, "claim_template_build"):
		select {
		case m.claimReached <- struct{}{}:
		default:
		}
		return cleanupSchedulingRow{values: []any{(*uuid.UUID)(nil)}}
	case strings.Contains(sql, "FROM template_build_execution e"):
		return cleanupSchedulingRow{values: []any{m.buildID, (*uuid.UUID)(nil), (*string)(nil), (*time.Time)(nil), "", 0, false, ""}}
	case strings.Contains(sql, "name: GetHost"):
		return cleanupHostRow{incarnationID: m.incarnationID}
	default:
		return cleanupSchedulingRow{values: []any{uuid.New(), time.Now(), time.Now()}}
	}
}

type singleBuildRow struct {
	pgx.Rows
	buildID uuid.UUID
	read    bool
}

type cleanupAttemptRows struct {
	pgx.Rows
	incarnationID uuid.UUID
	read          int
}

func (r *cleanupAttemptRows) Close()     {}
func (r *cleanupAttemptRows) Err() error { return nil }
func (r *cleanupAttemptRows) Next() bool {
	if r.read == 20 {
		return false
	}
	r.read++
	return true
}
func (r *cleanupAttemptRows) Scan(dest ...any) error {
	*dest[0].(*uuid.UUID) = uuid.New()
	*dest[1].(*uuid.UUID) = uuid.New()
	*dest[2].(*uuid.UUID) = uuid.New()
	*dest[3].(*string) = "unreachable-owner"
	*dest[4].(*uuid.UUID) = r.incarnationID
	*dest[5].(*string) = "attempt-vm"
	*dest[6].(*string) = "failed"
	*dest[7].(*time.Time) = time.Now()
	return nil
}

type cleanupHostRow struct{ incarnationID uuid.UUID }

func (r cleanupHostRow) Scan(dest ...any) error {
	*dest[11].(*pgtype.UUID) = pgtype.UUID{Bytes: r.incarnationID, Valid: true}
	return nil
}

func (r *singleBuildRow) Close()     {}
func (r *singleBuildRow) Err() error { return nil }
func (r *singleBuildRow) Next() bool {
	if r.read {
		return false
	}
	r.read = true
	return true
}
func (r *singleBuildRow) Scan(dest ...any) error {
	*dest[0].(*uuid.UUID) = r.buildID
	return nil
}

type cleanupSchedulingRow struct{ values []any }

func (r cleanupSchedulingRow) Scan(dest ...any) error {
	for i, value := range r.values {
		switch d := dest[i].(type) {
		case *uuid.UUID:
			*d = value.(uuid.UUID)
		case **uuid.UUID:
			*d = value.(*uuid.UUID)
		case **string:
			*d = value.(*string)
		case **time.Time:
			*d = value.(*time.Time)
		case *time.Time:
			*d = value.(time.Time)
		case *string:
			*d = value.(string)
		case *int:
			*d = value.(int)
		case *bool:
			*d = value.(bool)
		}
	}
	return nil
}

func TestCleanupBacklogDoesNotDelayNewBuildClaim(t *testing.T) {
	m := &cleanupSchedulingDB{
		buildID:       uuid.New(),
		incarnationID: uuid.New(),
		cancelStarted: make(chan struct{}, 1),
		claimReached:  make(chan struct{}, 1),
	}
	s := &BuildSupervisor{
		q: db.New(m), cfg: BuildSupervisorConfig{Interval: time.Second, BatchSize: 1}, log: zerolog.Nop(),
		resolve: func(context.Context, string) (vmdclient.Client, error) {
			return timeoutCleanupClient{cancelStarted: m.cancelStarted}, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cleanupDone := make(chan struct{})
	defer func() {
		cancel()
		<-cleanupDone
	}()
	go func() { s.cleanupLoop(ctx); close(cleanupDone) }()
	select {
	case <-m.cancelStarted:
	case <-time.After(time.Second):
		t.Fatal("cleanup cancellation RPC did not start")
	}
	finished := make(chan struct{})
	go func() { s.tickExecutions(ctx); close(finished) }()
	select {
	case <-m.claimReached:
	case <-time.After(time.Second):
		t.Fatal("newly queued build could not reach host claim while cleanup stalled")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("execution tick waited for cleanup")
	}
}

type fairCleanupDB struct {
	attempts [2]db.BuildAttempt
	checked  [2]int
	cleaned  [2]bool
	sequence int
}

func (m *fairCleanupDB) Exec(_ context.Context, _ string, args ...interface{}) (pgconn.CommandTag, error) {
	for i := range m.attempts {
		if m.attempts[i].ID == args[0].(uuid.UUID) {
			m.cleaned[i] = true
		}
	}
	return pgconn.CommandTag{}, nil
}

func (m *fairCleanupDB) Query(_ context.Context, _ string, args ...interface{}) (pgx.Rows, error) {
	limit := int(args[0].(int32))
	var excluded []uuid.UUID
	if len(args) > 1 {
		excluded = args[1].([]uuid.UUID)
	}
	var selected []db.BuildAttempt
	for len(selected) < limit {
		candidate := -1
		for i, a := range m.attempts {
			if m.cleaned[i] {
				continue
			}
			skip := false
			for _, id := range excluded {
				if id == a.ID {
					skip = true
					break
				}
			}
			if !skip && (candidate == -1 || m.checked[i] < m.checked[candidate]) {
				candidate = i
			}
		}
		if candidate == -1 {
			break
		}
		m.sequence++
		m.checked[candidate] = m.sequence
		selected = append(selected, m.attempts[candidate])
	}
	return &fairCleanupRows{attempts: selected}, nil
}

func (m *fairCleanupDB) QueryRow(_ context.Context, sql string, _ ...interface{}) pgx.Row {
	if strings.Contains(sql, "name: GetHost") {
		return cleanupHostRow{incarnationID: m.attempts[0].IncarnationID}
	}
	return cleanupSchedulingRow{values: []any{false}}
}

type fairCleanupRows struct {
	pgx.Rows
	attempts []db.BuildAttempt
	index    int
}

func (r *fairCleanupRows) Close()     {}
func (r *fairCleanupRows) Err() error { return nil }
func (r *fairCleanupRows) Next() bool {
	if r.index == len(r.attempts) {
		return false
	}
	r.index++
	return true
}
func (r *fairCleanupRows) Scan(dest ...any) error {
	a := r.attempts[r.index-1]
	*dest[0].(*uuid.UUID) = a.ID
	*dest[1].(*uuid.UUID) = a.BuildID
	*dest[2].(*uuid.UUID) = a.TemplateID
	*dest[3].(*string) = a.HostID
	*dest[4].(*uuid.UUID) = a.IncarnationID
	*dest[5].(*string) = a.VMID
	*dest[6].(*string) = a.State
	*dest[7].(*time.Time) = a.ClaimedAt
	return nil
}

func TestCleanupStalledOwnerDoesNotStarveReachableOwner(t *testing.T) {
	incarnation := uuid.New()
	cancelStarted := make(chan struct{}, 1)
	m := &fairCleanupDB{attempts: [2]db.BuildAttempt{
		{ID: uuid.New(), BuildID: uuid.New(), TemplateID: uuid.New(), HostID: "stalled-owner", IncarnationID: incarnation, VMID: "stalled-vm", State: "fenced", ClaimedAt: time.Now()},
		{ID: uuid.New(), BuildID: uuid.New(), TemplateID: uuid.New(), HostID: "reachable-owner", IncarnationID: incarnation, VMID: "reachable-vm", State: "fenced", ClaimedAt: time.Now()},
	}}
	s := &BuildSupervisor{
		q: db.New(m), log: zerolog.Nop(),
		resolve: func(_ context.Context, host string) (vmdclient.Client, error) {
			return fairCleanupClient{stalled: host == "stalled-owner", cancelStarted: cancelStarted}, nil
		},
	}
	for range 2 {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { s.cleanupAttempts(ctx); close(done) }()
		select {
		case <-cancelStarted:
		case <-time.After(time.Second):
			cancel()
			<-done
			t.Fatal("stalled owner cancellation did not start")
		}
		cancel()
		<-done
	}
	if !m.cleaned[1] {
		t.Fatal("reachable owner was not cleaned after stalled owner consumed the first pass")
	}
	if m.cleaned[0] {
		t.Fatal("stalled owner was incorrectly marked clean")
	}
}
