package supervisor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// pollDBTX records which named queries fired. Reads/scans all error — the
// only behavior under test is WHICH terminal write pollOne issues.
type pollDBTX struct {
	mu    sync.Mutex
	names []string
}

func (m *pollDBTX) record(sql string) {
	if i := strings.Index(sql, "-- name: "); i >= 0 {
		name := sql[i+len("-- name: "):]
		if j := strings.IndexAny(name, " \n"); j >= 0 {
			name = name[:j]
		}
		m.mu.Lock()
		m.names = append(m.names, name)
		m.mu.Unlock()
	}
}

func (m *pollDBTX) fired(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, n := range m.names {
		if n == name {
			return true
		}
	}
	return false
}

func (m *pollDBTX) Exec(_ context.Context, sql string, _ ...interface{}) (pgconn.CommandTag, error) {
	m.record(sql)
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

func (m *pollDBTX) Query(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
	m.record(sql)
	return nil, fmt.Errorf("no rows in fake")
}

func (m *pollDBTX) QueryRow(_ context.Context, sql string, _ ...interface{}) pgx.Row {
	m.record(sql)
	return failRow{}
}

type failRow struct{}

func (failRow) Scan(...any) error { return fmt.Errorf("fake row") }

// A poll that cannot resolve its host because the registration is GONE (not
// a transient blip) must fail the build immediately — pollOne otherwise
// retries a non-retryable error every tick until the build-timeout reap,
// holding the build's concurrency slot the whole time.
func TestPollOneFailsBuildWhenHostGone(t *testing.T) {
	mock := &pollDBTX{}
	vmID := "bvm-1"
	s := &BuildSupervisor{
		q: db.New(mock),
		resolve: func(context.Context, string) (vmdclient.Client, error) {
			return nil, fmt.Errorf("host %q not registered: %w", "ghost", ErrBuildHostGone)
		},
		log: zerolog.Nop(),
	}
	hostID := "ghost"
	s.pollOne(context.Background(), db.TemplateBuild{
		ID:           uuid.New(),
		TemplateID:   uuid.New(),
		TeamID:       uuid.New(),
		VmdHostID:    &hostID,
		VmdBuildVmID: &vmID,
	})
	if !mock.fired("FailBuild") {
		t.Fatalf("build not failed on ErrBuildHostGone; queries fired: %v", mock.names)
	}
}

// A transient resolution error keeps today's behavior: no terminal write,
// retry next tick.
func TestPollOneRetriesOnTransientResolveError(t *testing.T) {
	mock := &pollDBTX{}
	vmID := "bvm-1"
	s := &BuildSupervisor{
		q: db.New(mock),
		resolve: func(context.Context, string) (vmdclient.Client, error) {
			return nil, errors.New("dial tcp: i/o timeout")
		},
		log: zerolog.Nop(),
	}
	hostID := "flaky"
	s.pollOne(context.Background(), db.TemplateBuild{
		ID:           uuid.New(),
		TemplateID:   uuid.New(),
		VmdHostID:    &hostID,
		VmdBuildVmID: &vmID,
	})
	if mock.fired("FailBuild") {
		t.Fatal("transient resolve error must not fail the build")
	}
}
