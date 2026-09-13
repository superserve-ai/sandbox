package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type refusalScheduler struct {
	stubScheduler
	excluded string
}

func (s *refusalScheduler) SelectHostExcluding(_ context.Context, _ []string, excluded string) (string, uint64, error) {
	s.excluded = excluded
	return "host-b", 2, nil
}

func TestCreateReplacesOnlyDefinitivelyRefusedBoot(t *testing.T) {
	team := uuid.New()
	scheduler := &refusalScheduler{stubScheduler: stubScheduler{hostID: "host-a"}}
	var boots atomic.Int32
	var reassigned atomic.Bool
	vmd := &stubVMD{restoreFn: func(context.Context, string, string, string) (string, error) {
		if boots.Add(1) == 1 {
			return "", vmdclient.AdmissionRefused(codes.Unavailable, "draining")
		}
		if !reassigned.Load() {
			t.Error("second boot before conditional reassignment")
		}
		return "10.0.0.9", nil
	}}
	mock := &mockDBTX{queryRowFn: func(_ context.Context, q string, args ...any) pgx.Row {
		switch {
		case strings.Contains(q, "HostHasCapabilities"):
			return previewCapableHostRow()
		case strings.Contains(q, "INSERT INTO sandbox"):
			return sandboxRow(db.Sandbox{ID: args[0].(uuid.UUID), TeamID: team, HostID: "host-a", Status: db.SandboxStatusStarting, CreatedAt: time.Now()})
		case strings.Contains(q, "FROM template"):
			return templateRow(defaultReadyTemplate())
		default:
			return activityRow()
		}
	}, execFn: func(_ context.Context, q string, args ...any) (pgconn.CommandTag, error) {
		if strings.Contains(q, "ReassignRejectedCreateHost") {
			if !strings.Contains(q, "status = 'starting'") || !strings.Contains(q, "ip_address IS NULL") {
				t.Error("unguarded reassignment")
			}
			reassigned.Store(true)
		}
		return pgconn.NewCommandTag("UPDATE 1"), nil
	}}
	h := &Handlers{VMD: vmd, DB: db.New(mock), Scheduler: scheduler}
	w := httptest.NewRecorder()
	setupTestRouter(h, team.String()).ServeHTTP(w, createSandboxReq(`{"name":"refused-create"}`))
	if w.Code != http.StatusCreated || boots.Load() != 2 || scheduler.excluded != "host-a" {
		t.Fatalf("status %d boots %d excluded %s: %s", w.Code, boots.Load(), scheduler.excluded, w.Body.String())
	}
}

func TestUncertainBootCannotBeReassigned(t *testing.T) {
	h := &Handlers{}
	for _, tc := range []struct {
		err     error
		retried bool
	}{
		{status.Error(codes.Unavailable, "transport lost"), false},
		{status.Error(codes.ResourceExhausted, "after boot"), false},
		{vmdclient.AdmissionRefused(codes.Unavailable, "closed"), true},
	} {
		if _, _, err := h.reassignRefusedCreate(context.Background(), db.Sandbox{}, nil, tc.err, tc.retried); err == nil {
			t.Fatal("uncertain create re-placed")
		}
	}
}
