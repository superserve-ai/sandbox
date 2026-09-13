package api

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

type drainVMD struct {
	stubVMD
	call func(int64, bool) (vmdclient.HostAdmissionState, error)
}

func (v *drainVMD) HostAdmission(_ context.Context, r int64, c bool) (vmdclient.HostAdmissionState, error) {
	return v.call(r, c)
}

func TestHostDrainRequiresAcknowledgedOrderedFence(t *testing.T) {
	for _, failure := range []string{"", "preflight", "database", "host", "superseded"} {
		t.Run(failure, func(t *testing.T) {
			prepared := false
			row := db.Host{ID: "host-a", Status: "draining", AdmissionRevision: 12}
			h := &Handlers{DB: db.New(&mockDBTX{queryRowFn: func(_ context.Context, q string, args ...any) pgx.Row {
				if strings.Contains(q, "PrepareHostAdmission") {
					if failure == "database" {
						return errorRow(errors.New("write failed"))
					}
					prepared = true
					return hostRow(row)
				}
				if failure == "superseded" {
					row.AdmissionRevision++
				}
				return hostRow(row)
			}})}
			h.VMD = &drainVMD{call: func(r int64, closed bool) (vmdclient.HostAdmissionState, error) {
				if r == 0 {
					if failure == "preflight" {
						return vmdclient.HostAdmissionState{}, errors.New("offline")
					}
					return vmdclient.HostAdmissionState{Ready: true}, nil
				}
				if !prepared || r != 12 || !closed {
					t.Fatal("host command before persisted revision", r, closed)
				}
				if failure == "host" {
					return vmdclient.HostAdmissionState{}, errors.New("lost ack")
				}
				return vmdclient.HostAdmissionState{Revision: r, Closed: closed, Ready: true}, nil
			}}
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("POST", "/", nil)
			h.transitionHostAdmission(c, "host-a", "draining")
			if (w.Code == 200) != (failure == "") {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if failure == "preflight" && prepared {
				t.Fatal("failed preflight mutated directory")
			}
		})
	}
}

func TestOwnerCapabilityCacheCannotAuthorizePlacement(t *testing.T) {
	queries := 0
	h := &Handlers{DB: db.New(&mockDBTX{queryRowFn: func(_ context.Context, q string, args ...any) pgx.Row {
		queries++
		owner := strings.Contains(q, "OwnerHostHasCapabilities")
		if owner && !strings.Contains(q, "'active', 'draining'") {
			t.Fatal("draining owner excluded")
		}
		if !owner && !strings.Contains(q, "status = 'active'") {
			t.Fatal("placement eligibility weakened")
		}
		return scalarBoolRow(owner)
	}})}
	if ok, err := h.hostCapabilitiesCached(context.Background(), "host-a", []string{"preview_ports_v1"}, true); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if ok, err := h.hostHasCapabilitiesCached(context.Background(), "host-a", []string{"preview_ports_v1"}); err != nil || ok {
		t.Fatal("owner cache leaked into placement", ok, err)
	}
	if queries != 2 {
		t.Fatal("operation cache keys overlap", queries)
	}
}
