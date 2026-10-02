//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

type heartbeatHostRegistry struct{ invalidated []string }

func (f *heartbeatHostRegistry) ClientFor(context.Context, string) (vmdclient.Client, error) {
	return nil, fmt.Errorf("not used in this test")
}
func (f *heartbeatHostRegistry) Invalidate(hostID string) {
	f.invalidated = append(f.invalidated, hostID)
}
func (f *heartbeatHostRegistry) Generation(string) uint64 { return 0 }
func (f *heartbeatHostRegistry) MarkVerified(context.Context, string, string, uint64) error {
	return nil
}

func heartbeatFixture(t *testing.T) (string, http.Handler, *heartbeatHostRegistry) {
	t.Helper()
	hostID := "example-" + uuid.NewString()
	cleanupHost(t, hostID)
	if _, err := testQueries.CreateHost(t.Context(), db.CreateHostParams{
		ID: hostID, VmdAddr: "192.0.2.1:50051", ProxyAddr: "192.0.2.1:5007",
		Region: "example-region", CapacityMemoryMib: 1024, CapacityVcpus: 2,
	}); err != nil {
		t.Fatal(err)
	}
	registry := &heartbeatHostRegistry{}
	h := &api.Handlers{DB: testQueries, Pool: testPool, Hosts: registry}
	r := gin.New()
	r.POST("/internal/hosts/:host_id/heartbeat", h.HostHeartbeat)
	return hostID, r, registry
}

func TestIntegration_HostHeartbeatSyncsAndClearsCapabilities(t *testing.T) {
	hostID, r, _ := heartbeatFixture(t)
	for _, tc := range []struct {
		body string
		want int
	}{
		{`{"capabilities":["preview_ports_v1"]}`, 1},
		{"", 0},
	} {
		w := hostHeartbeat(t, r, "", hostID, tc.body)
		if w.Code != http.StatusOK {
			t.Fatalf("heartbeat = %d %s", w.Code, w.Body.String())
		}
		var total, attested int
		if err := testPool.QueryRow(t.Context(), `SELECT count(*), count(*) FILTER (
			WHERE capability = 'preview_ports_v1' AND heartbeat_at =
			(SELECT last_heartbeat_at FROM host WHERE id = $1))
			FROM host_capability WHERE host_id = $1`, hostID).Scan(&total, &attested); err != nil {
			t.Fatal(err)
		}
		if total != tc.want || attested != tc.want {
			t.Fatalf("capabilities = %d, attested = %d; want %d", total, attested, tc.want)
		}
	}
}

func TestIntegration_HostHeartbeatSyncsProxyAddressWithoutVMDChange(t *testing.T) {
	for _, binding := range []string{"legacy", "bound"} {
		t.Run(binding, func(t *testing.T) {
			hostID, r, _ := heartbeatFixture(t)
			incarnation := ""
			if binding == "bound" {
				incarnation = uuid.NewString()
			}
			beat := func(proxyAddr string) {
				t.Helper()
				body := fmt.Sprintf(`{"incarnation_id":%q,"vmd_addr":"192.0.2.1:50051","proxy_addr":%q,"region":"example-region","capacity_memory_mib":1024,"capacity_vcpus":2}`, incarnation, proxyAddr)
				if w := hostHeartbeat(t, r, "", hostID, body); w.Code != http.StatusOK {
					t.Fatalf("heartbeat = %d %s", w.Code, w.Body.String())
				}
			}
			beat("192.0.2.1:5007")
			before, err := testQueries.GetHost(t.Context(), hostID)
			if err != nil {
				t.Fatal(err)
			}
			if binding == "bound" && (!before.IncarnationID.Valid ||
				uuid.UUID(before.IncarnationID.Bytes).String() != incarnation ||
				before.PeerGeneration == nil || *before.PeerGeneration <= 0) {
				t.Fatalf("host was not authoritatively bound: %+v", before)
			}
			beat("192.0.2.1:6007")
			host, err := testQueries.GetHost(t.Context(), hostID)
			if err != nil {
				t.Fatal(err)
			}
			if host.VmdAddr != "192.0.2.1:50051" || host.ProxyAddr != "192.0.2.1:6007" {
				t.Fatalf("addresses = %s / %s", host.VmdAddr, host.ProxyAddr)
			}
			if host.IncarnationID != before.IncarnationID {
				t.Fatal("proxy-only heartbeat changed incarnation")
			}
			if binding == "bound" {
				if host.PeerGeneration == nil || *host.PeerGeneration != *before.PeerGeneration {
					t.Fatalf("proxy-only heartbeat changed generation: before=%+v after=%+v", before, host)
				}
			} else if host.PeerGeneration != nil {
				t.Fatal("legacy heartbeat allocated a peer generation")
			}
		})
	}
}

func TestIntegration_HostHeartbeatInitialBindingClearsPressure(t *testing.T) {
	hostID, r, _ := heartbeatFixture(t)
	pressure := db.UpsertHostPressureParams{HostID: hostID, VmdAddr: "192.0.2.1:50051", AllocatedMemoryMib: 512}
	if rows, err := testQueries.UpsertHostPressure(t.Context(), pressure); err != nil || rows != 1 {
		t.Fatalf("pre-bind pressure = %d rows, %v", rows, err)
	}
	incarnation := uuid.NewString()
	body := fmt.Sprintf(`{"incarnation_id":%q,"vmd_addr":"192.0.2.1:50051","proxy_addr":"192.0.2.1:5007","region":"example-region","capacity_memory_mib":1024,"capacity_vcpus":2,"capabilities":["capacity_pressure_v1"]}`, incarnation)
	beat := func() {
		t.Helper()
		if w := hostHeartbeat(t, r, "", hostID, body); w.Code != http.StatusOK {
			t.Fatalf("heartbeat = %d %s", w.Code, w.Body.String())
		}
	}
	beat()
	host, err := testQueries.GetHost(t.Context(), hostID)
	if err != nil {
		t.Fatal(err)
	}
	if !host.IncarnationID.Valid || uuid.UUID(host.IncarnationID.Bytes).String() != incarnation ||
		host.PeerGeneration == nil || *host.PeerGeneration != 1 {
		t.Fatalf("host was not authoritatively bound: %+v", host)
	}
	var reports, capabilities int
	if err := testPool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM host_pressure WHERE host_id = $1),
		(SELECT count(*) FROM host_capability WHERE host_id = $1 AND capability = 'capacity_pressure_v1'
		 AND heartbeat_at = (SELECT last_heartbeat_at FROM host WHERE id = $1))`, hostID).Scan(&reports, &capabilities); err != nil {
		t.Fatal(err)
	}
	if reports != 0 || capabilities != 1 {
		t.Fatalf("after binding: pressure reports = %d, attested capabilities = %d; want 0, 1", reports, capabilities)
	}

	pressure.IncarnationID = incarnation
	if rows, err := testQueries.UpsertHostPressure(t.Context(), pressure); err != nil || rows != 1 {
		t.Fatalf("bound pressure = %d rows, %v", rows, err)
	}
	beat()
	var allocatedMemory int64
	if err := testPool.QueryRow(t.Context(), `SELECT allocated_memory_mib FROM host_pressure WHERE host_id = $1`, hostID).Scan(&allocatedMemory); err != nil {
		t.Fatal(err)
	}
	if allocatedMemory != pressure.AllocatedMemoryMib {
		t.Fatalf("retry changed bound pressure: got %d, want %d", allocatedMemory, pressure.AllocatedMemoryMib)
	}
}

func TestIntegration_HostHeartbeatReclaimEvictsCachedClient(t *testing.T) {
	full := `{"vmd_addr":"192.0.2.2:50051","proxy_addr":"192.0.2.2:5007","region":"example-region","capacity_memory_mib":1024,"capacity_vcpus":2}`
	partial := `{"vmd_addr":"192.0.2.2:50051","capacity_memory_mib":1024,"capacity_vcpus":2}`
	for _, tc := range []struct {
		name   string
		stale  bool
		body   string
		status int
	}{
		{"stale reclaim", true, full, http.StatusOK},
		{"live conflict", false, full, http.StatusConflict},
		{"partial claim", true, partial, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hostID, r, registry := heartbeatFixture(t)
			ageSeconds := 0
			if tc.stale {
				ageSeconds = 180
			}
			if _, err := testPool.Exec(t.Context(), `UPDATE host SET last_heartbeat_at = now() - make_interval(secs => $2) WHERE id = $1`, hostID, ageSeconds); err != nil {
				t.Fatal(err)
			}
			before, err := testQueries.GetHost(t.Context(), hostID)
			if err != nil {
				t.Fatal(err)
			}
			w := hostHeartbeat(t, r, "", hostID, tc.body)
			if w.Code != tc.status {
				t.Fatalf("heartbeat = %d %s; want %d", w.Code, w.Body.String(), tc.status)
			}
			if tc.status == http.StatusOK {
				if len(registry.invalidated) != 1 || registry.invalidated[0] != hostID {
					t.Fatalf("invalidated = %v; want [%s]", registry.invalidated, hostID)
				}
			} else {
				if len(registry.invalidated) != 0 {
					t.Fatalf("rejected claim invalidated %v", registry.invalidated)
				}
				after, err := testQueries.GetHost(t.Context(), hostID)
				if err != nil {
					t.Fatal(err)
				}
				if after.VmdAddr != before.VmdAddr || after.LastHeartbeatAt != before.LastHeartbeatAt {
					t.Fatal("rejected claim changed address or liveness")
				}
			}
		})
	}
}
