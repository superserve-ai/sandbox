//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/proxy"
)

func generationBody(incarnation, address string) string {
	return fmt.Sprintf(`{"incarnation_id":%q,"vmd_addr":%q,"proxy_addr":"192.0.2.99:5009","region":"example-region","capacity_memory_mib":1024,"capacity_vcpus":2}`, incarnation, address)
}

func TestIntegration_HostGenerationAuthority(t *testing.T) {
	ctx := context.Background()
	t.Setenv("INTERNAL_API_TOKEN", "example-machine-token")
	t.Setenv("OPERATOR_API_TOKEN", "example-operator-token")
	router := newRouter(t)
	hostID, first, next := "example-"+uuid.NewString(), uuid.NewString(), uuid.NewString()
	cleanupHost(t, hostID)
	heartbeat := func(inc, addr string, want int) {
		t.Helper()
		w := hostHeartbeat(t, router, "example-machine-token", hostID, generationBody(inc, addr))
		if w.Code != want {
			t.Fatalf("heartbeat = %d %s; want %d", w.Code, w.Body.String(), want)
		}
	}
	read := func(want int64, addr, inc string) db.Host {
		t.Helper()
		h, err := testQueries.GetHost(ctx, hostID)
		if err != nil {
			t.Fatal(err)
		}
		if h.PeerGeneration == nil || *h.PeerGeneration != want || h.VmdAddr != addr || uuid.UUID(h.IncarnationID.Bytes).String() != inc {
			t.Fatalf("unexpected authoritative row: %+v", h)
		}
		return h
	}
	heartbeat("", "192.0.2.10:50051", 200)
	legacy, err := testQueries.GetHost(ctx, hostID)
	if err != nil || legacy.IncarnationID.Valid || legacy.PeerGeneration != nil {
		t.Fatalf("legacy eligible: %+v, %v", legacy, err)
	}
	heartbeat(first, "192.0.2.10:50051", 200)
	heartbeat(first, "192.0.2.10:50051", 200)
	read(1, "192.0.2.10:50051", first)
	for _, status := range []string{"active", "draining"} {
		req := httptest.NewRequest(http.MethodPost, "/internal/hosts/"+hostID+"/status",
			strings.NewReader(fmt.Sprintf(`{"status":%q}`, status)))
		req.Header.Set("Authorization", "Bearer example-operator-token")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK || mustJSON(t, w)["status"] != status {
			t.Fatalf("set status %s: %d %s", status, w.Code, w.Body.String())
		}
		if h := read(1, "192.0.2.10:50051", first); h.Status != status {
			t.Fatalf("persisted status = %s, want %s", h.Status, status)
		}
	}
	heartbeat("", "192.0.2.10:50051", 409)
	heartbeat(next, "192.0.2.10:50051", 409)
	heartbeat(first, "192.0.2.11:50051", 409) // existing live-holder guard
	if _, err := testPool.Exec(ctx, `UPDATE host SET last_heartbeat_at=now() WHERE id=$1`, hostID); err == nil {
		t.Fatal("legacy SQL writer mutated bound liveness")
	}

	// Authoritatively age the current holder, preserving the incarnation claim.
	age := func(inc string) {
		t.Helper()
		tx, err := testPool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		q := testQueries.WithTx(tx)
		if err := q.PrepareHostHeartbeat(ctx, db.PrepareHostHeartbeatParams{HostID: hostID, IncarnationID: inc}); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `UPDATE host SET last_heartbeat_at=now()-interval '3 minutes' WHERE id=$1`, hostID); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	age(first)
	heartbeat(next, "192.0.2.11:50051", 409) // staleness cannot authorize replacement
	heartbeat(first, "192.0.2.11:50051", 200)
	read(2, "192.0.2.11:50051", first)
	age(first)
	heartbeat(first, "192.0.2.10:50051", 409) // delayed address claim
	read(2, "192.0.2.11:50051", first)

	rebind := func(expected, proposed, token string, want int) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/internal/hosts/"+hostID+"/incarnation",
			strings.NewReader(fmt.Sprintf(`{"expected_incarnation":%q,"new_incarnation":%q}`, expected, proposed)))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("rebind = %d %s; want %d", w.Code, w.Body.String(), want)
		}
	}
	// The host-held credential must never authorize a replacement.
	req := httptest.NewRequest(http.MethodPost, "/internal/hosts/"+hostID+"/incarnation", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer example-machine-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != 401 && w.Code != 403 {
		t.Fatalf("machine rebind status %d", w.Code)
	}
	pressure := db.UpsertHostPressureParams{HostID: hostID, VmdAddr: "192.0.2.11:50051", IncarnationID: first}
	if rows, err := testQueries.UpsertHostPressure(ctx, pressure); err != nil || rows != 1 {
		t.Fatalf("current pressure: %d, %v", rows, err)
	}
	rebind(first, next, "example-operator-token", 200)
	rebind(first, next, "example-operator-token", 200)
	if rows, err := testQueries.UpsertHostPressure(ctx, pressure); err != nil || rows != 0 {
		t.Fatalf("retired pressure: %d, %v", rows, err)
	}
	h := read(3, "192.0.2.11:50051", next)
	if h.Status != "provisioning" || h.LastHeartbeatAt.Valid {
		t.Fatal("rebind retained activation/attestation")
	}
	heartbeat(first, "192.0.2.11:50051", 409)
	rebind(next, first, "example-operator-token", 409)
	heartbeat(next, "192.0.2.11:50051", 200)
	heartbeat(next, "192.0.2.11:50051", 200)
	read(3, "192.0.2.11:50051", next)
	age(next)
	heartbeat(first, "192.0.2.11:50051", 409)
	rebind(next, first, "example-operator-token", 409)
	read(3, "192.0.2.11:50051", next)
}

func TestIntegration_HostRebindExactTransitionRetry(t *testing.T) {
	ctx := context.Background()
	t.Setenv("INTERNAL_API_TOKEN", "example-machine-token")
	t.Setenv("OPERATOR_API_TOKEN", "example-operator-token")
	router := newRouter(t)
	hostID := "example-" + uuid.NewString()
	first, second, third := uuid.NewString(), uuid.NewString(), uuid.NewString()
	cleanupHost(t, hostID)
	if w := hostHeartbeat(t, router, "example-machine-token", hostID, generationBody(first, "192.0.2.10:50051")); w.Code != http.StatusOK {
		t.Fatalf("initial heartbeat = %d %s", w.Code, w.Body.String())
	}
	rebind := func(expected, proposed string, wantStatus int, wantGeneration int64) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/internal/hosts/"+hostID+"/incarnation",
			strings.NewReader(fmt.Sprintf(`{"expected_incarnation":%q,"new_incarnation":%q}`, expected, proposed)))
		req.Header.Set("Authorization", "Bearer example-operator-token")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != wantStatus {
			t.Fatalf("rebind = %d %s; want %d", w.Code, w.Body.String(), wantStatus)
		}
		if wantStatus == http.StatusOK && mustJSON(t, w)["peer_generation"] != float64(wantGeneration) {
			t.Fatalf("rebind response = %s; want generation %d", w.Body.String(), wantGeneration)
		}
	}
	rebind(first, second, http.StatusOK, 2)
	rebind(first, second, http.StatusOK, 2)
	rebind(second, third, http.StatusOK, 3)
	if w := hostHeartbeat(t, router, "example-machine-token", hostID, generationBody(third, "192.0.2.10:50051")); w.Code != http.StatusOK {
		t.Fatalf("current heartbeat = %d %s", w.Code, w.Body.String())
	}
	before, err := testQueries.GetHost(ctx, hostID)
	if err != nil {
		t.Fatal(err)
	}
	for _, retry := range []struct {
		expected, proposed string
		status             int
	}{
		{first, third, http.StatusConflict},
		{first, second, http.StatusConflict},
		{second, third, http.StatusOK},
		{third, first, http.StatusConflict},
		{third, second, http.StatusConflict},
	} {
		rebind(retry.expected, retry.proposed, retry.status, 3)
		after, err := testQueries.GetHost(ctx, hostID)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("rebind retry mutated host: before=%+v after=%+v", before, after)
		}
	}
}

func TestIntegration_HostGenerationOverflowRollsBack(t *testing.T) {
	ctx := context.Background()
	t.Setenv("INTERNAL_API_TOKEN", "example-machine-token")
	router := newRouter(t)
	for _, transition := range []string{"address", "operator rebind"} {
		t.Run(transition, func(t *testing.T) {
			hostID, inc := "example-"+uuid.NewString(), uuid.New()
			cleanupHost(t, hostID)
			const address = "192.0.2.10:50051"
			if w := hostHeartbeat(t, router, "example-machine-token", hostID, generationBody(inc.String(), address)); w.Code != http.StatusOK {
				t.Fatalf("initial heartbeat = %d %s", w.Code, w.Body.String())
			}

			seed, err := testPool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer seed.Rollback(ctx)
			// Bypass generation assignment only on this fixture transaction's connection.
			// SET LOCAL is reset before the real transition runs on the pool.
			if _, err := seed.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
				t.Fatal(err)
			}
			if _, err := seed.Exec(ctx, `UPDATE host SET peer_generation=$2 WHERE id=$1`, hostID, int64(math.MaxInt64)); err != nil {
				t.Fatal(err)
			}
			if err := seed.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			before, err := testQueries.GetHost(ctx, hostID)
			if err != nil {
				t.Fatal(err)
			}
			if before.PeerGeneration == nil || *before.PeerGeneration != math.MaxInt64 ||
				!before.IncarnationID.Valid || uuid.UUID(before.IncarnationID.Bytes) != inc || before.VmdAddr != address {
				t.Fatalf("unexpected overflow fixture: %+v", before)
			}
			readRetirements := func() (string, string) {
				t.Helper()
				var incarnations, addresses string
				if err := testPool.QueryRow(ctx, `SELECT
					(SELECT COALESCE(jsonb_agg(to_jsonb(i) ORDER BY i.incarnation_id), '[]'::jsonb)::text
					 FROM host_retired_incarnation i WHERE i.host_id=$1),
					(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY a.incarnation_id, a.vmd_addr), '[]'::jsonb)::text
					 FROM host_retired_address a WHERE a.host_id=$1)`, hostID).Scan(&incarnations, &addresses); err != nil {
					t.Fatal(err)
				}
				return incarnations, addresses
			}
			beforeIncarnations, beforeAddresses := readRetirements()

			tx, err := testPool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			q := testQueries.WithTx(tx)
			if transition == "address" {
				if err := q.PrepareHostHeartbeat(ctx, db.PrepareHostHeartbeatParams{HostID: hostID, IncarnationID: inc.String()}); err != nil {
					t.Fatal(err)
				}
				err = q.UpdateHostAddresses(ctx, db.UpdateHostAddressesParams{
					ID: hostID, VmdAddr: "192.0.2.11:50051", ProxyAddr: before.ProxyAddr,
					Region: before.Region, CapacityMemoryMib: before.CapacityMemoryMib, CapacityVcpus: before.CapacityVcpus,
				})
			} else {
				_, err = q.RebindHostIncarnation(ctx, db.RebindHostIncarnationParams{
					HostID: hostID, ExpectedIncarnation: inc, NewIncarnation: uuid.New(),
				})
			}
			var pgerr *pgconn.PgError
			if !errors.As(err, &pgerr) || pgerr.Code != "22003" {
				t.Fatalf("transition error = %v; want bigint overflow (22003)", err)
			}
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			after, err := testQueries.GetHost(ctx, hostID)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("overflow mutated host: before=%+v after=%+v", before, after)
			}
			if incarnations, addresses := readRetirements(); incarnations != beforeIncarnations || addresses != beforeAddresses {
				t.Fatalf("overflow mutated retirements: incarnations before=%s after=%s; addresses before=%s after=%s",
					beforeIncarnations, incarnations, beforeAddresses, addresses)
			}
		})
	}
}

func TestIntegration_HostGenerationConcurrentInitialClaims(t *testing.T) {
	t.Setenv("INTERNAL_API_TOKEN", "example-machine-token")
	router := newRouter(t)
	hostID := "example-" + uuid.NewString()
	cleanupHost(t, hostID)
	start, results := make(chan struct{}), make(chan int, 2)
	for range 2 {
		incarnation := uuid.NewString()
		go func() {
			<-start
			req := httptest.NewRequest(http.MethodPost, "/internal/hosts/"+hostID+"/heartbeat", strings.NewReader(generationBody(incarnation, "192.0.2.10:50051")))
			req.Header.Set("Authorization", "Bearer example-machine-token")
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			results <- w.Code
		}()
	}
	close(start)
	a, b := <-results, <-results
	if !((a == 200 && b == 409) || (a == 409 && b == 200)) {
		t.Fatalf("claims = %d/%d", a, b)
	}
	h, err := testQueries.GetHost(context.Background(), hostID)
	if err != nil || h.PeerGeneration == nil || *h.PeerGeneration != 1 {
		t.Fatalf("generation after claims: %+v, %v", h, err)
	}
}

func TestIntegration_HostGenerationConcurrentRebindAndHeartbeats(t *testing.T) {
	ctx := context.Background()
	t.Setenv("INTERNAL_API_TOKEN", "example-machine-token")
	t.Setenv("OPERATOR_API_TOKEN", "example-operator-token")
	router := newRouter(t)
	hostID, first, next := "example-"+uuid.NewString(), uuid.NewString(), uuid.NewString()
	cleanupHost(t, hostID)
	const address = "192.0.2.10:50051"
	request := func(path, token, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/internal/hosts/"+hostID+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	if w := request("/heartbeat", "example-machine-token", generationBody(first, address)); w.Code != http.StatusOK {
		t.Fatalf("initial heartbeat = %d %s", w.Code, w.Body.String())
	}
	other := uuid.NewString()
	rebindBody := func(proposed string) string {
		return fmt.Sprintf(`{"expected_incarnation":%q,"new_incarnation":%q}`, first, proposed)
	}
	type result struct {
		name, incarnation string
		response          *httptest.ResponseRecorder
	}
	start, results := make(chan struct{}), make(chan result, 5)
	for _, call := range []struct{ name, incarnation, path, token, body string }{
		{"rebind", next, "/incarnation", "example-operator-token", rebindBody(next)},
		{"rebind", other, "/incarnation", "example-operator-token", rebindBody(other)},
		{"heartbeat", first, "/heartbeat", "example-machine-token", generationBody(first, address)},
		{"heartbeat", next, "/heartbeat", "example-machine-token", generationBody(next, address)},
		{"heartbeat", other, "/heartbeat", "example-machine-token", generationBody(other, address)},
	} {
		go func() {
			<-start
			results <- result{call.name, call.incarnation, request(call.path, call.token, call.body)}
		}()
	}
	close(start)
	var winner, loser string
	successes, conflicts := 0, 0
	for range 5 {
		r := <-results
		// Heartbeats can serialize before or after the winning rebind.
		if r.response.Code != http.StatusOK && r.response.Code != http.StatusConflict {
			t.Errorf("%s for %s = %d %s", r.name, r.incarnation, r.response.Code, r.response.Body.String())
		}
		if r.name == "rebind" {
			switch r.response.Code {
			case http.StatusOK:
				successes++
				winner = r.incarnation
				if mustJSON(t, r.response)["peer_generation"] != float64(2) {
					t.Errorf("winning rebind generation: %s", r.response.Body.String())
				}
			case http.StatusConflict:
				conflicts++
				loser = r.incarnation
			}
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("competing rebinds: successes=%d conflicts=%d; want 1 each", successes, conflicts)
	}
	next = winner
	read := func() db.Host {
		t.Helper()
		h, err := testQueries.GetHost(ctx, hostID)
		if err != nil {
			t.Fatal(err)
		}
		if !h.IncarnationID.Valid || uuid.UUID(h.IncarnationID.Bytes).String() != next ||
			h.PeerGeneration == nil || *h.PeerGeneration != 2 || h.VmdAddr != address {
			t.Fatalf("authority after concurrent rebind: %+v", h)
		}
		return h
	}
	if h := read(); h.Status != "provisioning" {
		t.Fatalf("rebind race activated host: %s", h.Status)
	}
	beforeLoser := read()
	if w := request("/heartbeat", "example-machine-token", generationBody(loser, address)); w.Code != http.StatusConflict {
		t.Fatalf("losing holder heartbeat = %d %s", w.Code, w.Body.String())
	}
	if w := request("/incarnation", "example-operator-token", rebindBody(loser)); w.Code != http.StatusConflict {
		t.Fatalf("losing rebind retry = %d %s", w.Code, w.Body.String())
	}
	if after := read(); !reflect.DeepEqual(beforeLoser, after) {
		t.Fatalf("losing candidate mutated host: before=%+v after=%+v", beforeLoser, after)
	}
	if w := request("/incarnation", "example-operator-token", rebindBody(winner)); w.Code != http.StatusOK {
		t.Fatalf("winning rebind retry = %d %s", w.Code, w.Body.String())
	}
	if w := request("/heartbeat", "example-machine-token", generationBody(next, address)); w.Code != http.StatusOK {
		t.Fatalf("new holder retry = %d %s", w.Code, w.Body.String())
	}
	read()

	teamID, _ := seedTeamAndKey(t)
	sandboxID := seedPrivatePreviewSandbox(t, teamID, hostID, "example-retired-heartbeat")
	if _, err := testPool.Exec(ctx, `INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'billing_metrics_write', true)
		ON CONFLICT (team_id, key) DO UPDATE SET enabled = EXCLUDED.enabled`, teamID); err != nil {
		t.Fatal(err)
	}
	withAttestations := func(body, capabilities string, allocatedBytes int64) string {
		return strings.TrimSuffix(body, "}") + fmt.Sprintf(`,"capabilities":%s,"storage":[{"sandbox_id":%q,"allocated_bytes":%d}]}`, capabilities, sandboxID.String(), allocatedBytes)
	}
	seedBody := withAttestations(generationBody(next, address), `["preview_ports_v1","example_retained"]`, 8*1024*1024)
	if w := request("/heartbeat", "example-machine-token", seedBody); w.Code != http.StatusOK {
		t.Fatalf("seed attestations = %d %s", w.Code, w.Body.String())
	}
	var capabilities, storage int
	deadline := time.Now().Add(7 * time.Second)
	for {
		if err := testPool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM host_capability WHERE host_id=$1),
			(SELECT count(*) FROM sandbox_storage_interval WHERE sandbox_id=$2 AND ended_at IS NULL AND disk_mib=8)`,
			hostID, sandboxID).Scan(&capabilities, &storage); err != nil {
			t.Fatal(err)
		}
		if capabilities == 2 && storage == 1 {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if capabilities != 2 || storage != 1 {
		t.Fatalf("seeded capabilities=%d storage=%d; want 2 and 1", capabilities, storage)
	}
	readAttestations := func() (string, string) {
		t.Helper()
		var capabilities, storage string
		if err := testPool.QueryRow(ctx, `SELECT
			(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY c.capability), '[]'::jsonb)::text
			 FROM host_capability c WHERE c.host_id=$1),
			(SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY s.id), '[]'::jsonb)::text
			 FROM sandbox_storage_interval s WHERE s.sandbox_id=$2)`, hostID, sandboxID).Scan(&capabilities, &storage); err != nil {
			t.Fatal(err)
		}
		return capabilities, storage
	}
	beforeCapabilities, beforeStorage := readAttestations()

	// A stale, unhealthy replacement must not be revived by its retired holder.
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := testQueries.WithTx(tx).PrepareHostHeartbeat(ctx, db.PrepareHostHeartbeatParams{HostID: hostID, IncarnationID: next}); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE host SET status='unhealthy', last_heartbeat_at=now()-interval '3 minutes' WHERE id=$1`, hostID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	before := read()
	for _, addr := range []string{address, "192.0.2.11:50051"} {
		body := strings.Replace(generationBody(first, addr), "192.0.2.99:5009", "203.0.113.99:5009", 1)
		body = withAttestations(body, `["preview_ports_v1","example_retired"]`, 16*1024*1024)
		if w := request("/heartbeat", "example-machine-token", body); w.Code != http.StatusConflict {
			t.Fatalf("retired heartbeat = %d %s", w.Code, w.Body.String())
		}
		if after := read(); !reflect.DeepEqual(before, after) {
			t.Fatalf("retired heartbeat mutated replacement: before=%+v after=%+v", before, after)
		}
		if capabilities, storage := readAttestations(); capabilities != beforeCapabilities || storage != beforeStorage {
			t.Fatalf("retired heartbeat mutated attestations: capabilities before=%s after=%s; storage before=%s after=%s",
				beforeCapabilities, capabilities, beforeStorage, storage)
		}
	}
}

func TestIntegration_HostGenerationAtomicAddressAndTombstone(t *testing.T) {
	ctx := context.Background()
	t.Setenv("INTERNAL_API_TOKEN", "example-machine-token")
	router := newRouter(t)
	hostID, inc := "example-"+uuid.NewString(), uuid.NewString()
	cleanupHost(t, hostID)
	if w := hostHeartbeat(t, router, "example-machine-token", hostID, generationBody(inc, "192.0.2.10:50051")); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	q := testQueries.WithTx(tx)
	if err := q.PrepareHostHeartbeat(ctx, db.PrepareHostHeartbeatParams{HostID: hostID, IncarnationID: inc}); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE host SET vmd_addr='192.0.2.11:50051' WHERE id=$1`, hostID); err != nil {
		t.Fatal(err)
	}
	old, err := testQueries.GetHost(ctx, hostID)
	if err != nil || old.VmdAddr != "192.0.2.10:50051" || old.PeerGeneration == nil || *old.PeerGeneration != 1 {
		t.Fatalf("dirty endpoint snapshot: %+v, %v", old, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	current, err := testQueries.GetHost(ctx, hostID)
	if err != nil || current.VmdAddr != "192.0.2.11:50051" || current.PeerGeneration == nil || *current.PeerGeneration != 2 {
		t.Fatalf("committed endpoint snapshot: %+v, %v", current, err)
	}
	if _, err := testPool.Exec(ctx, `DELETE FROM host WHERE id=$1`, hostID); err != nil {
		t.Fatal(err)
	}
	if w := hostHeartbeat(t, router, "example-machine-token", hostID, generationBody(inc, "192.0.2.11:50051")); w.Code != 409 {
		t.Fatalf("retired host ID accepted: %d", w.Code)
	}
	if w := hostHeartbeat(t, router, "example-machine-token", hostID, generationBody(uuid.NewString(), "192.0.2.11:50051")); w.Code != http.StatusConflict {
		t.Fatalf("retired host ID accepted fresh incarnation: %d %s", w.Code, w.Body.String())
	}
	if host, err := testQueries.GetHost(ctx, hostID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("retired host row recreated: %+v, %v", host, err)
	}
}

func TestIntegration_HostPeerDiscoverySnapshot(t *testing.T) {
	ctx := context.Background()
	t.Setenv("INTERNAL_API_TOKEN", "example-machine-token")
	router := newRouter(t)
	hostID, inc := "example-"+uuid.NewString(), uuid.NewString()
	cleanupHost(t, hostID)
	beat := func(incarnation string) {
		t.Helper()
		w := hostHeartbeat(t, router, "example-machine-token", hostID, strings.Replace(generationBody(incarnation, "192.0.2.10:50051"), "192.0.2.99:5009", "192.0.2.10:5009", 1))
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
	}
	beat("")
	team, _ := seedTeamAndKey(t)
	sandboxID := seedPrivatePreviewSandbox(t, team, hostID, "example-peer-discovery")
	row, err := testQueries.GetSandboxPeerEndpoint(ctx, sandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := proxy.PeerEndpointFromDiscovery(row); err == nil {
		t.Fatal("legacy discovery accepted")
	}
	beat(inc)
	row, err = testQueries.GetSandboxPeerEndpoint(ctx, sandboxID)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := proxy.PeerEndpointFromDiscovery(row)
	if err != nil || endpoint.Address != "192.0.2.10:5009" || endpoint.Generation != 1 {
		t.Fatalf("discovery = %+v, %v", endpoint, err)
	}
	body := strings.Replace(generationBody(inc, "192.0.2.10:50051"), "192.0.2.99:5009", "203.0.113.200:1234", 1)
	if w := hostHeartbeat(t, router, "example-machine-token", hostID, body); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	row, err = testQueries.GetSandboxPeerEndpoint(ctx, sandboxID)
	if err != nil {
		t.Fatal(err)
	}
	unchanged, err := proxy.PeerEndpointFromDiscovery(row)
	if err == nil || unchanged != (proxy.PeerEndpoint{}) {
		t.Fatalf("mismatched proxy advertisement returned route: %+v, %v", unchanged, err)
	}
	if row.ProxyAddr == nil || *row.ProxyAddr != "203.0.113.200:1234" || row.PeerGeneration == nil || *row.PeerGeneration != int64(endpoint.Generation) {
		t.Fatalf("advertisement and generation snapshot = %+v", row)
	}
	beat(inc)
	row, err = testQueries.GetSandboxPeerEndpoint(ctx, sandboxID)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := proxy.PeerEndpointFromDiscovery(row)
	if err != nil || restored != endpoint {
		t.Fatalf("restored listener = %+v, %v", restored, err)
	}
}
