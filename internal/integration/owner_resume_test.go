//go:build integration

package integration

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/preview"
)

func TestIntegration_OwnerResumeCapabilities(t *testing.T) {
	ctx := context.Background()
	required := []string{preview.HostCapabilityPorts, preview.HostCapabilityPortAccess, preview.HostCapabilityPortTokens, preview.HostCapabilityPortBrowserAuth}
	for _, state := range []string{"active", "draining", "provisioning", "unhealthy"} {
		for _, freshness := range []string{"current", "missing", "stale", "one-stale", "null-heartbeat", "expired", "at-cutoff", "fresh-near-cutoff"} {
			t.Run(state+"/"+freshness, func(t *testing.T) {
				hostID := seedActivePreviewHost(t, required...)
				cutoff := pgtype.Timestamptz{Time: time.Now().Add(-2 * time.Minute).Truncate(time.Microsecond), Valid: true}
				exec := func(sql string) {
					t.Helper()
					if _, err := testPool.Exec(ctx, sql, hostID); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := testPool.Exec(ctx, `UPDATE host SET status=$2 WHERE id=$1`, hostID, state); err != nil {
					t.Fatal(err)
				}
				switch freshness {
				case "missing":
					if _, err := testPool.Exec(ctx, `DELETE FROM host_capability WHERE host_id=$1 AND capability=$2`, hostID, required[3]); err != nil {
						t.Fatal(err)
					}
				case "stale":
					exec(`UPDATE host SET last_heartbeat_at=last_heartbeat_at+interval '1 second' WHERE id=$1`)
				case "one-stale":
					if _, err := testPool.Exec(ctx, `UPDATE host_capability SET heartbeat_at=heartbeat_at-interval '1 second' WHERE host_id=$1 AND capability=$2`, hostID, required[3]); err != nil {
						t.Fatal(err)
					}
				case "expired", "at-cutoff", "fresh-near-cutoff":
					heartbeat := cutoff.Time
					if freshness == "expired" {
						heartbeat = heartbeat.Add(-time.Second)
					} else if freshness == "fresh-near-cutoff" {
						heartbeat = heartbeat.Add(time.Second)
					}
					setOwnerHeartbeat(t, hostID, heartbeat)
				case "null-heartbeat":
					exec(`UPDATE host SET last_heartbeat_at=NULL WHERE id=$1`)
				}
				want := (state == "active" || state == "draining") && (freshness == "current" || freshness == "fresh-near-cutoff")
				locked, err := testQueries.OwnerHasResumeCapabilities(ctx, db.OwnerHasResumeCapabilitiesParams{HostID: hostID, RequiredCapabilities: required, HeartbeatAfter: cutoff})
				if err != nil || locked != want {
					t.Fatalf("locked=%v, err=%v, want %v", locked, err, want)
				}
				unlocked, err := testQueries.OwnerHasResumeCapabilitiesUnlocked(ctx, db.OwnerHasResumeCapabilitiesUnlockedParams{HostID: hostID, RequiredCapabilities: required, HeartbeatAfter: cutoff})
				if err != nil || unlocked.HasCapabilities != want {
					t.Fatalf("unlocked=%+v, err=%v, want %v", unlocked, err, want)
				}
				if want && unlocked.VmdAddr != "localhost:0" {
					t.Fatalf("owner address=%q", unlocked.VmdAddr)
				}
				active, err := testQueries.HostHasCapabilities(ctx, db.HostHasCapabilitiesParams{HostID: hostID, RequiredCapabilities: required})
				if err != nil || active != (state == "active" && (freshness == "current" || freshness == "expired" || freshness == "at-cutoff" || freshness == "fresh-near-cutoff")) {
					t.Fatalf("active-only=%v, err=%v", active, err)
				}
				hosts, err := testQueries.ListActiveHosts(ctx)
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, host := range hosts {
					found = found || host.ID == hostID
				}
				if found != (state == "active") {
					t.Fatalf("active placement includes owner=%v, status=%s", found, state)
				}
				loaded, err := testQueries.ListActiveHostsByLoad(ctx, required)
				if err != nil {
					t.Fatal(err)
				}
				found = false
				for _, host := range loaded {
					found = found || host.ID == hostID
				}
				if found != (state == "active" && (freshness == "current" || freshness == "expired" || freshness == "at-cutoff" || freshness == "fresh-near-cutoff")) {
					t.Fatalf("capability-gated placement includes owner=%v, status=%s, freshness=%s", found, state, freshness)
				}
			})
		}
	}
	missing, err := testQueries.OwnerHasResumeCapabilities(ctx, db.OwnerHasResumeCapabilitiesParams{HostID: "missing-owner", RequiredCapabilities: required, HeartbeatAfter: pgtype.Timestamptz{Time: time.Now().Add(-2 * time.Minute), Valid: true}})
	if err != nil || missing {
		t.Fatalf("missing owner=%v, err=%v", missing, err)
	}
}

func TestIntegration_ResumeSandbox_OwnerEligibility(t *testing.T) {
	t.Setenv("HOST_CAPABILITY_CACHE_TTL", "0")
	for _, state := range []string{"active", "draining", "provisioning", "unhealthy", "missing", "stale", "null-heartbeat", "expired-active", "expired-draining"} {
		t.Run(state, func(t *testing.T) {
			ctx := context.Background()
			teamID, key := seedTeamAndKey(t)
			required := []string{preview.HostCapabilityPorts, preview.HostCapabilityPortAccess, preview.HostCapabilityPortTokens, preview.HostCapabilityPortBrowserAuth}
			owner := seedActivePreviewHost(t, required...)
			sid := seedPrivatePreviewSandbox(t, teamID, owner, "owner-resume")
			vmd := &stubVMD{}
			r := previewTokenIntegrationRouter(t, vmd, []byte("integration-preview-seed-32-bytes!!"))
			base := "/sandboxes/" + sid.String()
			if w := do(r, http.MethodPost, base+"/pause", key, ""); w.Code != http.StatusNoContent {
				t.Fatalf("pause=%d %s", w.Code, w.Body.String())
			}
			hostStatus := state
			if state == "missing" || state == "stale" || state == "null-heartbeat" || state == "expired-draining" {
				hostStatus = "draining"
			}
			if state == "expired-active" {
				hostStatus = "active"
			}
			if state == "expired-active" || state == "expired-draining" {
				setOwnerHeartbeat(t, owner, time.Now().Add(-3*time.Minute))
			}
			if _, err := testPool.Exec(ctx, `UPDATE host SET status=$2 WHERE id=$1`, owner, hostStatus); err != nil {
				t.Fatal(err)
			}
			if state == "missing" {
				if _, err := testPool.Exec(ctx, `DELETE FROM host_capability WHERE host_id=$1 AND capability=$2`, owner, required[3]); err != nil {
					t.Fatal(err)
				}
			}
			if state == "stale" {
				if _, err := testPool.Exec(ctx, `UPDATE host SET last_heartbeat_at=last_heartbeat_at+interval '1 second' WHERE id=$1`, owner); err != nil {
					t.Fatal(err)
				}
			}
			if state == "null-heartbeat" {
				if _, err := testPool.Exec(ctx, `UPDATE host SET last_heartbeat_at=NULL WHERE id=$1`, owner); err != nil {
					t.Fatal(err)
				}
			}
			wantCode, wantStatus := http.StatusConflict, db.SandboxStatusPaused
			if state == "active" || state == "draining" {
				wantCode, wantStatus = http.StatusOK, db.SandboxStatusActive
			}
			w := do(r, http.MethodPost, base+"/resume", key, "")
			if w.Code != wantCode {
				t.Fatalf("resume=%d %s, want %d", w.Code, w.Body.String(), wantCode)
			}
			wantResumeCalls := int32(0)
			if wantCode == http.StatusOK {
				wantResumeCalls = 1
			}
			if vmd.resumeCalls.Load() != wantResumeCalls || vmd.restoreCalls.Load() != 0 {
				t.Fatalf("daemon resume/restore calls=%d/%d, want %d/0", vmd.resumeCalls.Load(), vmd.restoreCalls.Load(), wantResumeCalls)
			}
			sb, err := testQueries.GetSandbox(ctx, db.GetSandboxParams{ID: sid, TeamID: teamID})
			if err != nil {
				t.Fatal(err)
			}
			if sb.HostID != owner || sb.Status != wantStatus {
				t.Fatalf("owner/status=%s/%s, want %s/%s", sb.HostID, sb.Status, owner, wantStatus)
			}
		})
	}
}

func setOwnerHeartbeat(t *testing.T, hostID string, heartbeat time.Time) {
	t.Helper()
	ctx := context.Background()
	if _, err := testPool.Exec(ctx, `UPDATE host SET last_heartbeat_at=$2 WHERE id=$1`, hostID, heartbeat); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE host_capability SET heartbeat_at=$2 WHERE host_id=$1`, hostID, heartbeat); err != nil {
		t.Fatal(err)
	}
}
