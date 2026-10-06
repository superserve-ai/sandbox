//go:build integration

package integration

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/abuse"
	"github.com/superserve-ai/sandbox/internal/mining"
)

type miningAssignments struct{ policy abuse.SandboxPolicy }

func (a miningAssignments) MiningPolicy(id uuid.UUID, ip string) (abuse.SandboxPolicy, bool) {
	return a.policy, a.policy.SandboxID == id && a.policy.HostIP == ip
}

func TestMiningIncidentAtomicRetryReleaseAndAttribution(t *testing.T) {
	ctx := context.Background()
	team := mustCreateTeam(t, ctx, "mining-"+uuid.NewString()[:8])
	sandbox := seedActiveSandbox(t, team, "mining-synthetic")
	if _, err := testPool.Exec(ctx, `UPDATE abuse_runtime_settings SET mode='enforce'`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { testPool.Exec(ctx, `UPDATE abuse_runtime_settings SET mode='off'`) })
	assignment := abuse.SandboxPolicy{TeamPolicy: abuse.TeamPolicy{TeamID: team, Known: true, Mode: abuse.ModeEnforce}, SandboxID: sandbox, HostID: testDefaultHostID, HostIP: "192.0.2.9", Assignment: "synthetic-assignment"}
	store := abuse.NewIncidentStore(testPool, testDefaultHostID, miningAssignments{assignment})
	incident := abuse.MiningIncident{ID: uuid.New(), TeamID: team, SandboxID: sandbox, HostID: testDefaultHostID, HostIP: assignment.HostIP, Assignment: assignment.Assignment, Generation: currentMiningGeneration(t), ObservedAt: time.Now(), Evidence: abuse.MiningEvidence{Kind: "domain", Indicator: "pool.invalid", PolicyRevision: "synthetic"}}
	const count = 6
	receipts := make(chan abuse.IncidentReceipt, count)
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for n := 0; n < count; n++ {
		wg.Add(1)
		go func() { defer wg.Done(); r, e := store.RecordIncident(ctx, incident); receipts <- r; errs <- e }()
	}
	wg.Wait()
	close(receipts)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var restriction uuid.UUID
	for r := range receipts {
		if r.Disposition != abuse.IncidentApplied {
			t.Fatalf("receipt %+v", r)
		}
		if restriction == uuid.Nil {
			restriction = r.RestrictionID
		} else if restriction != r.RestrictionID {
			t.Fatal("duplicate restriction")
		}
	}
	spoofDomain := "unverified-" + uuid.NewString() + ".invalid"
	if _, err := testPool.Exec(ctx, `INSERT INTO abuse_trusted_identities(auth_provider,domain) VALUES('google',$1)`, spoofDomain); err != nil {
		t.Fatal(err)
	}
	for _, action := range []abuse.Action{abuse.ActionCreate, abuse.ActionResume} {
		decision, err := abuse.Resolve(ctx, testPool, abuse.Request{TeamID: team, UserID: uuid.New(), AuthProvider: "google", Domain: spoofDomain, Action: action, GlobalEnabled: true})
		if err != nil || decision.Allowed {
			t.Fatalf("unverified request claims bypassed unified compute restriction: %+v %v", decision, err)
		}
	}
	var auditPayload, privateEvidence string
	if err := testPool.QueryRow(ctx, `SELECT a.new_value::text,i.evidence::text FROM audit_logs a JOIN abuse_mining_incidents i ON i.id=$2 WHERE a.team_id=$1 AND a.event_type='abuse.mining_incident.recorded'`, team, incident.ID).Scan(&auditPayload, &privateEvidence); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(auditPayload, incident.Evidence.Indicator) || strings.Contains(auditPayload, "policy_revision") || !strings.Contains(privateEvidence, incident.Evidence.Indicator) {
		t.Fatalf("private evidence must remain solely in protected incident state")
	}
	var audits, changes, restrictions int
	if err := testPool.QueryRow(ctx, `SELECT (SELECT count(*) FROM audit_logs WHERE team_id=$1 AND event_type='abuse.mining_incident.recorded' AND actor_user_id IS NULL),(SELECT count(*) FROM abuse_state_changes WHERE team_id=$1 AND reason='mining incident recorded'),(SELECT count(*) FROM abuse_restrictions WHERE subject_team_id=$1)`, team).Scan(&audits, &changes, &restrictions); err != nil {
		t.Fatal(err)
	}
	if audits != 1 || changes != 1 || restrictions != 1 {
		t.Fatalf("atomic counts %d/%d/%d", audits, changes, restrictions)
	}
	changed := incident
	changed.TeamID = uuid.New()
	if _, err := store.RecordIncident(ctx, changed); !errors.Is(err, abuse.ErrInvalidIncident) {
		t.Fatalf("changed victim accepted: %v", err)
	}
	changed = incident
	changed.ID = uuid.New()
	changed.Assignment = "stale"
	if _, err := store.RecordIncident(ctx, changed); !errors.Is(err, abuse.ErrInvalidIncident) {
		t.Fatalf("stale assignment accepted: %v", err)
	}
	forgedAssignment := assignment
	forgedAssignment.TeamID = uuid.New()
	forged := incident
	forged.ID = uuid.New()
	forged.TeamID = forgedAssignment.TeamID
	forgedStore := abuse.NewIncidentStore(testPool, testDefaultHostID, miningAssignments{forgedAssignment})
	if _, err := forgedStore.RecordIncident(ctx, forged); !errors.Is(err, abuse.ErrInvalidIncident) {
		t.Fatalf("local owner contradicted DB but accepted: %v", err)
	}
	foreign := incident
	foreign.HostID = "another-host"
	foreignAssignment := assignment
	foreignAssignment.HostID = foreign.HostID
	foreignStore := abuse.NewIncidentStore(testPool, foreign.HostID, miningAssignments{foreignAssignment})
	if _, err := foreignStore.RecordIncident(ctx, foreign); !errors.Is(err, abuse.ErrInvalidIncident) {
		t.Fatalf("foreign host stole duplicate receipt: %v", err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE abuse_restrictions SET released_at=now() WHERE id=$1`, restriction); err != nil {
		t.Fatal(err)
	}
	r, err := store.RecordIncident(ctx, incident)
	if err != nil || r.Disposition != abuse.IncidentReleased {
		t.Fatalf("retry resurrected released incident: %+v %v", r, err)
	}
	fresh := incident
	fresh.ID = uuid.New()
	fresh.ObservedAt = time.Now()
	r, err = store.RecordIncident(ctx, fresh)
	if err != nil || r.Disposition != abuse.IncidentApplied || r.RestrictionID == restriction {
		t.Fatalf("new observation did not create independent restriction: %+v %v", r, err)
	}
	overlap := incident
	overlap.ID = uuid.New()
	overlap.ObservedAt = time.Now()
	overlapReceipt, err := store.RecordIncident(ctx, overlap)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE abuse_restrictions SET expires_at=now()-interval '1 second' WHERE id=$1`, overlapReceipt.RestrictionID); err != nil {
		t.Fatal(err)
	}
	expired, err := store.RecordIncident(ctx, overlap)
	if err != nil || expired.Disposition != abuse.IncidentReleased {
		t.Fatalf("expiry retry resurrected restriction: %+v %v", expired, err)
	}
	effective, err := abuse.ResolveTeamPolicy(ctx, testPool, team)
	if err != nil || !effective.Restricted {
		t.Fatalf("expiry removed another active restriction: %+v %v", effective, err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO abuse_team_trust(team_id,verified) VALUES($1,true)`, team); err != nil {
		t.Fatal(err)
	}
	r, err = store.IncidentStatus(ctx, fresh.ID)
	if err != nil || r.Disposition != abuse.IncidentExempt {
		t.Fatalf("current trust not honored: %+v %v", r, err)
	}
	fresh.ID = uuid.New()
	r, err = store.RecordIncident(ctx, fresh)
	if err != nil || r.Disposition != abuse.IncidentExempt || r.RestrictionID != uuid.Nil {
		t.Fatalf("trusted team quarantined: %+v %v", r, err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE abuse_team_trust SET verified=false WHERE team_id=$1;`, team); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"off", "observe"} {
		if _, err := testPool.Exec(ctx, `UPDATE abuse_runtime_settings SET mode=$1`, mode); err != nil {
			t.Fatal(err)
		}
		fresh.ID = uuid.New()
		r, err = store.RecordIncident(ctx, fresh)
		if err != nil || r.Disposition != abuse.IncidentIgnored || r.RestrictionID != uuid.Nil {
			t.Fatalf("mode %s quarantined: %+v %v", mode, r, err)
		}
	}
	var readable bool
	if err := testPool.QueryRow(ctx, `SELECT COALESCE(bool_or(has_table_privilege(oid,'abuse_mining_incidents','SELECT,INSERT,UPDATE,DELETE')),false) FROM pg_roles WHERE rolname IN ('authenticated','anon')`).Scan(&readable); err != nil {
		t.Fatal(err)
	}
	if readable {
		t.Fatal("tenant role has incident privileges")
	}
}

func TestMiningIncidentAuditFailureRollsBackRestrictionAndReceipt(t *testing.T) {
	ctx := context.Background()
	team := mustCreateTeam(t, ctx, "mining-atomic-"+uuid.NewString()[:8])
	sandbox := seedActiveSandbox(t, team, "mining-atomic")
	if _, err := testPool.Exec(ctx, `UPDATE abuse_runtime_settings SET mode='enforce'`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		testPool.Exec(ctx, `UPDATE abuse_runtime_settings SET mode='off'`)
		testPool.Exec(ctx, `ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS mining_test_reject_audit`)
	})
	// Only this synthetic team's machine audit is rejected.
	if _, err := testPool.Exec(ctx, `ALTER TABLE audit_logs ADD CONSTRAINT mining_test_reject_audit CHECK (team_id IS DISTINCT FROM '`+team.String()+`'::uuid OR event_type <> 'abuse.mining_incident.recorded') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	assignment := abuse.SandboxPolicy{TeamPolicy: abuse.TeamPolicy{TeamID: team, Known: true, Mode: abuse.ModeEnforce}, SandboxID: sandbox, HostID: testDefaultHostID, HostIP: "192.0.2.10", Assignment: "atomic-assignment"}
	store := abuse.NewIncidentStore(testPool, testDefaultHostID, miningAssignments{assignment})
	incident := abuse.MiningIncident{ID: uuid.New(), TeamID: team, SandboxID: sandbox, HostID: testDefaultHostID, HostIP: assignment.HostIP, Assignment: assignment.Assignment, Generation: currentMiningGeneration(t), ObservedAt: time.Now(), Evidence: abuse.MiningEvidence{Kind: "domain", Indicator: "pool.invalid"}}
	if _, err := store.RecordIncident(ctx, incident); err == nil {
		t.Fatal("audit failure was ignored")
	}
	var count int
	if err := testPool.QueryRow(ctx, `SELECT (SELECT count(*) FROM abuse_restrictions WHERE subject_team_id=$1)+(SELECT count(*) FROM abuse_mining_incidents WHERE team_id=$1)+(SELECT count(*) FROM abuse_state_changes WHERE team_id=$1 AND reason='mining incident recorded')`, team).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("partial mutation persisted: %d rows", count)
	}
}

func currentMiningGeneration(t *testing.T) int64 {
	t.Helper()
	var generation int64
	if err := testPool.QueryRow(context.Background(), `SELECT COALESCE(max(id),0) FROM abuse_state_changes`).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	return generation
}
func TestMiningReleaseFencesUndeliveredOlderObservation(t *testing.T) {
	ctx := context.Background()
	team := mustCreateTeam(t, ctx, "mining-fence-"+uuid.NewString()[:8])
	sandbox := seedActiveSandbox(t, team, "mining-fence")
	if _, err := testPool.Exec(ctx, `UPDATE abuse_runtime_settings SET mode='enforce'`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { testPool.Exec(ctx, `UPDATE abuse_runtime_settings SET mode='off'`) })
	assignment := abuse.SandboxPolicy{TeamPolicy: abuse.TeamPolicy{TeamID: team, Known: true, Mode: abuse.ModeEnforce}, SandboxID: sandbox, HostID: testDefaultHostID, HostIP: "192.0.2.11", Assignment: "fence-assignment"}
	store := abuse.NewIncidentStore(testPool, testDefaultHostID, miningAssignments{assignment})
	incident := abuse.MiningIncident{ID: uuid.New(), TeamID: team, SandboxID: sandbox, HostID: testDefaultHostID, HostIP: assignment.HostIP, Assignment: assignment.Assignment, Generation: currentMiningGeneration(t), ObservedAt: time.Now(), Evidence: abuse.MiningEvidence{Kind: "domain", Indicator: "pool.invalid"}}
	applied, err := store.RecordIncident(ctx, incident)
	if err != nil || applied.Disposition != abuse.IncidentApplied {
		t.Fatalf("initial %+v %v", applied, err)
	}
	pending := incident
	pending.ID = uuid.New()
	actor := seedPlatformAdminProfile(t)
	r := newInternalRouter(t)
	response := doInternal(r, http.MethodPost, "/internal/abuse/restrictions/"+applied.RestrictionID.String()+"/release", actor.String(), "")
	if response.Code != http.StatusNoContent {
		t.Fatalf("release failed: %d %s", response.Code, response.Body.String())
	}
	var bound bool
	if err := testPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM abuse_state_changes WHERE team_id=$1 AND reason='restriction released')`, team).Scan(&bound); err != nil || !bound {
		t.Fatalf("release generation not team-bound: %v", err)
	}
	released, err := store.RecordIncident(ctx, incident)
	if err != nil || released.Disposition != abuse.IncidentReleased {
		t.Fatalf("old receipt resurrected: %+v %v", released, err)
	}
	ignored, err := store.RecordIncident(ctx, pending)
	if err != nil || ignored.Disposition != abuse.IncidentIgnored || ignored.RestrictionID != uuid.Nil {
		t.Fatalf("undelivered old observation undid release: %+v %v", ignored, err)
	}
	fresh := incident
	fresh.ID = uuid.New()
	fresh.Generation = currentMiningGeneration(t)
	fresh.ObservedAt = time.Now()
	renewed, err := store.RecordIncident(ctx, fresh)
	if err != nil || renewed.Disposition != abuse.IncidentApplied {
		t.Fatalf("fresh post-refresh observation was suppressed: %+v %v", renewed, err)
	}
}

// This source represents a replacement network session after the durable
// observation was captured; receipts must never contain its different owner.
type retiredMiningAssignment struct{ miningAssignments }

func (a retiredMiningAssignment) AssignmentRetired(abuse.MiningIncident) bool { return true }

func TestMiningCapturedReplaySurvivesLifecycleAndHonorsCurrentPolicy(t *testing.T) {
	ctx := context.Background()
	for _, transition := range []string{"pause", "delete", "migrate", "delete-trust", "delete-release", "delete-off"} {
		t.Run(transition, func(t *testing.T) {
			if _, err := testPool.Exec(ctx, `UPDATE abuse_runtime_settings SET mode='enforce'`); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { testPool.Exec(ctx, `UPDATE abuse_runtime_settings SET mode='off'`) })
			team := mustCreateTeam(t, ctx, "capture-"+uuid.NewString()[:8])
			replacementTeam := mustCreateTeam(t, ctx, "replacement-"+uuid.NewString()[:8])
			sandbox := seedActiveSandbox(t, team, "capture-synthetic")
			generation := currentMiningGeneration(t)
			p := abuse.SandboxPolicy{TeamPolicy: abuse.TeamPolicy{TeamID: team, Known: true, Mode: abuse.ModeEnforce, Generation: generation}, SandboxID: sandbox, HostID: testDefaultHostID, HostIP: "192.0.2.19", Assignment: "captured-session"}
			i := abuse.MiningIncident{ID: uuid.New(), TeamID: team, SandboxID: sandbox, HostID: p.HostID, HostIP: p.HostIP, Assignment: p.Assignment, Generation: generation, ObservedAt: time.Now().UTC(), Evidence: abuse.MiningEvidence{Kind: "domain", Indicator: "pool.invalid"}}
			store := abuse.NewIncidentStore(testPool, p.HostID, miningAssignments{p})
			var releaseID uuid.UUID
			if transition == "delete-release" {
				prior := i
				prior.ID = uuid.New()
				r, err := store.RecordIncident(ctx, prior)
				if err != nil || r.Disposition != abuse.IncidentApplied {
					t.Fatalf("initial restriction: %+v %v", r, err)
				}
				releaseID = r.RestrictionID
			}
			dir := t.TempDir()
			delivery, err := mining.NewDelivery(dir, 1, store, func(context.Context, abuse.MiningIncident, abuse.IncidentReceipt) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			if err := delivery.Submit(i); err != nil {
				t.Fatalf("capture: %v", err)
			}

			var sql string
			switch transition {
			case "pause":
				sql = `UPDATE sandbox SET status='paused' WHERE id=$1`
			case "migrate":
				sql = `UPDATE sandbox SET host_id='migrated-synthetic-host' WHERE id=$1`
			default:
				sql = `UPDATE sandbox SET destroyed_at=now() WHERE id=$1`
			}
			if _, err := testPool.Exec(ctx, sql, sandbox); err != nil {
				t.Fatal(err)
			}
			want := abuse.IncidentApplied
			switch transition {
			case "delete-trust":
				if _, err := testPool.Exec(ctx, `INSERT INTO abuse_team_trust(team_id,verified) VALUES($1,true)`, team); err != nil {
					t.Fatal(err)
				}
				want = abuse.IncidentExempt
			case "delete-release":
				actor := seedPlatformAdminProfile(t)
				response := doInternal(newInternalRouter(t), http.MethodPost, "/internal/abuse/restrictions/"+releaseID.String()+"/release", actor.String(), "")
				if response.Code != http.StatusNoContent {
					t.Fatalf("release: %d %s", response.Code, response.Body.String())
				}
				want = abuse.IncidentIgnored
			case "delete-off":
				if _, err := testPool.Exec(ctx, `UPDATE abuse_runtime_settings SET mode='off'`); err != nil {
					t.Fatal(err)
				}
				want = abuse.IncidentIgnored
			}
			replacement := p
			replacement.SandboxID, replacement.TeamID, replacement.Assignment = uuid.New(), replacementTeam, "replacement-session"
			source := retiredMiningAssignment{miningAssignments{replacement}}
			store = abuse.NewIncidentStore(testPool, p.HostID, source)
			// The same fresh, unmarked claim must still fail after retirement.
			if _, err := store.RecordIncident(ctx, i); !errors.Is(err, abuse.ErrInvalidIncident) {
				t.Fatalf("fresh retired claim accepted: %v", err)
			}
			received := make(chan abuse.IncidentReceipt, 1)
			delivery, err = mining.NewDelivery(dir, 1, store, func(ctx context.Context, got abuse.MiningIncident, r abuse.IncidentReceipt) error {
				if got != i {
					return errors.New("durable body changed")
				}
				received <- r
				return mining.ErrLocalCleanupComplete
			})
			if err != nil {
				t.Fatal(err)
			}
			runCtx, cancel := context.WithCancel(ctx)
			done := make(chan struct{})
			go func() { defer close(done); delivery.Run(runCtx) }()
			t.Cleanup(func() { cancel(); <-done })
			var receipt abuse.IncidentReceipt
			select {
			case receipt = <-received:
			case <-time.After(10 * time.Second):
				t.Fatal("captured observation did not replay")
			}
			cancel()
			<-done
			if receipt.Disposition != want {
				t.Fatalf("replay disposition %+v, want %s", receipt, want)
			}
			if delivery.Pending() != 0 {
				t.Fatal("historical receipt leaked retired spool capacity")
			}
			var victim uuid.UUID
			if err := testPool.QueryRow(ctx, `SELECT team_id FROM abuse_mining_incidents WHERE id=$1`, i.ID).Scan(&victim); err != nil || victim != team {
				t.Fatalf("original victim lost: %s %v", victim, err)
			}
			var active, replacementRestrictions int
			if err := testPool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE subject_team_id=$1 AND released_at IS NULL),count(*) FILTER (WHERE subject_team_id=$2) FROM abuse_restrictions WHERE subject_team_id IN ($1,$2)`, team, replacementTeam).Scan(&active, &replacementRestrictions); err != nil {
				t.Fatal(err)
			}
			wantActive := 0
			if want == abuse.IncidentApplied {
				wantActive = 1
			}
			if active != wantActive || replacementRestrictions != 0 {
				t.Fatalf("wrong quarantine victims: original=%d replacement=%d", active, replacementRestrictions)
			}
		})
	}
}

func TestMiningCapturedReplayRetainsContradictoryOwnership(t *testing.T) {
	ctx := context.Background()
	team := mustCreateTeam(t, ctx, "capture-owner-"+uuid.NewString()[:8])
	otherTeam := mustCreateTeam(t, ctx, "capture-other-"+uuid.NewString()[:8])
	sandbox := seedActiveSandbox(t, team, "capture-owner")
	p := abuse.SandboxPolicy{TeamPolicy: abuse.TeamPolicy{TeamID: team, Known: true, Mode: abuse.ModeEnforce}, SandboxID: sandbox, HostID: testDefaultHostID, HostIP: "192.0.2.20", Assignment: "original"}
	i := abuse.MiningIncident{ID: uuid.New(), TeamID: team, SandboxID: sandbox, HostID: p.HostID, HostIP: p.HostIP, Assignment: p.Assignment, ObservedAt: time.Now(), Evidence: abuse.MiningEvidence{Kind: "domain", Indicator: "pool.invalid"}}
	store := abuse.NewIncidentStore(testPool, p.HostID, miningAssignments{p})
	capture, err := store.CaptureObservation(i)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE sandbox SET team_id=$2 WHERE id=$1`, sandbox, otherTeam); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordCapturedIncident(ctx, i, capture); err == nil || errors.Is(err, abuse.ErrInvalidIncident) {
		t.Fatalf("contradictory history acknowledged or permanently discarded: %v", err)
	}
	var count int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM abuse_mining_incidents WHERE id=$1`, i.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("contradiction created a receipt: %d %v", count, err)
	}
}
