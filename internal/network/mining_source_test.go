package network

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/abuse"
)

func TestMiningRetirementRequiresAuthoritativeOwnership(t *testing.T) {
	p := NewEgressProxy(0, 0, 0, 10, zerolog.Nop())
	team, id := uuid.New(), uuid.New()
	source := NewHostMiningSource(nil, &kernelTestTeams{id: team}, p, "host-test", "boot-test")
	policy := abuse.SandboxPolicy{TeamPolicy: abuse.TeamPolicy{TeamID: team}, SandboxID: id, HostIP: "10.11.0.2", HostID: "host-test", Assignment: "a"}
	i := abuse.MiningIncident{ID: uuid.New(), TeamID: team, SandboxID: id, HostIP: policy.HostIP, HostID: policy.HostID, Assignment: policy.Assignment}
	if source.AssignmentRetired(i) {
		t.Fatal("cold source falsely retired incident")
	}
	assignments := miningAssignments{id: policy}
	source.cur.Store(&assignments)
	if source.AssignmentRetired(i) {
		t.Fatal("unready local registration falsely retired incident")
	}
	gate := &miningTestGate{on: make(map[string]bool)}
	c := NewMiningContainment(source, gate, &miningTestSubmit{}, zerolog.Nop())
	if err := c.Receipt(context.Background(), i, abuse.IncidentReceipt{Disposition: abuse.IncidentApplied}); err != nil {
		t.Fatalf("unready source prematurely discarded durable receipt: %v", err)
	}
	retired := make(miningAssignments)
	source.cur.Store(&retired)
	if err := c.Receipt(context.Background(), i, abuse.IncidentReceipt{Disposition: abuse.IncidentApplied}); err != abuse.ErrMiningLocalCleanupComplete {
		t.Fatalf("retired assignment did not release local capacity: %v", err)
	}
}

// A real SQL projection test catches paused historical rows filling the host
// assignment bound and prevents an unfinished pause from retiring early.
func TestMiningHostProjectionRetiresPausedHistory(t *testing.T) {
	dsn := os.Getenv("MINING_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `CREATE TEMP TABLE sandbox(id uuid,team_id uuid,host_id text,ip_address inet,routing_version bigint,status text,destroyed_at timestamptz,pause_op_id uuid)`)
	if err != nil {
		t.Fatal(err)
	}
	team, active, pausing, paused := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	_, err = tx.Exec(ctx, `INSERT INTO sandbox(id,team_id,host_id,ip_address,routing_version,status,pause_op_id) VALUES ($1,$4,'host-test','10.11.0.2',1,'active',NULL),($2,$4,'host-test','10.11.0.3',1,'pausing',$2),($3,$4,'host-test','10.11.0.4',1,'paused',NULL)`, active, pausing, paused, team)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO sandbox(id,team_id,host_id,ip_address,routing_version,status) SELECT md5(n::text)::uuid,$1,'host-test','10.11.0.5',1,'paused' FROM generate_series(1,$2) AS n`, team, MaxSlots+1)
	if err != nil {
		t.Fatal(err)
	}
	source := NewHostMiningSource(tx, &kernelTestTeams{id: team}, NewEgressProxy(0, 0, 0, 10, zerolog.Nop()), "host-test", "boot-test")
	incarnation := "first-instance"
	source.SetIncarnationResolver(func(uuid.UUID) (string, bool) { return incarnation, true })
	if err := source.Refresh(ctx); err != nil {
		t.Fatalf("paused history exhausted live assignment projection: %v", err)
	}
	if got := len(*source.cur.Load()); got != 2 {
		t.Fatalf("projected %d assignments; want active and incomplete pause only", got)
	}
	for _, id := range []uuid.UUID{active, pausing} {
		p := (*source.cur.Load())[id]
		i := abuse.MiningIncident{SandboxID: id, TeamID: team, HostID: p.HostID, HostIP: p.HostIP, Assignment: p.Assignment}
		if source.AssignmentRetired(i) {
			t.Fatal("live/unfinished assignment retired")
		}
	}
	if !source.AssignmentRetired(abuse.MiningIncident{SandboxID: paused, TeamID: team, HostID: "host-test", HostIP: "10.11.0.4"}) {
		t.Fatal("completed pause retained historical receipt")
	}
	first := (*source.cur.Load())[active]
	if err := source.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if (*source.cur.Load())[active].Assignment != first.Assignment {
		t.Fatal("stable reattachment changed persisted incarnation")
	}
	incarnation = "replacement-instance"
	if err := source.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if (*source.cur.Load())[active].Assignment == first.Assignment {
		t.Fatal("same sandbox/IP replacement reused assignment")
	}
	if !source.AssignmentRetired(abuse.MiningIncident{SandboxID: active, TeamID: team, HostID: first.HostID, HostIP: first.HostIP, Assignment: first.Assignment}) {
		t.Fatal("replaced incarnation not retired")
	}

}

func TestMiningSameSandboxReRegistrationInvalidatesPublishedAssignment(t *testing.T) {
	proxy := NewEgressProxy(0, 0, 0, 10, zerolog.Nop())
	team, id := uuid.New(), uuid.New()
	ip := "10.11.0.2"
	proxy.RegisterSandbox(ip, id.String())
	_, original := proxy.miningRegistration(ip)
	source := NewHostMiningSource(nil, &kernelTestTeams{id: team}, proxy, "host-test", "boot-test")
	policy := abuse.SandboxPolicy{TeamPolicy: abuse.TeamPolicy{TeamID: team}, SandboxID: id, HostIP: ip, HostID: "host-test", Assignment: "persisted-instance-time"}
	source.ready.Store(&miningReady{policies: miningAssignments{id: policy}, bindings: map[uuid.UUID]*EgressRules{id: original}})
	if _, known := source.MiningPolicy(id, ip); !known {
		t.Fatal("initial assignment not ready")
	}
	proxy.RegisterSandbox(ip, id.String())
	if _, known := source.MiningPolicy(id, ip); !known {
		t.Fatal("idempotent registration invalidated assignment")
	}
	proxy.RemoveRules(ip)
	proxy.RegisterSandbox(ip, id.String())
	if _, known := source.MiningPolicy(id, ip); known {
		t.Fatal("same sandbox/IP replacement inherited retired assignment before refresh")
	}
}

func TestMiningClosesPrePolicyStreamsWithoutClosingReusedRegistration(t *testing.T) {
	proxy := NewEgressProxy(0, 0, 0, 10, zerolog.Nop())
	proxy.EnableMiningStreamTracking()
	team, id := uuid.New(), uuid.New()
	ip := "10.11.0.2"
	proxy.RegisterSandbox(ip, id.String())
	_, registration := proxy.miningRegistration(ip)
	early, peer := net.Pipe()
	defer peer.Close()
	done := proxy.trackEarlyMining(ip, id.String(), registration, early)
	defer done()
	source := NewHostMiningSource(nil, &kernelTestTeams{id: team}, proxy, "host-test", "boot-test")
	policy := abuse.SandboxPolicy{TeamPolicy: abuse.TeamPolicy{TeamID: team}, SandboxID: id, HostIP: ip, HostID: "host-test", Assignment: "persisted-instance-time"}
	source.ready.Store(&miningReady{policies: miningAssignments{id: policy}, bindings: map[uuid.UUID]*EgressRules{id: registration}})
	controller := NewMiningContainment(source, &miningTestGate{on: make(map[string]bool)}, &miningTestSubmit{}, zerolog.Nop())
	if !controller.Observe(id, ip, abuse.MiningEvidence{}) {
		t.Fatal("mining hit not contained")
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("stream accepted before policy was not closed: %v", err)
	}
	proxy.RemoveRules(ip)
	proxy.RegisterSandbox(ip, id.String())
	_, replacement := proxy.miningRegistration(ip)
	fresh, freshPeer := net.Pipe()
	defer fresh.Close()
	defer freshPeer.Close()
	freshDone := proxy.trackEarlyMining(ip, id.String(), replacement, fresh)
	defer freshDone()
	source.CloseMiningStreams(policy)
	freshPeer.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := freshPeer.Read(make([]byte, 1)); errors.Is(err, io.EOF) {
		t.Fatal("old closer disconnected replacement registration")
	}
}
