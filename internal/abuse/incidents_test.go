package abuse

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"testing"
	"time"
)

func TestMiningIncidentDigestBindsEvidenceAndVictim(t *testing.T) {
	i := MiningIncident{ID: uuid.New(), TeamID: uuid.New(), SandboxID: uuid.New(), HostID: "host-test", HostIP: "192.0.2.3", Assignment: "assignment-test", ObservedAt: time.Now(), Evidence: MiningEvidence{Kind: "domain", Indicator: "pool.invalid"}}
	original, err := incidentDigest(i)
	if err != nil {
		t.Fatal(err)
	}
	copy := i
	copy.ObservedAt = i.ObservedAt.In(time.FixedZone("test", 3600))
	same, err := incidentDigest(copy)
	if err != nil || same != original {
		t.Fatal("time zone changed stable digest")
	}
	for _, mutate := range []func(*MiningIncident){func(i *MiningIncident) { i.TeamID = uuid.New() }, func(i *MiningIncident) { i.Assignment = "another" }, func(i *MiningIncident) { i.Evidence.Indicator = "mirror.invalid" }} {
		copy := i
		mutate(&copy)
		other, err := incidentDigest(copy)
		if err != nil || other == original {
			t.Fatal("changed incident body reused digest")
		}
	}
	i.HostIP = "guest-controlled-label"
	if _, err := incidentDigest(i); err == nil {
		t.Fatal("invalid host address accepted")
	}
}

type incidentTestRow struct{ err error }

func (r incidentTestRow) Scan(...any) error { return r.err }

type incidentTestTx struct{ pgx.Tx }

func (tx incidentTestTx) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}
func (tx incidentTestTx) QueryRow(context.Context, string, ...any) pgx.Row {
	return incidentTestRow{pgx.ErrNoRows}
}
func (tx incidentTestTx) Rollback(context.Context) error { return nil }

type incidentTestPool struct{}

func (incidentTestPool) Begin(context.Context) (pgx.Tx, error) { return incidentTestTx{}, nil }

type incidentTestAttribution struct {
	retired bool
	known   bool
	policy  SandboxPolicy
}

func (s *incidentTestAttribution) MiningPolicy(uuid.UUID, string) (SandboxPolicy, bool) {
	return s.policy, s.known
}
func (s *incidentTestAttribution) AssignmentRetired(MiningIncident) bool { return s.retired }
func TestMiningUnknownAttributionRetriesUntilRetirementProven(t *testing.T) {
	i := MiningIncident{ID: uuid.New(), TeamID: uuid.New(), SandboxID: uuid.New(), HostID: "host-test", HostIP: "192.0.2.4", Assignment: "original", ObservedAt: time.Now(), Evidence: MiningEvidence{Kind: "domain", Indicator: "pool.invalid"}}
	source := &incidentTestAttribution{}
	store := NewIncidentStore(incidentTestPool{}, i.HostID, source)
	for n := 0; n < 2; n++ {
		if _, err := store.RecordIncident(context.Background(), i); err == nil || errors.Is(err, ErrInvalidIncident) {
			t.Fatalf("unknown attribution was acknowledged or discarded: %v", err)
		}
	}
	source.retired = true
	if _, err := store.RecordIncident(context.Background(), i); !errors.Is(err, ErrInvalidIncident) {
		t.Fatalf("confirmed retirement was not terminal: %v", err)
	}
	source.retired = false
	source.known = true
	source.policy = SandboxPolicy{TeamPolicy: TeamPolicy{TeamID: i.TeamID}, HostID: i.HostID, Assignment: "different"}
	if _, err := store.RecordIncident(context.Background(), i); !errors.Is(err, ErrInvalidIncident) {
		t.Fatalf("known different assignment was not terminal: %v", err)
	}
}

func TestMiningCaptureRequiresExactLiveAttributionAndBindsReplayBody(t *testing.T) {
	i := MiningIncident{ID: uuid.New(), TeamID: uuid.New(), SandboxID: uuid.New(), HostID: "host-test", HostIP: "192.0.2.4", Assignment: "original", Generation: 7, ObservedAt: time.Now(), Evidence: MiningEvidence{Kind: "domain", Indicator: "pool.invalid"}}
	policy := SandboxPolicy{TeamPolicy: TeamPolicy{TeamID: i.TeamID, Known: true, Mode: ModeEnforce, Generation: i.Generation}, SandboxID: i.SandboxID, HostID: i.HostID, HostIP: i.HostIP, Assignment: i.Assignment}
	source := &incidentTestAttribution{known: true, policy: policy}
	store := NewIncidentStore(incidentTestPool{}, i.HostID, source)
	capture, err := store.CaptureObservation(i)
	if err != nil || capture == "" {
		t.Fatalf("capture failed: %v", err)
	}
	for _, mutate := range []func(*MiningIncident){
		func(i *MiningIncident) { i.TeamID = uuid.New() },
		func(i *MiningIncident) { i.SandboxID = uuid.New() },
		func(i *MiningIncident) { i.HostID = "foreign" },
		func(i *MiningIncident) { i.HostIP = "192.0.2.9" },
		func(i *MiningIncident) { i.Assignment = "replacement" },
		func(i *MiningIncident) { i.Generation++ },
		func(i *MiningIncident) { i.Evidence.Indicator = "changed.invalid" },
	} {
		changed := i
		mutate(&changed)
		if _, err := store.RecordCapturedIncident(context.Background(), changed, capture); !errors.Is(err, ErrInvalidIncident) {
			t.Fatalf("capture accepted changed body: %v", err)
		}
	}
	for _, badCapture := range []string{"", "v2:" + capture[3:], "v1:corrupt"} {
		if _, err := store.RecordCapturedIncident(context.Background(), i, badCapture); !errors.Is(err, ErrInvalidIncident) {
			t.Fatalf("invalid capture accepted: %v", err)
		}
	}
	foreign := NewIncidentStore(incidentTestPool{}, "foreign", source)
	if _, err := foreign.RecordCapturedIncident(context.Background(), i, capture); !errors.Is(err, ErrInvalidIncident) {
		t.Fatalf("capture transferred to foreign host: %v", err)
	}
	for _, mutate := range []func(*SandboxPolicy){
		func(p *SandboxPolicy) { p.Known = false },
		func(p *SandboxPolicy) { p.Trusted = true },
		func(p *SandboxPolicy) { p.Mode = ModeObserve },
		func(p *SandboxPolicy) { p.TeamID = uuid.New() },
		func(p *SandboxPolicy) { p.SandboxID = uuid.New() },
		func(p *SandboxPolicy) { p.HostID = "foreign" },
		func(p *SandboxPolicy) { p.HostIP = "192.0.2.9" },
		func(p *SandboxPolicy) { p.Assignment = "replacement" },
		func(p *SandboxPolicy) { p.Generation-- },
	} {
		source.policy = policy
		mutate(&source.policy)
		if _, err := store.CaptureObservation(i); !errors.Is(err, ErrInvalidIncident) {
			t.Fatalf("fresh invalid attribution captured: %v", err)
		}
	}
	source.policy = policy
	source.policy.Generation++
	if _, err := store.CaptureObservation(i); err != nil {
		t.Fatalf("later policy publication erased observation: %v", err)
	}
	source.known = false
	source.retired = true
	if _, err := store.CaptureObservation(i); !errors.Is(err, ErrInvalidIncident) {
		t.Fatalf("retired fresh claim captured: %v", err)
	}
	// The test transaction has no retained sandbox row. Valid historical
	// evidence must remain retryable instead of being discarded as invalid.
	if _, err := store.RecordCapturedIncident(context.Background(), i, capture); err == nil || errors.Is(err, ErrInvalidIncident) {
		t.Fatalf("missing history acknowledged or permanently discarded: %v", err)
	}
}
