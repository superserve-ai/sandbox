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
