package vm

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOwnershipRecoveryAttestation(t *testing.T) {
	const principal = "a7260779-855f-4ac6-9c31-25e5c659999a"
	cases := []struct {
		name                  string
		record                VMRecord
		state, owner, machine string
	}{
		{"recordless machine", VMRecord{OwnerID: "machine:" + principal}, "machine", "", principal},
		{"recordless ordinary", VMRecord{OwnerID: "ordinary:attested"}, "ordinary", "", ""},
		{"legacy creator", VMRecord{OwnerID: "creator"}, "ordinary", "creator", ""},
		{"missing", VMRecord{}, "unknown", "", ""},
		{"malformed machine", VMRecord{OwnerID: "machine:broken"}, "unknown", "", ""},
		{"empty machine", VMRecord{OwnerID: "machine:"}, "unknown", "", ""},
		{"zero machine", VMRecord{OwnerID: "machine:00000000-0000-0000-0000-000000000000"}, "unknown", "", ""},
		{"malformed ordinary", VMRecord{OwnerID: "ordinary:broken"}, "unknown", "", ""},
		{"durable machine wins", VMRecord{MachineOwned: true, MachineOwnerPrincipalID: principal, OwnerID: "creator"}, "machine", "", principal},
		{"incomplete durable machine", VMRecord{MachineOwned: true, OwnerID: "creator"}, "unknown", "", ""},
		{"contradictory", VMRecord{MachineOwned: true, MachineOwnerPrincipalID: principal, OrdinaryOwned: true}, "unknown", "", principal},
		{"malformed cannot downgrade", VMRecord{OwnerID: "machine:broken", OrdinaryOwned: true}, "unknown", "", ""},
		{"ordinary durable", VMRecord{OrdinaryOwned: true}, "ordinary", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inst := &VMInstance{OwnerID: "stale-creator", OrdinaryOwned: true}
			restoreOwnershipFromRecord(inst, &tc.record)
			assert := func(inst *VMInstance) {
				t.Helper()
				if got := ownershipState(inst.MachineOwned, inst.MachineOwnerPrincipalID, inst.OwnerID, inst.OrdinaryOwned); got != tc.state {
					t.Fatalf("state = %s, want %s", got, tc.state)
				}
				if inst.OwnerID != tc.owner || inst.MachineOwnerPrincipalID != tc.machine {
					t.Fatalf("owner = %q, machine = %q", inst.OwnerID, inst.MachineOwnerPrincipalID)
				}
			}
			assert(inst)
			encoded, err := json.Marshal(toRecord(inst))
			if err != nil {
				t.Fatal(err)
			}
			var persisted VMRecord
			if err = json.Unmarshal(encoded, &persisted); err != nil {
				t.Fatal(err)
			}
			assert(toInstance(persisted))
		})
	}
}

func TestRecoveredOwnershipLocalHTTP(t *testing.T) {
	for _, tc := range []struct{ marker, state string }{
		{"ordinary:attested", "ordinary"},
		{"machine:a7260779-855f-4ac6-9c31-25e5c659999a", "machine"},
		{"machine:invalid", "unknown"},
	} {
		t.Run(tc.state, func(t *testing.T) {
			m := newTestManager()
			m.vms = make(map[string]*VMInstance)
			inst := &VMInstance{ID: "ownership-recovery", Status: StatusRunning, IP: "10.0.0.2", TeamID: "team"}
			setOwnershipFromTrustedMarker(inst, tc.marker)
			m.vms[inst.ID] = toInstance(toRecord(inst))
			server := NewLocalHTTPServer(m, m.log)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/instances/"+inst.ID, nil)
			server.handleInstance(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			var response instanceResponse
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response.OwnershipState != tc.state || response.OwnerID != "" {
				t.Fatalf("response = %#v", response)
			}
		})
	}
}

func TestRecoveryRetryPreservesExplicitOwnership(t *testing.T) {
	for _, marker := range []string{"ordinary:attested", "machine:a7260779-855f-4ac6-9c31-25e5c659999a", "machine:broken"} {
		previous := &VMInstance{}
		setOwnershipFromTrustedMarker(previous, marker)
		rec := explicitOwnershipRecord(previous)
		replacement := &VMInstance{}
		setOwnershipFromTrustedMarker(replacement, "requesting-admin")
		restoreOwnershipFromRecord(replacement, rec)
		if replacement.OwnerID != previous.OwnerID || replacement.MachineOwned != previous.MachineOwned || replacement.OrdinaryOwned != previous.OrdinaryOwned || replacement.MachineOwnerPrincipalID != previous.MachineOwnerPrincipalID {
			t.Fatalf("retry changed %q ownership: %#v", marker, replacement)
		}
	}
}
