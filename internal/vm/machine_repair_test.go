package vm

import (
	"encoding/json"
	"testing"
	"time"
)

func TestMachineRepairOwnershipAttestation(t *testing.T) {
	testMachineRepairResourceOwnershipRecovery(t)
}

func TestMachineRepairResourceOwnershipRecovery(t *testing.T) {
	testMachineRepairResourceOwnershipRecovery(t)
}

func testMachineRepairResourceOwnershipRecovery(t *testing.T) {
	if got := ownershipState(true, "principal", ""); got != "machine" {
		t.Fatalf("machine attestation = %q", got)
	}
	if got := ownershipState(false, "", "creator"); got != "ordinary" {
		t.Fatalf("server-attested ordinary record = %q", got)
	}
	if got := ownershipState(false, "", ""); got != "unknown" {
		t.Fatalf("unattested record = %q, want unknown", got)
	}
	if got := ownershipState(true, "", "creator"); got != "unknown" {
		t.Fatalf("incomplete machine attestation = %q, want unknown", got)
	}

	original := &VMInstance{ID: "machine-repair-vm", TeamID: "team", OwnerID: "", MachineOwned: true, MachineOwnerPrincipalID: "principal", CreatedAt: time.Unix(123, 0)}
	record := toRecord(original)
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal machine record: %v", err)
	}
	var decoded VMRecord
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal machine record: %v", err)
	}
	restored := toInstance(decoded)
	if !restored.MachineOwned || restored.MachineOwnerPrincipalID != original.MachineOwnerPrincipalID || restored.OwnerID != "" {
		t.Fatalf("machine ownership lost across persistence: %#v", restored)
	}

	// Revival copies the durable attestation, not a human creator owner.
	revived := &VMInstance{OwnerID: "creator"}
	restoreOwnershipFromRecord(revived, &record)
	if !revived.MachineOwned || revived.MachineOwnerPrincipalID != "principal" || revived.OwnerID != "" {
		t.Fatalf("human-triggered restore changed machine owner: %#v", revived)
	}
	unknown := &VMInstance{OwnerID: "creator"}
	restoreOwnershipFromRecord(unknown, &VMRecord{MachineOwned: true, OwnerID: "creator"})
	if ownershipState(unknown.MachineOwned, unknown.MachineOwnerPrincipalID, unknown.OwnerID) != "unknown" {
		t.Fatal("incomplete restored machine attestation became ordinary ownership")
	}
}
