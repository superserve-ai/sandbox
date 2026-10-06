package vm

import "testing"

func TestMachineRepairOwnershipAttestation(t *testing.T) {
	if got := ownershipState(true, "principal", ""); got != "machine" {
		t.Fatalf("machine attestation = %q", got)
	}
	if got := ownershipState(false, "", "creator"); got != "ordinary" {
		t.Fatalf("server-attested ordinary record = %q", got)
	}
	if got := ownershipState(false, "", ""); got != "unknown" {
		t.Fatalf("unattested record = %q, want unknown", got)
	}
}
