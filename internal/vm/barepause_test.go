package vm

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mgrWith builds a Manager holding a single instance in the given status. The
// guard paths exercised below short-circuit before any Firecracker socket IO,
// so no real VM is needed.
func mgrWith(vmID string, st VMStatus) *Manager {
	return &Manager{vms: map[string]*VMInstance{
		vmID: {ID: vmID, Status: st, SocketPath: "/nonexistent.sock"},
	}}
}

// TestBarePauseGuards: PauseVMBare only acts on a running VM and is idempotent
// on an already-resident one; it refuses snapshot-paused/stopped VMs (whose
// firecracker socket is gone) rather than PATCHing a dead socket.
func TestBarePauseGuards(t *testing.T) {
	ctx := context.Background()

	// Already bare-paused → idempotent no-op.
	if err := mgrWith("a", StatusPausedResident).PauseVMBare(ctx, "a"); err != nil {
		t.Errorf("bare pause of resident VM should be a no-op, got %v", err)
	}

	// Snapshot-paused / stopped / errored → FailedPrecondition (no socket touch).
	for _, st := range []VMStatus{StatusPaused, StatusStopped, StatusError, StatusCreating} {
		err := mgrWith("a", st).PauseVMBare(ctx, "a")
		if status.Code(err) != codes.FailedPrecondition {
			t.Errorf("bare pause of %s VM should be FailedPrecondition, got %v", st, err)
		}
	}

	// Unknown VM → NotFound.
	if status.Code(mgrWith("a", StatusRunning).PauseVMBare(ctx, "ghost")) != codes.NotFound {
		t.Error("bare pause of unknown VM should be NotFound")
	}
}

// TestBareResumeGuards: ResumeVMBare only acts on a resident-paused VM and is
// idempotent on a running one; it refuses snapshot-paused VMs so they route to
// the snapshot-restore path instead of unpausing a dead socket (which would
// destructively evict the VM's snapshot pointers).
func TestBareResumeGuards(t *testing.T) {
	ctx := context.Background()

	// Already running → idempotent, returns the instance.
	inst, err := mgrWith("a", StatusRunning).ResumeVMBare(ctx, "a")
	if err != nil || inst == nil || inst.ID != "a" {
		t.Errorf("bare resume of running VM should return the instance, got inst=%v err=%v", inst, err)
	}

	// Snapshot-paused / stopped → FailedPrecondition (route to snapshot restore).
	for _, st := range []VMStatus{StatusPaused, StatusStopped, StatusError, StatusCreating} {
		_, err := mgrWith("a", st).ResumeVMBare(ctx, "a")
		if status.Code(err) != codes.FailedPrecondition {
			t.Errorf("bare resume of %s VM should be FailedPrecondition, got %v", st, err)
		}
	}

	// Unknown VM → NotFound.
	if _, err := mgrWith("a", StatusRunning).ResumeVMBare(ctx, "ghost"); status.Code(err) != codes.NotFound {
		t.Error("bare resume of unknown VM should be NotFound")
	}
}

// TestPausedResidentString locks the new status's display name.
func TestPausedResidentString(t *testing.T) {
	if StatusPausedResident.String() != "paused_resident" {
		t.Errorf("got %q", StatusPausedResident.String())
	}
}
