package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/auth"
)

type repairAuthority struct {
	principal, credential uuid.UUID
	deadline              time.Time
	fail                  bool
}

func (a *repairAuthority) Lookup(context.Context, uuid.UUID, uuid.UUID) (uint64, error) {
	if a.fail {
		return 0, context.DeadlineExceeded
	}
	return 1, nil
}
func (a *repairAuthority) LookupSnapshot(context.Context, uuid.UUID, uuid.UUID) (uint64, time.Time, error) {
	if a.fail {
		return 0, time.Time{}, context.DeadlineExceeded
	}
	return 1, a.deadline, nil
}
func (a *repairAuthority) RefreshSnapshot(context.Context, uuid.UUID, uuid.UUID) (uint64, time.Time, error) {
	if a.fail {
		return 0, time.Time{}, context.DeadlineExceeded
	}
	a.deadline = time.Now().Add(80 * time.Millisecond)
	return 1, a.deadline, nil
}

func repairCapability(t *testing.T, key []byte, principal, credential uuid.UUID, exp time.Time) (string, uuid.UUID, uuid.UUID) {
	t.Helper()
	capability := auth.MachineCapability{PrincipalID: principal, CredentialID: credential, LineageID: uuid.New(), TeamID: uuid.New(), SandboxID: uuid.New(), Operations: []auth.MachineOperation{auth.MachineOperationCommandRun}, Audience: "sandbox-proxy", ExpiresAt: exp, RevocationGeneration: 1}
	token, err := auth.SignMachineCapability(capability, key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return token, principal, credential
}

func TestMachineRepairActiveTransports(t *testing.T) {
	key := []byte("repair-proxy-key-0123456789012345")
	a := &repairAuthority{deadline: time.Now().Add(time.Minute)}
	h := NewHandler(nil, nil, zerolog.Nop()).WithAuth(key)
	h.machineAuthority = a.Lookup
	h.machineAuthoritySnapshotter = a
	token, principal, credential := repairCapability(t, key, uuid.New(), uuid.New(), time.Now().Add(time.Minute))
	ctx, cleanup, ok := h.machineSessionContext(context.Background(), token)
	if !ok {
		t.Fatal("session admission failed")
	}
	defer cleanup()
	h.RevokeMachineCredential(credential, 1)
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("active stream was not cancelled")
	}
	_ = principal
}

func TestMachineRepairAuthorityFreshness(t *testing.T) {
	key := []byte("repair-proxy-key-0123456789012345")
	a := &repairAuthority{deadline: time.Now().Add(40 * time.Millisecond)}
	h := NewHandler(nil, nil, zerolog.Nop()).WithAuth(key)
	h.machineAuthority = a.Lookup
	h.machineAuthoritySnapshotter = a
	token, _, _ := repairCapability(t, key, uuid.New(), uuid.New(), time.Now().Add(time.Second))
	ctx, cleanup, ok := h.machineSessionContext(context.Background(), token)
	if !ok {
		t.Fatal("session admission failed")
	}
	defer cleanup()
	a.fail = true
	select {
	case <-ctx.Done():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("stream remained alive after freshness failure")
	}
}

func TestMachineRepairOwnershipAndHumanAccess(t *testing.T) {
	capability, err := auth.DeriveHumanCapability(uuid.New(), uuid.New(), uuid.New(), "sandbox-proxy", []auth.MachineOperation{auth.MachineOperationRead}, time.Now().Add(time.Minute), time.Now())
	if err != nil || capability.CallerKind != "human" {
		t.Fatalf("human capability = %#v, err=%v", capability, err)
	}
}

func TestMachineRepairProactiveAuthorityRefresh(t *testing.T) {
	key := []byte("repair-proactive-key-01234567890")
	a := &repairAuthority{deadline: time.Now().Add(120 * time.Millisecond)}
	h := NewHandler(nil, nil, zerolog.Nop()).WithAuth(key)
	h.machineAuthority = a.Lookup
	h.machineAuthoritySnapshotter = a
	token, _, _ := repairCapability(t, key, uuid.New(), uuid.New(), time.Now().Add(time.Second))
	ctx, cleanup, ok := h.machineSessionContext(context.Background(), token)
	if !ok {
		t.Fatal("session admission failed")
	}
	defer cleanup()
	time.Sleep(250 * time.Millisecond)
	select {
	case <-ctx.Done():
		t.Fatal("healthy authority was closed at the original freshness deadline")
	default:
	}
	a.fail = true
	select {
	case <-ctx.Done():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("session did not enforce the absolute freshness deadline")
	}
}

func TestMachineRepairTypedTransportLifetimes(t *testing.T) {
	key := []byte("repair-human-expiry-key-01234567")
	now := time.Now()
	capability, err := auth.DeriveHumanCapability(uuid.New(), uuid.New(), uuid.New(), "sandbox-proxy", []auth.MachineOperation{auth.MachineOperationCommandRun}, now.Add(40*time.Millisecond), now)
	if err != nil {
		t.Fatal(err)
	}
	token, err := auth.SignMachineCapability(capability, key, now)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(nil, nil, zerolog.Nop()).WithAuth(key)
	ctx, cleanup, ok := h.machineSessionContext(context.Background(), token)
	if !ok {
		t.Fatal("human typed capability admission failed")
	}
	defer cleanup()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("typed human transport outlived capability expiry")
	}
}

func TestMachineRepairVerifiedDenialContext(t *testing.T) {
	caller := callerContextFromCapability(auth.MachineCapability{PrincipalID: uuid.New(), CredentialID: uuid.New(), LineageID: uuid.New(), TeamID: uuid.New(), Audience: "sandbox-proxy", ExpiresAt: time.Now().Add(time.Minute), RevocationGeneration: 1, Operations: []auth.MachineOperation{auth.MachineOperationRead}})
	if caller == nil || caller.PrincipalID == uuid.Nil || caller.CredentialID == uuid.Nil || caller.LineageID == uuid.Nil {
		t.Fatal("verified caller references were not preserved for denial")
	}
}
