package vm

import (
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"

	fcmodels "github.com/superserve-ai/sandbox/internal/vm/fc/models"
)

// fakeFC serves the DescribeInstance endpoint on a unix socket, answering
// with the given state — the same wire shape a real Firecracker produces.
func fakeFC(t *testing.T, state string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "firecracker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"x","state":"`+state+`","vmm_version":"1.15.0","app_name":"Firecracker"}`)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

func TestVMState_DistinguishesShellFromRunning(t *testing.T) {
	shell := fakeFC(t, fcmodels.InstanceInfoStateNotStarted)
	got, err := VMState(context.Background(), shell)
	if err != nil || got != fcmodels.InstanceInfoStateNotStarted {
		t.Fatalf("shell probe = %q, %v; want %q", got, err, fcmodels.InstanceInfoStateNotStarted)
	}
	if !fcReportsEmptyShell(context.Background(), shell) {
		t.Error("fcReportsEmptyShell = false for a Not started FC, want true")
	}

	running := fakeFC(t, fcmodels.InstanceInfoStateRunning)
	got, err = VMState(context.Background(), running)
	if err != nil || got != fcmodels.InstanceInfoStateRunning {
		t.Fatalf("running probe = %q, %v; want %q", got, err, fcmodels.InstanceInfoStateRunning)
	}
	if fcReportsEmptyShell(context.Background(), running) {
		t.Error("fcReportsEmptyShell = true for a Running FC, want false")
	}
}

func TestFcReportsEmptyShell_ProbeErrorIsNotEvidence(t *testing.T) {
	// No listener at all — a dead socket must read as "not a shell", never
	// as evidence for destructive action.
	if fcReportsEmptyShell(context.Background(), filepath.Join(t.TempDir(), "absent.sock")) {
		t.Error("fcReportsEmptyShell = true on probe error, want false")
	}
}
