//go:build linux

package vm

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestSavedSnapshotFirecrackerHelperProcess(t *testing.T) {
	if os.Getenv("SUPERSERVE_TEST_FIRECRACKER_HELPER") != "1" {
		return
	}
	for {
		time.Sleep(time.Minute)
	}
}

func TestStopVMProcessAndConfirmKillsExactFirecrackerIdentity(t *testing.T) {
	installInactiveSystemctl(t)
	vmID := "saved-snapshot-containment-test"
	cmd := exec.Command(os.Args[0], "-test.run=TestSavedSnapshotFirecrackerHelperProcess", "--", "--id", vmID)
	cmd.Args[0] = "firecracker"
	cmd.Env = append(os.Environ(), "SUPERSERVE_TEST_FIRECRACKER_HELPER=1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	}()

	deadline := time.Now().Add(3 * time.Second)
	for !pidIsVMFirecracker(cmd.Process.Pid, vmID) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !pidIsVMFirecracker(cmd.Process.Pid, vmID) {
		t.Fatalf("helper pid %d never acquired exact Firecracker identity", cmd.Process.Pid)
	}

	mgr := &Manager{log: zerolog.Nop()}
	inst := &VMInstance{ID: vmID, PID: cmd.Process.Pid}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, err := mgr.stopVMProcessAndConfirm(ctx, vmID, inst)
	cancel()
	if err != nil {
		t.Fatalf("stopVMProcessAndConfirm: %v", err)
	}
	if pidIsVMFirecracker(cmd.Process.Pid, vmID) {
		t.Fatalf("exact Firecracker process %d remains after containment", cmd.Process.Pid)
	}
	if remaining, err := vmFirecrackerPIDs(vmID); err != nil {
		t.Fatalf("scan remaining Firecracker processes: %v", err)
	} else if len(remaining) != 0 {
		t.Fatalf("remaining Firecracker pids: %v", remaining)
	}
}

func TestSavedRestoreRetryRetainsTargetWhenProcessStopIsInconclusive(t *testing.T) {
	binDir := t.TempDir()
	systemctl := filepath.Join(binDir, "systemctl")
	if err := os.WriteFile(systemctl, []byte(`#!/bin/sh
case "$1" in
  stop) echo synthetic-stop-failure >&2; exit 1 ;;
  is-active) echo active; exit 0 ;;
  *) exit 0 ;;
esac
`), 0o755); err != nil {
		t.Fatalf("write fake systemctl: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	vmID := "saved-restore-inconclusive-test"
	runDir := t.TempDir()
	diskPath := filepath.Join(runDir, vmID, "rootfs.ext4")
	if err := os.MkdirAll(filepath.Dir(diskPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(diskPath, []byte("retain-me"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshotPath := filepath.Join(t.TempDir(), "vmstate.snap")
	memPath := filepath.Join(t.TempDir(), "mem.snap")
	if err := os.WriteFile(snapshotPath, []byte("snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(memPath, []byte("memory"), 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open state store: %v", err)
	}
	defer state.Close()

	inst := &VMInstance{
		ID:        vmID,
		Status:    StatusCreating,
		RunDirID:  vmID,
		DiskPath:  diskPath,
		CreatedAt: time.Now(),
	}
	mgr := &Manager{
		cfg:        ManagerConfig{RunDir: runDir},
		log:        zerolog.Nop(),
		state:      state,
		vms:        map[string]*VMInstance{vmID: inst},
		restoreSem: make(chan struct{}, 1),
	}

	_, err = mgr.RestoreVMSnapshot(context.Background(), vmID, snapshotPath, memPath, VMConfig{
		RootfsPath:           diskPath,
		savedSnapshotRestore: true,
	}, nil, "team", "owner", "", nil, 0)
	if err == nil {
		t.Fatal("saved restore retry unexpectedly proceeded after inconclusive process stop")
	}
	if _, err := os.Stat(diskPath); err != nil {
		t.Fatalf("inconclusive containment removed provisional disk: %v", err)
	}
	mgr.mu.RLock()
	tracked := mgr.vms[vmID]
	mgr.mu.RUnlock()
	if tracked != inst {
		t.Fatal("inconclusive containment removed provisional VM")
	}
	inst.mu.RLock()
	statusAfter := inst.Status
	inst.mu.RUnlock()
	if statusAfter != StatusError {
		t.Fatalf("provisional status = %s, want error", statusAfter)
	}
	record, err := state.Get(vmID)
	if err != nil || record == nil || record.Status != StatusError {
		t.Fatalf("persisted retained target = %+v, %v", record, err)
	}
}
