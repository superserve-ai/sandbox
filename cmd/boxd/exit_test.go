package main

import (
	"context"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"
)

func TestFinalExitCode_Normal(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "exit 7")
	if err := cmd.Run(); err == nil {
		t.Fatal("expected non-nil err for non-zero exit")
	}
	got := finalExitCode(cmd.ProcessState, false)
	if got != 7 {
		t.Errorf("finalExitCode = %d, want 7", got)
	}
}

func TestFinalExitCode_TimedOut(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sleep", "5")
	_ = cmd.Run()
	got := finalExitCode(cmd.ProcessState, true)
	if got != timeoutExitCode {
		t.Errorf("finalExitCode (timed out) = %d, want %d", got, timeoutExitCode)
	}
}

func TestFinalExitCode_SignalKilled(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill: %v", err)
	}
	_ = cmd.Wait()
	got := finalExitCode(cmd.ProcessState, false)
	if got != 137 {
		t.Errorf("finalExitCode (SIGKILL) = %d, want 137", got)
	}
}

func TestFinalExitCode_NilProcessState(t *testing.T) {
	if got := finalExitCode(nil, false); got != 0 {
		t.Errorf("finalExitCode(nil, false) = %d, want 0", got)
	}
	if got := finalExitCode(nil, true); got != timeoutExitCode {
		t.Errorf("finalExitCode(nil, true) = %d, want %d", got, timeoutExitCode)
	}
}

func TestStartTimeout_AtomicFlag(t *testing.T) {
	cmdCtx, cmdCancel := context.WithCancel(context.Background())
	defer cmdCancel()
	var timedOut atomic.Bool

	timer := time.AfterFunc(50*time.Millisecond, func() {
		timedOut.Store(true)
		cmdCancel()
	})
	defer timer.Stop()

	cmd := exec.CommandContext(cmdCtx, "/bin/sleep", "5")
	start := time.Now()
	_ = cmd.Run()
	elapsed := time.Since(start)

	if !timedOut.Load() {
		t.Error("timedOut flag was not set; timer didn't fire")
	}
	if elapsed > 1*time.Second {
		t.Errorf("cmd took %v; expected to be killed within ~50ms", elapsed)
	}
	got := finalExitCode(cmd.ProcessState, timedOut.Load())
	if got != timeoutExitCode {
		t.Errorf("finalExitCode = %d, want %d", got, timeoutExitCode)
	}
}
