package main

import (
	"context"
	"sync"
	"syscall"
	"testing"
	"time"

	"connectrpc.com/connect"
	pb "github.com/superserve-ai/sandbox/proto/boxdpb"
)

// TestSendInput_NonPTYStdin verifies SendInput feeds a non-PTY process's stdin
// and that Eof closes it — cat echoes the input back and exits.
func TestSendInput_NonPTYStdin(t *testing.T) {
	s := newProcessService()

	var (
		mu     sync.Mutex
		stdout []byte
	)
	pidCh := make(chan uint32, 1)
	emit := func(ev *pb.ProcessEvent) error {
		switch x := ev.Event.(type) {
		case *pb.ProcessEvent_Start:
			pidCh <- x.Start.GetPid()
		case *pb.ProcessEvent_Data:
			if o := x.Data.GetStdout(); len(o) > 0 {
				mu.Lock()
				stdout = append(stdout, o...)
				mu.Unlock()
			}
		}
		return nil
	}

	done := make(chan error, 1)
	go func() {
		// `cat` echoes stdin to stdout. Cwd must exist or fork/exec fails.
		done <- s.runProcess(context.Background(), &pb.StartRequest{Cmd: "cat", Cwd: "/tmp"}, emit, true)
	}()

	var pid uint32
	select {
	case pid = <-pidCh:
	case err := <-done:
		t.Fatalf("runProcess returned before StartEvent: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for StartEvent")
	}

	// Write to stdin and signal EOF in one call — cat should echo and exit.
	if _, err := s.SendInput(context.Background(), connect.NewRequest(&pb.SendInputRequest{
		Pid:  pid,
		Data: []byte("hello stdin\n"),
		Eof:  true,
	})); err != nil {
		t.Fatalf("SendInput: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runProcess: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("process did not exit after stdin EOF")
	}

	mu.Lock()
	got := string(stdout)
	mu.Unlock()
	if got != "hello stdin\n" {
		t.Errorf("stdout = %q, want %q", got, "hello stdin\n")
	}
}

// TestRunProcess_NoStdinExitsOnEOF guards that a non-interactive exec
// (wantStdin=false) leaves stdin at /dev/null, so a stdin-reading command like
// `cat` sees EOF and exits instead of blocking until the timeout.
func TestRunProcess_NoStdinExitsOnEOF(t *testing.T) {
	s := newProcessService()
	done := make(chan error, 1)
	go func() {
		done <- s.runProcess(context.Background(), &pb.StartRequest{
			Cmd: "cat", Cwd: "/tmp",
		}, func(*pb.ProcessEvent) error { return nil }, false)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runProcess: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cat blocked on stdin; expected immediate EOF with wantStdin=false")
	}
}

// TestSignal_TerminatesShellCommand guards that Signal terminates a non-PTY
// shell-wrapped command.
func TestSignal_TerminatesShellCommand(t *testing.T) {
	s := newProcessService()
	pidCh := make(chan uint32, 1)
	emit := func(ev *pb.ProcessEvent) error {
		if st := ev.GetStart(); st != nil {
			pidCh <- st.GetPid()
		}
		return nil
	}
	done := make(chan error, 1)
	go func() {
		done <- s.runProcess(context.Background(), &pb.StartRequest{
			Cmd: "/bin/sh", Args: []string{"-c", "sleep 30"}, Cwd: "/tmp",
		}, emit, false)
	}()

	var pid uint32
	select {
	case pid = <-pidCh:
	case err := <-done:
		t.Fatalf("runProcess returned before StartEvent: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for StartEvent")
	}
	time.Sleep(200 * time.Millisecond)

	if _, err := s.Signal(context.Background(), connect.NewRequest(&pb.SignalRequest{
		Pid: pid, Signal: int32(syscall.SIGTERM),
	})); err != nil {
		t.Fatalf("Signal: %v", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SIGTERM did not terminate the command")
	}
}
