package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	pb "github.com/superserve-ai/sandbox/proto/boxdpb"
)

// TestSendInput_NonPTYStdin verifies that SendInput feeds a non-PTY process's
// stdin and that Eof closes it, letting a stdin-consuming command (cat) echo
// the input back and exit. This covers the wiring added for /exec/ws.
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
		// `cat` with no args reads stdin until EOF and echoes it to stdout.
		// Cwd must exist or fork/exec fails (it defaults to a home dir that
		// isn't present in the test environment).
		done <- s.runProcess(context.Background(), &pb.StartRequest{Cmd: "cat", Cwd: "/tmp"}, emit)
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
