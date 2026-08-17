package sdnotify

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNotifyNoSocketIsNoop(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if err := Ready(); err != nil {
		t.Fatalf("Ready with no NOTIFY_SOCKET should be a no-op, got %v", err)
	}
}

func TestNotifySendsState(t *testing.T) {
	// Short path: unix sun_path is ~104-108 bytes.
	path := filepath.Join("/tmp", fmt.Sprintf("sdn-%d.sock", os.Getpid()))
	t.Cleanup(func() { os.Remove(path) })

	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()

	t.Setenv("NOTIFY_SOCKET", path)
	if err := Ready(); err != nil {
		t.Fatalf("Ready: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, _, err := conn.ReadFromUnix(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != "READY=1" {
		t.Fatalf("got %q, want READY=1", got)
	}
}
