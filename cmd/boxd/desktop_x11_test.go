package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"connectrpc.com/connect"

	pb "github.com/superserve-ai/sandbox/proto/boxdpb"
)

// Exercises Resize against a real X server, since xrandr mode registration is
// server-specific (Xvfb silently drops CVT modes). Skipped unless the desktop
// template's tools are installed, e.g. in a container built like the template.
func TestDesktopResize_RealXServer(t *testing.T) {
	for _, bin := range []string{"Xvnc", "xrandr", "cvt", "xdotool"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	display := startXvnc(t, 1280, 800)
	t.Setenv("DISPLAY", display)
	s := newDesktopService(&sandboxContext{})

	for _, want := range [][2]uint32{{1280, 720}, {1920, 1080}, {1280, 800}} {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		_, err := s.Resize(ctx, connect.NewRequest(&pb.DesktopResizeRequest{Width: want[0], Height: want[1]}))
		if err != nil {
			cancel()
			t.Fatalf("Resize(%dx%d): %v", want[0], want[1], err)
		}
		w, h, err := s.displayGeometry(ctx)
		cancel()
		if err != nil || w != want[0] || h != want[1] {
			t.Fatalf("after Resize(%dx%d): geometry %dx%d, err %v", want[0], want[1], w, h, err)
		}
	}
}

// startXvnc runs a loopback-only Xvnc on a free display and returns its
// DISPLAY value; the server is killed when the test ends.
func startXvnc(t *testing.T, width, height int) string {
	t.Helper()
	n := 50
	for ; n < 100; n++ {
		if _, err := os.Stat(fmt.Sprintf("/tmp/.X11-unix/X%d", n)); os.IsNotExist(err) {
			break
		}
	}
	display := ":" + strconv.Itoa(n)
	cmd := exec.Command("Xvnc", display, "-geometry", fmt.Sprintf("%dx%d", width, height), "-depth", "24",
		"-SecurityTypes", "None", "-localhost", "-rfbport", strconv.Itoa(5900+n))
	if err := cmd.Start(); err != nil {
		t.Fatalf("start Xvnc: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		probe := exec.Command("xdotool", "getdisplaygeometry")
		probe.Env = append(os.Environ(), "DISPLAY="+display)
		if probe.Run() == nil {
			return display
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("Xvnc on %s did not come up", display)
	return ""
}
