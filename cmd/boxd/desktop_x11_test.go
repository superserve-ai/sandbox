package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
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

// The persistent backend against a real server: capture via GetImage and
// pointer injection via XTest, verified from outside with xdotool.
func TestDesktopX11Backend_RealXServer(t *testing.T) {
	for _, bin := range []string{"Xvnc", "xdotool"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	display := startXvnc(t, 640, 480)
	t.Setenv("DISPLAY", display)
	s := newDesktopService(&sandboxContext{})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	shot, err := s.Screenshot(ctx, connect.NewRequest(&pb.ScreenshotRequest{}))
	if err != nil {
		t.Fatalf("Screenshot: %v", err)
	}
	if shot.Msg.GetWidth() != 640 || shot.Msg.GetHeight() != 480 || len(shot.Msg.GetImage()) == 0 {
		t.Fatalf("screenshot = %dx%d, %d bytes; want 640x480 with data", shot.Msg.GetWidth(), shot.Msg.GetHeight(), len(shot.Msg.GetImage()))
	}
	if s.x11.backend == nil {
		t.Fatal("screenshot did not go through the X11 backend")
	}

	_, err = s.SendPointer(ctx, connect.NewRequest(&pb.PointerEvent{
		X: 123, Y: 45,
		Button: pb.PointerButton_POINTER_BUTTON_LEFT,
		Action: pb.PointerAction_POINTER_ACTION_CLICK,
	}))
	if err != nil {
		t.Fatalf("SendPointer: %v", err)
	}
	probe := exec.Command("xdotool", "getmouselocation")
	probe.Env = append(os.Environ(), "DISPLAY="+display)
	out, err := probe.Output()
	if err != nil {
		t.Fatalf("xdotool getmouselocation: %v", err)
	}
	if got := string(out); !strings.HasPrefix(got, "x:123 y:45 ") {
		t.Fatalf("pointer after XTest click: %q, want x:123 y:45", got)
	}
}

// Step against a real server: the batch lands through XTest and the frame is
// captured on the same connection, in one call.
func TestDesktopStep_RealXServer(t *testing.T) {
	for _, bin := range []string{"Xvnc", "xdotool"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	display := startXvnc(t, 640, 480)
	t.Setenv("DISPLAY", display)
	s := newDesktopService(&sandboxContext{})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	resp, err := s.Step(ctx, connect.NewRequest(&pb.StepRequest{
		Actions: []*pb.Action{{Action: &pb.Action_Pointer{Pointer: &pb.PointerEvent{
			X: 321, Y: 54,
			Button: pb.PointerButton_POINTER_BUTTON_LEFT,
			Action: pb.PointerAction_POINTER_ACTION_CLICK,
		}}}},
		SettleMs: 20,
	}))
	if err != nil {
		t.Fatalf("Step: %v", err)
	}
	if resp.Msg.GetExecuted() != 1 || resp.Msg.GetActionError() != "" || resp.Msg.GetCaptureError() != "" {
		t.Fatalf("executed=%d action_error=%q capture_error=%q", resp.Msg.GetExecuted(), resp.Msg.GetActionError(), resp.Msg.GetCaptureError())
	}
	shot := resp.Msg.GetScreenshot()
	if shot.GetWidth() != 640 || shot.GetHeight() != 480 || len(shot.GetImage()) == 0 {
		t.Fatalf("screenshot = %dx%d, %d bytes; want 640x480 with data", shot.GetWidth(), shot.GetHeight(), len(shot.GetImage()))
	}
	if s.x11.backend == nil {
		t.Fatal("step did not go through the X11 backend")
	}
	probe := exec.Command("xdotool", "getmouselocation")
	probe.Env = append(os.Environ(), "DISPLAY="+display)
	out, err := probe.Output()
	if err != nil {
		t.Fatalf("xdotool getmouselocation: %v", err)
	}
	if got := string(out); !strings.HasPrefix(got, "x:321 y:54 ") {
		t.Fatalf("pointer after Step: %q, want x:321 y:54", got)
	}
}

// A reachable display with a screen it does not have must be an init error
// and a shell fallback, not a panic in boxd.
func TestX11Backend_RejectsMissingScreen(t *testing.T) {
	if _, err := exec.LookPath("Xvnc"); err != nil {
		t.Skip("Xvnc not installed")
	}
	display := startXvnc(t, 320, 240)
	var h x11Holder
	if b := h.get(context.Background(), display+".5"); b != nil {
		t.Fatal("got a backend for a screen the server does not have")
	}
	h.lastProbe = time.Time{} // past the cooldown of the failed probe
	b := h.get(context.Background(), display)
	if b == nil {
		t.Fatal("valid display did not connect")
	}
	h.drop(b)
}
