package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xproto"

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

// Keyboard input against a real server, read back through a terminal: the
// desktop helpers are hidden so only the XTest path can deliver it.
func TestDesktopKeys_RealXServer(t *testing.T) {
	for _, bin := range []string{"Xvnc", "xdotool", "xterm"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	display := startXvnc(t, 640, 480)
	t.Setenv("DISPLAY", display)
	typed := filepath.Join(t.TempDir(), "typed.txt")
	term := exec.Command("xterm", "-geometry", "80x24+0+0", "-e", "sh", "-c", "cat > "+typed)
	term.Env = append(os.Environ(), "DISPLAY="+display, "LC_ALL=C.UTF-8", "LANG=C.UTF-8")
	if err := term.Start(); err != nil {
		t.Fatalf("start xterm: %v", err)
	}
	t.Cleanup(func() { _ = term.Process.Kill(); _ = term.Wait() })
	wait := exec.Command("xdotool", "search", "--sync", "--class", "xterm")
	wait.Env = append(os.Environ(), "DISPLAY="+display)
	if err := wait.Run(); err != nil {
		t.Fatalf("xterm window did not appear: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	old := desktopHelperPath
	desktopHelperPath = t.TempDir()
	t.Cleanup(func() { desktopHelperPath = old })
	s := newDesktopService(&sandboxContext{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Focus follows the pointer without a window manager.
	if _, err := s.SendPointer(ctx, connect.NewRequest(&pb.PointerEvent{X: 100, Y: 100, Action: pb.PointerAction_POINTER_ACTION_CLICK})); err != nil {
		t.Fatalf("SendPointer: %v", err)
	}
	send := func(ev *pb.KeyEvent) {
		t.Helper()
		if _, err := s.SendKey(ctx, connect.NewRequest(ev)); err != nil {
			t.Fatalf("SendKey(%v): %v", ev, err)
		}
	}
	send(&pb.KeyEvent{Input: &pb.KeyEvent_Text{Text: "discarded"}})
	send(&pb.KeyEvent{Input: &pb.KeyEvent_Key{Key: "u"}, Modifiers: []string{"ctrl"}})
	send(&pb.KeyEvent{Input: &pb.KeyEvent_Text{Text: "Hello, World! 123 café Été €\n"}})
	send(&pb.KeyEvent{Input: &pb.KeyEvent_Text{Text: "second line"}})
	send(&pb.KeyEvent{Input: &pb.KeyEvent_Key{Key: "Return"}})

	want := "Hello, World! 123 café Été €\nsecond line\n"
	deadline := time.Now().Add(10 * time.Second)
	var got string
	for time.Now().Before(deadline) {
		if out, err := os.ReadFile(typed); err == nil {
			got = string(out)
			if got == want {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got != want {
		t.Fatalf("terminal received %q, want %q", got, want)
	}
	if s.x11.backend == nil {
		t.Fatal("keys did not go through the X11 backend")
	}

	// Another client changes the layout between requests: the cached map
	// must be refreshed from the queued MappingNotify, not reused. With
	// `a` gone from the layout it has to be typed through a scratch keycode.
	remap := exec.Command("xmodmap", "-e", "keysym a = z")
	remap.Env = append(os.Environ(), "DISPLAY="+display)
	if out, err := remap.CombinedOutput(); err != nil {
		t.Fatalf("xmodmap: %v: %s", err, out)
	}
	// No settle on purpose: the server already processed the remap when
	// xmodmap exited, and the next request must see it without help.
	send(&pb.KeyEvent{Input: &pb.KeyEvent_Text{Text: "banana\n"}})
	want += "banana\n"
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if out, err := os.ReadFile(typed); err == nil {
			got = string(out)
			if got == want {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got != want {
		t.Fatalf("after an external remap the terminal received %q, want %q", got, want)
	}
	t.Logf("spare keycodes on this server: %d", len(s.x11.backend.keys.spare))

	expect := func(label, text string) {
		t.Helper()
		send(&pb.KeyEvent{Input: &pb.KeyEvent_Text{Text: text}})
		want += text
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if out, err := os.ReadFile(typed); err == nil {
				got = string(out)
				if got == want {
					return
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("%s: terminal received %q, want %q", label, got, want)
	}

	// Caps Lock on: the X11 path must invert Shift for letters, nothing else.
	toggleCaps := func() {
		t.Helper()
		caps := exec.Command("xdotool", "key", "Caps_Lock")
		caps.Env = append(os.Environ(), "DISPLAY="+display)
		if out, err := caps.CombinedOutput(); err != nil {
			t.Fatalf("xdotool key Caps_Lock: %v: %s", err, out)
		}
	}
	toggleCaps()
	expect("with Caps Lock", "Mixed Case 42!\n")
	toggleCaps()

	// Num Lock on: keypad digits must still be digits (they go through a
	// single-level scratch keycode rather than the shared KP_End/KP_1 key).
	toggleNum := func() {
		t.Helper()
		num := exec.Command("xdotool", "key", "Num_Lock")
		num.Env = append(os.Environ(), "DISPLAY="+display)
		if out, err := num.CombinedOutput(); err != nil {
			t.Fatalf("xdotool key Num_Lock: %v: %s", err, out)
		}
	}
	toggleNum()
	for _, name := range []string{"KP_1", "KP_2", "KP_Enter"} {
		send(&pb.KeyEvent{Input: &pb.KeyEvent_Key{Key: name}})
	}
	want += "12\n"
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if out, err := os.ReadFile(typed); err == nil {
			got = string(out)
			if got == want {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	toggleNum()
	if got != want {
		t.Fatalf("with Num Lock the terminal received %q, want %q", got, want)
	}

	// Shift locked: literal text is typed with the lock cleared and the
	// lock is back afterwards.
	xkbLatchLockState(t, display, xproto.ModMaskShift, xproto.ModMaskShift, false, 0)
	if state, err := s.x11.backend.xkbGetState(); err != nil || !state.shiftLock {
		t.Fatalf("state after Shift lock = %+v, %v; want shiftLock", state, err)
	}
	expect("with Shift Lock", "1a\n")
	if state, err := s.x11.backend.xkbGetState(); err != nil || !state.shiftLock {
		t.Fatalf("Shift lock was not restored: %+v, %v", state, err)
	}
	xkbLatchLockState(t, display, xproto.ModMaskShift, 0, false, 0)

	// A second group made active: the X11 path declines (its keycodes
	// would type the other group's symbols) and xdotool, which locks the
	// group per keysym, types the text.
	if _, err := exec.LookPath("setxkbmap"); err != nil {
		t.Skip("setxkbmap not installed; group check skipped")
	}
	layout := exec.Command("setxkbmap", "-layout", "us,ru")
	layout.Env = append(os.Environ(), "DISPLAY="+display)
	if out, err := layout.CombinedOutput(); err != nil {
		t.Fatalf("setxkbmap: %v: %s", err, out)
	}
	xkbLatchLockState(t, display, 0, 0, true, 1)
	if state, err := s.x11.backend.xkbGetState(); err != nil || state.group != 1 {
		t.Fatalf("state after lock = %+v, %v; want group 1", state, err)
	}
	desktopHelperPath = old
	expect("under group 2", "plain\n")
	if s.x11.backend == nil {
		t.Fatal("declining for the active group dropped the backend")
	}
}

// xkbLatchLockState sends XkbLatchLockState(XkbUseCoreKbd, ...) from a
// connection of its own, after XkbUseExtension(1.0): modifier locks and,
// when lockGroup is set, the group lock.
func xkbLatchLockState(t *testing.T, display string, affectModLocks, modLocks byte, lockGroup bool, group byte) {
	t.Helper()
	conn, err := xgb.NewConnDisplay(display)
	if err != nil {
		t.Fatalf("xkb test connection: %v", err)
	}
	defer conn.Close()
	ext, err := xproto.QueryExtension(conn, 9, "XKEYBOARD").Reply()
	if err != nil || !ext.Present {
		t.Fatalf("XKEYBOARD extension: %v", err)
	}
	use := make([]byte, 8)
	use[0], use[1] = ext.MajorOpcode, 0
	xgb.Put16(use[2:], 2)
	xgb.Put16(use[4:], 1)
	cookie := conn.NewCookie(true, true)
	conn.NewRequest(use, cookie)
	if _, err := cookie.Reply(); err != nil {
		t.Fatalf("XkbUseExtension: %v", err)
	}
	lock := make([]byte, 16)
	lock[0], lock[1] = ext.MajorOpcode, 5
	xgb.Put16(lock[2:], 4)
	xgb.Put16(lock[4:], 0x100)
	lock[6], lock[7] = affectModLocks, modLocks
	if lockGroup {
		lock[8], lock[9] = 1, group
	}
	cookie = conn.NewCookie(true, false)
	conn.NewRequest(lock, cookie)
	if err := cookie.Check(); err != nil {
		t.Fatalf("XkbLatchLockState: %v", err)
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
