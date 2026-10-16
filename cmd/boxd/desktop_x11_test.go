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
		// Nothing draws on this bare server, so the repaint wait runs out;
		// that is an answer, not a failure, and must not cost the connection.
		if s.x11.backend == nil {
			t.Fatalf("after Resize(%dx%d): X11 backend dropped by the repaint wait", want[0], want[1])
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
	if resp.Msg.GetSettleMs() < 20 || resp.Msg.GetCaptureMs() == 0 {
		t.Errorf("timings actions=%d settle=%d capture=%d, want the 20ms settle and a capture time", resp.Msg.GetActionsMs(), resp.Msg.GetSettleMs(), resp.Msg.GetCaptureMs())
	}
	if s.x11.backend == nil {
		t.Fatal("step did not go through the X11 backend")
	}
	jpegShot, err := s.Screenshot(ctx, connect.NewRequest(&pb.ScreenshotRequest{Format: pb.FrameFormat_FRAME_FORMAT_JPEG}))
	if err != nil {
		t.Fatalf("Screenshot(JPEG): %v", err)
	}
	img := jpegShot.Msg.GetImage()
	if jpegShot.Msg.GetFormat() != pb.FrameFormat_FRAME_FORMAT_JPEG || len(img) < 4 || img[0] != 0xff || img[1] != 0xd8 || jpegShot.Msg.GetWidth() != 640 {
		t.Fatalf("JPEG screenshot: format=%v width=%d head=% x", jpegShot.Msg.GetFormat(), jpegShot.Msg.GetWidth(), img[:min(4, len(img))])
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

// Change detection against a real server: a keystroke into a terminal
// comes back as soon as it is painted, and input that paints nothing waits
// out the settle and says so.
func TestDesktopStepWaitForChange_RealXServer(t *testing.T) {
	for _, bin := range []string{"Xvnc", "xdotool", "xterm"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	display := startXvnc(t, 640, 480)
	t.Setenv("DISPLAY", display)
	term := exec.Command("xterm", "-geometry", "80x24+0+0", "-e", "sh", "-c", "cat > /dev/null")
	term.Env = append(os.Environ(), "DISPLAY="+display)
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

	s := newDesktopService(&sandboxContext{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Focus follows the pointer without a window manager.
	if _, err := s.SendPointer(ctx, connect.NewRequest(&pb.PointerEvent{X: 100, Y: 100, Action: pb.PointerAction_POINTER_ACTION_CLICK})); err != nil {
		t.Fatalf("SendPointer: %v", err)
	}
	step := func(action *pb.Action, settleMs uint32) (*pb.StepResponse, time.Duration) {
		t.Helper()
		start := time.Now()
		resp, err := s.Step(ctx, connect.NewRequest(&pb.StepRequest{
			Actions: []*pb.Action{action}, SettleMs: settleMs, WaitForChange: true,
		}))
		if err != nil {
			t.Fatalf("Step: %v", err)
		}
		if resp.Msg.GetExecuted() != 1 || resp.Msg.GetActionError() != "" || resp.Msg.GetCaptureError() != "" {
			t.Fatalf("executed=%d action_error=%q capture_error=%q", resp.Msg.GetExecuted(), resp.Msg.GetActionError(), resp.Msg.GetCaptureError())
		}
		return resp.Msg, time.Since(start)
	}

	typed, typedAfter := step(&pb.Action{Action: &pb.Action_Key{Key: &pb.KeyEvent{Input: &pb.KeyEvent_Text{Text: "x"}}}}, 1500)
	if !typed.GetChanged() || typedAfter > 500*time.Millisecond {
		t.Errorf("typing into the terminal: changed=%v after %v, want a changed frame well before the 1500ms bound", typed.GetChanged(), typedAfter)
	}
	still, elapsed := step(&pb.Action{Action: &pb.Action_Pointer{Pointer: &pb.PointerEvent{X: 100, Y: 100, Action: pb.PointerAction_POINTER_ACTION_MOVE}}}, 300)
	if still.GetChanged() || elapsed < 300*time.Millisecond {
		t.Errorf("pointer move in place: changed=%v after %v, want an unchanged frame after the full 300ms", still.GetChanged(), elapsed)
	}
	t.Logf("changed frame after %v; unchanged frame after %v", typedAfter, elapsed)
	if still.GetScreenshot().GetWidth() != 640 || len(still.GetScreenshot().GetImage()) == 0 {
		t.Errorf("unchanged step returned no frame: %v", still.GetScreenshot())
	}
	if s.x11.backend == nil || s.x11.backend.damage == 0 {
		t.Fatal("change detection did not go through the DAMAGE watch")
	}
}

// A repaint that lands after a snapshot's read but before its event drain
// is the one DAMAGE will not report again (the region is already non-empty),
// so a same-pixel repaint followed by a real one must not wait out the
// settle. The hook interleaves both repaints into that window.
func TestDesktopStepWaitForChange_RepaintDuringSnapshot_RealXServer(t *testing.T) {
	for _, bin := range []string{"Xvnc", "xdotool", "xsetroot"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	display := startXvnc(t, 640, 480)
	t.Setenv("DISPLAY", display)
	paint := func(color string) {
		t.Helper()
		cmd := exec.Command("xsetroot", "-solid", color)
		cmd.Env = append(os.Environ(), "DISPLAY="+display)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("xsetroot %s: %v: %s", color, err, out)
		}
	}
	paint("#102030")
	s := newDesktopService(&sandboxContext{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := s.SendPointer(ctx, connect.NewRequest(&pb.PointerEvent{X: 100, Y: 100, Action: pb.PointerAction_POINTER_ACTION_MOVE})); err != nil {
		t.Fatalf("SendPointer: %v", err)
	}
	backend := s.x11.backend
	if backend == nil || backend.damage == 0 {
		t.Fatal("no DAMAGE watch on the X11 backend")
	}
	reads := 0
	backend.readHook = func() {
		reads++
		switch reads {
		case 1: // arming: a repaint with identical pixels, reported after the read
			paint("#102030")
		case 2: // the capture after it: a real change, again after the read
			paint("#ff0000")
		default:
			return
		}
		// Round-trip so the report is queued before the drain runs.
		if _, err := xproto.GetInputFocus(backend.conn).Reply(); err != nil {
			t.Errorf("sync after repaint: %v", err)
		}
	}
	start := time.Now()
	resp, err := s.Step(ctx, connect.NewRequest(&pb.StepRequest{
		Actions: []*pb.Action{{Action: &pb.Action_Pointer{Pointer: &pb.PointerEvent{
			X: 101, Y: 100, Action: pb.PointerAction_POINTER_ACTION_MOVE,
		}}}},
		SettleMs: 1500, WaitForChange: true,
	}))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Step: %v", err)
	}
	if resp.Msg.GetCaptureError() != "" || !resp.Msg.GetChanged() || elapsed > 500*time.Millisecond {
		t.Fatalf("changed=%v capture_error=%q after %v (reads=%d), want the red frame well before the 1500ms bound",
			resp.Msg.GetChanged(), resp.Msg.GetCaptureError(), elapsed, reads)
	}
	t.Logf("changed frame after %v with %d snapshot reads", elapsed, reads)
}

// With a window mapped, the display is painted again right after the mode
// switch, so Resize must return long before its repaint bound.
func TestDesktopResize_ReturnsOncePainted_RealXServer(t *testing.T) {
	for _, bin := range []string{"Xvnc", "xdotool", "xterm"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	display := startXvnc(t, 640, 480)
	t.Setenv("DISPLAY", display)
	term := exec.Command("xterm", "-geometry", "60x20+10+10", "-e", "sh", "-c", "cat > /dev/null")
	term.Env = append(os.Environ(), "DISPLAY="+display)
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
	s := newDesktopService(&sandboxContext{})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	if _, err := s.Resize(ctx, connect.NewRequest(&pb.DesktopResizeRequest{Width: 800, Height: 600})); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	if elapsed := time.Since(start); elapsed > resizeRepaintWait/2 {
		t.Fatalf("Resize took %v with a window to repaint, want well under the %v bound", elapsed, resizeRepaintWait)
	}
	shot, err := s.Screenshot(ctx, connect.NewRequest(&pb.ScreenshotRequest{}))
	if err != nil {
		t.Fatalf("Screenshot: %v", err)
	}
	if shot.Msg.GetWidth() != 800 {
		t.Fatalf("screenshot width %d after resize, want 800", shot.Msg.GetWidth())
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

	// Consecutive requests on scratch keycodes: a binding made by one
	// request must still mean the same thing when a later request runs,
	// since the application may not have consumed the earlier events yet.
	// Two fitting requests type exactly; one that would need a keycode
	// taken back declines instead, with nothing typed.
	send(&pb.KeyEvent{Input: &pb.KeyEvent_Text{Text: "αβγδεζ"}})
	want += "αβγδεζ"
	expect("consecutive scratch requests", "ηθικλμ\n")
	if _, err := s.SendKey(ctx, connect.NewRequest(&pb.KeyEvent{Input: &pb.KeyEvent_Text{Text: "νξοπρστυφχψω\n"}})); err == nil {
		t.Fatal("a request needing more scratch keycodes than remain should have declined")
	}
	time.Sleep(300 * time.Millisecond)
	if out, _ := os.ReadFile(typed); string(out) != want {
		t.Fatalf("a declined request still typed: %q", out)
	}

	// A native non-Latin layout: its keys carry legacy keysyms, which the
	// X11 path must find by code point rather than bind scratch keycodes
	// for (there are not enough of those for an alphabet).
	setLayout := func(layout string) {
		t.Helper()
		cmd := exec.Command("setxkbmap", "-layout", layout)
		cmd.Env = append(os.Environ(), "DISPLAY="+display)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("setxkbmap %s: %v: %s", layout, err, out)
		}
	}
	if _, err := exec.LookPath("setxkbmap"); err != nil {
		t.Skip("setxkbmap not installed; layout checks skipped")
	}
	setLayout("gr")
	expect("Greek layout literal input", "αβγδεζηθικλμνξοπρστυφχψω\n")
	// More distinct unmapped characters than spare keycodes: the X11 path
	// declines rather than recycle keycodes mid-request. With no helper on
	// PATH the decline surfaces as an error, and nothing was typed.
	if _, err := s.SendKey(ctx, connect.NewRequest(&pb.KeyEvent{Input: &pb.KeyEvent_Text{Text: "абвгдежзийклмнопрсту\n"}})); err == nil {
		t.Fatal("20 unmapped characters on an 18-keycode pool should have declined")
	}
	time.Sleep(300 * time.Millisecond)
	if out, _ := os.ReadFile(typed); string(out) != want {
		t.Fatalf("a declined request still typed: %q", out)
	}
	if s.x11.backend == nil {
		t.Fatal("the decline dropped the backend")
	}
	setLayout("us")

	// Caps Lock on: literal text is typed with the lock cleared and the lock
	// is back afterwards.
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
	if state, err := s.x11.backend.xkbGetState(0); err != nil || !state.capsLock {
		t.Fatalf("Caps Lock was not restored: %+v, %v", state, err)
	}
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
	if state, err := s.x11.backend.xkbGetState(0); err != nil || !state.shiftLock {
		t.Fatalf("state after Shift lock = %+v, %v; want shiftLock", state, err)
	}
	expect("with Shift Lock", "1a\n")
	if state, err := s.x11.backend.xkbGetState(0); err != nil || !state.shiftLock {
		t.Fatalf("Shift lock was not restored: %+v, %v", state, err)
	}
	xkbLatchLockState(t, display, xproto.ModMaskShift, 0, false, 0)

	// A second group made active: the X11 path declines (its keycodes
	// would type the other group's symbols) and xdotool, which locks the
	// group per keysym, types the text.
	setLayout("us,ru")
	xkbLatchLockState(t, display, 0, 0, true, 1)
	if state, err := s.x11.backend.xkbGetState(0); err != nil || state.group != 1 {
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
