package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	pb "github.com/superserve-ai/sandbox/proto/boxdpb"
	"github.com/superserve-ai/sandbox/proto/boxdpb/boxdpbconnect"
)

// ---------------------------------------------------------------------------
// Pure validation / argument-building logic — no X11, xdotool, or
// ImageMagick required. These cover the request-validation and error paths
// that are genuinely testable in this environment.
// ---------------------------------------------------------------------------

func TestNormalizeFrameConfig(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		format, interval, err := normalizeFrameConfig(&pb.FrameConfig{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if format != pb.FrameFormat_FRAME_FORMAT_PNG {
			t.Errorf("format = %v, want PNG", format)
		}
		wantInterval := time.Second / defaultDesktopFPS
		if interval != wantInterval {
			t.Errorf("interval = %v, want %v", interval, wantInterval)
		}
	})

	t.Run("explicit fps within bounds", func(t *testing.T) {
		_, interval, err := normalizeFrameConfig(&pb.FrameConfig{Fps: 10})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if interval != time.Second/10 {
			t.Errorf("interval = %v, want %v", interval, time.Second/10)
		}
	})

	t.Run("fps clamped to max", func(t *testing.T) {
		_, interval, err := normalizeFrameConfig(&pb.FrameConfig{Fps: 1000})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if interval != time.Second/maxDesktopFPS {
			t.Errorf("interval = %v, want %v (clamped to maxDesktopFPS)", interval, time.Second/maxDesktopFPS)
		}
	})

	t.Run("explicit PNG format", func(t *testing.T) {
		format, _, err := normalizeFrameConfig(&pb.FrameConfig{Format: pb.FrameFormat_FRAME_FORMAT_PNG})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if format != pb.FrameFormat_FRAME_FORMAT_PNG {
			t.Errorf("format = %v, want PNG", format)
		}
	})

	t.Run("unsupported format rejected", func(t *testing.T) {
		_, _, err := normalizeFrameConfig(&pb.FrameConfig{Format: pb.FrameFormat(99)})
		if err == nil {
			t.Fatal("expected error for unsupported format")
		}
	})
}

func TestPointerButtonArg(t *testing.T) {
	cases := []struct {
		button pb.PointerButton
		want   string
	}{
		{pb.PointerButton_POINTER_BUTTON_UNSPECIFIED, "1"},
		{pb.PointerButton_POINTER_BUTTON_LEFT, "1"},
		{pb.PointerButton_POINTER_BUTTON_MIDDLE, "2"},
		{pb.PointerButton_POINTER_BUTTON_RIGHT, "3"},
	}
	for _, tc := range cases {
		got, err := pointerButtonArg(tc.button)
		if err != nil {
			t.Errorf("pointerButtonArg(%v): unexpected error: %v", tc.button, err)
		}
		if got != tc.want {
			t.Errorf("pointerButtonArg(%v) = %q, want %q", tc.button, got, tc.want)
		}
	}

	if _, err := pointerButtonArg(pb.PointerButton(99)); err == nil {
		t.Error("expected error for unknown button")
	}
}

func TestPointerArgs(t *testing.T) {
	t.Run("move", func(t *testing.T) {
		got, err := pointerArgs(10, 20, pb.PointerButton_POINTER_BUTTON_UNSPECIFIED, pb.PointerAction_POINTER_ACTION_MOVE)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"mousemove", "10", "20"}
		if !equalStrings(got, want) {
			t.Errorf("pointerArgs = %v, want %v", got, want)
		}
	})

	t.Run("click right button", func(t *testing.T) {
		got, err := pointerArgs(5, 5, pb.PointerButton_POINTER_BUTTON_RIGHT, pb.PointerAction_POINTER_ACTION_CLICK)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"mousemove", "5", "5", "click", "3"}
		if !equalStrings(got, want) {
			t.Errorf("pointerArgs = %v, want %v", got, want)
		}
	})

	t.Run("double click", func(t *testing.T) {
		got, err := pointerArgs(0, 0, pb.PointerButton_POINTER_BUTTON_LEFT, pb.PointerAction_POINTER_ACTION_DOUBLE_CLICK)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"mousemove", "0", "0", "click", "--repeat", "2", "1"}
		if !equalStrings(got, want) {
			t.Errorf("pointerArgs = %v, want %v", got, want)
		}
	})

	t.Run("mousedown / mouseup", func(t *testing.T) {
		down, err := pointerArgs(1, 2, pb.PointerButton_POINTER_BUTTON_MIDDLE, pb.PointerAction_POINTER_ACTION_DOWN)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !equalStrings(down, []string{"mousemove", "1", "2", "mousedown", "2"}) {
			t.Errorf("down args = %v", down)
		}
		up, err := pointerArgs(1, 2, pb.PointerButton_POINTER_BUTTON_MIDDLE, pb.PointerAction_POINTER_ACTION_UP)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !equalStrings(up, []string{"mousemove", "1", "2", "mouseup", "2"}) {
			t.Errorf("up args = %v", up)
		}
	})

	t.Run("malformed coordinates", func(t *testing.T) {
		cases := []struct{ x, y int32 }{
			{-1, 0},
			{0, -1},
			{maxCoordinate, 0},
			{0, maxCoordinate},
			{-100, -100},
		}
		for _, tc := range cases {
			if _, err := pointerArgs(tc.x, tc.y, pb.PointerButton_POINTER_BUTTON_LEFT, pb.PointerAction_POINTER_ACTION_MOVE); err == nil {
				t.Errorf("pointerArgs(%d, %d): expected error for malformed coordinates", tc.x, tc.y)
			}
		}
	})

	t.Run("unknown action", func(t *testing.T) {
		if _, err := pointerArgs(0, 0, pb.PointerButton_POINTER_BUTTON_LEFT, pb.PointerAction(99)); err == nil {
			t.Error("expected error for unknown action")
		}
	})

	t.Run("unknown button on action that needs one", func(t *testing.T) {
		if _, err := pointerArgs(0, 0, pb.PointerButton(99), pb.PointerAction_POINTER_ACTION_CLICK); err == nil {
			t.Error("expected error for unknown button")
		}
	})
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestKeyArgs(t *testing.T) {
	t.Run("key without modifiers", func(t *testing.T) {
		got, err := keyArgs(&pb.KeyEvent{Input: &pb.KeyEvent_Key{Key: "Return"}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"key", "--", "Return"}
		if !equalStrings(got, want) {
			t.Errorf("keyArgs = %v, want %v", got, want)
		}
	})

	t.Run("key with modifiers", func(t *testing.T) {
		got, err := keyArgs(&pb.KeyEvent{
			Input:     &pb.KeyEvent_Key{Key: "c"},
			Modifiers: []string{"ctrl", "shift"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"key", "--", "ctrl+shift+c"}
		if !equalStrings(got, want) {
			t.Errorf("keyArgs = %v, want %v", got, want)
		}
	})

	t.Run("text", func(t *testing.T) {
		got, err := keyArgs(&pb.KeyEvent{Input: &pb.KeyEvent_Text{Text: "hello world"}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"type", "--delay", "0", "--", "hello world"}
		if !equalStrings(got, want) {
			t.Errorf("keyArgs = %v, want %v", got, want)
		}
	})

	t.Run("empty key rejected", func(t *testing.T) {
		if _, err := keyArgs(&pb.KeyEvent{Input: &pb.KeyEvent_Key{Key: ""}}); err == nil {
			t.Error("expected error for empty key")
		}
	})

	t.Run("empty text rejected", func(t *testing.T) {
		if _, err := keyArgs(&pb.KeyEvent{Input: &pb.KeyEvent_Text{Text: ""}}); err == nil {
			t.Error("expected error for empty text")
		}
	})

	t.Run("neither key nor text rejected", func(t *testing.T) {
		if _, err := keyArgs(&pb.KeyEvent{}); err == nil {
			t.Error("expected error when neither key nor text is set")
		}
	})

	t.Run("text with leading dash is guarded by --", func(t *testing.T) {
		got, err := keyArgs(&pb.KeyEvent{Input: &pb.KeyEvent_Text{Text: "--evil-flag"}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got[len(got)-2] != "--" {
			t.Errorf("keyArgs = %v, want a -- guard before the literal text", got)
		}
	})

	t.Run("oversized inputs rejected", func(t *testing.T) {
		if _, err := keyArgs(&pb.KeyEvent{Input: &pb.KeyEvent_Key{Key: strings.Repeat("k", maxKeyLength+1)}}); err == nil {
			t.Error("expected oversized key to be rejected")
		}
		if _, err := keyArgs(&pb.KeyEvent{Input: &pb.KeyEvent_Text{Text: strings.Repeat("t", maxTextLength+1)}}); err == nil {
			t.Error("expected oversized text to be rejected")
		}
	})

	t.Run("invalid modifiers rejected", func(t *testing.T) {
		tooMany := make([]string, maxModifiers+1)
		for i := range tooMany {
			tooMany[i] = "ctrl"
		}
		if _, err := keyArgs(&pb.KeyEvent{Input: &pb.KeyEvent_Key{Key: "c"}, Modifiers: tooMany}); err == nil {
			t.Error("expected too many modifiers to be rejected")
		}
		if _, err := keyArgs(&pb.KeyEvent{Input: &pb.KeyEvent_Key{Key: "c"}, Modifiers: []string{""}}); err == nil {
			t.Error("expected empty modifier to be rejected")
		}
	})
}

func TestScrollCommands(t *testing.T) {
	t.Run("no-op", func(t *testing.T) {
		cmds, err := scrollCommands(0, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cmds != nil {
			t.Errorf("cmds = %v, want nil", cmds)
		}
	})

	t.Run("scroll down", func(t *testing.T) {
		cmds, err := scrollCommands(0, 3)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := [][]string{{"click", "--repeat", "3", "5"}}
		if len(cmds) != 1 || !equalStrings(cmds[0], want[0]) {
			t.Errorf("cmds = %v, want %v", cmds, want)
		}
	})

	t.Run("scroll up", func(t *testing.T) {
		cmds, err := scrollCommands(0, -4)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"click", "--repeat", "4", "4"}
		if len(cmds) != 1 || !equalStrings(cmds[0], want) {
			t.Errorf("cmds = %v, want %v", cmds, want)
		}
	})

	t.Run("horizontal scroll", func(t *testing.T) {
		right, err := scrollCommands(2, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(right) != 1 || !equalStrings(right[0], []string{"click", "--repeat", "2", "7"}) {
			t.Errorf("right = %v", right)
		}
		left, err := scrollCommands(-2, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(left) != 1 || !equalStrings(left[0], []string{"click", "--repeat", "2", "6"}) {
			t.Errorf("left = %v", left)
		}
	})

	t.Run("both axes", func(t *testing.T) {
		cmds, err := scrollCommands(1, 1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cmds) != 2 {
			t.Fatalf("expected 2 commands (one per axis), got %d: %v", len(cmds), cmds)
		}
	})

	t.Run("out of range rejected", func(t *testing.T) {
		if _, err := scrollCommands(0, maxScrollRepeat+1); err == nil {
			t.Error("expected error for dy exceeding maxScrollRepeat")
		}
		if _, err := scrollCommands(maxScrollRepeat+1, 0); err == nil {
			t.Error("expected error for dx exceeding maxScrollRepeat")
		}
		if _, err := scrollCommands(0, -(maxScrollRepeat + 1)); err == nil {
			t.Error("expected error for negative dy exceeding maxScrollRepeat")
		}
		if _, err := scrollCommands(-1<<31, 0); err == nil {
			t.Error("expected minimum int32 delta to be rejected")
		}
	})
}

func TestValidateResizeDims(t *testing.T) {
	cases := []struct {
		name          string
		width, height uint32
		wantErr       bool
	}{
		{"valid", 1920, 1080, false},
		{"minimum", minDesktopWidth, minDesktopHeight, false},
		{"zero width", 0, 1080, true},
		{"zero height", 1920, 0, true},
		{"width too small", minDesktopWidth - 8, 1080, true},
		{"height too small", 1920, minDesktopHeight - 1, true},
		{"width not CVT aligned", 1279, 720, true},
		{"width too large", maxDesktopDimension + 8, 1080, true},
		{"height too large", 1920, maxDesktopDimension + 1, true},
		{"both zero", 0, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateResizeDims(tc.width, tc.height)
			if tc.wantErr && err == nil {
				t.Errorf("validateResizeDims(%d, %d): expected error", tc.width, tc.height)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validateResizeDims(%d, %d): unexpected error: %v", tc.width, tc.height, err)
			}
		})
	}
}

func TestConnectedOutput(t *testing.T) {
	query := []byte("Screen 0: minimum 320 x 200, current 1280 x 800\nscreen connected 1280x800+0+0\n")
	got, err := connectedOutput(query)
	if err != nil {
		t.Fatalf("connectedOutput: %v", err)
	}
	if got != "screen" {
		t.Fatalf("connectedOutput = %q, want screen", got)
	}
	if _, err := connectedOutput([]byte("screen disconnected\n")); err == nil {
		t.Fatal("expected error when no output is connected")
	}
}

func TestParseCVTModeline(t *testing.T) {
	name, args, err := parseCVTModeline([]byte("# 1280x720 59.86 Hz\nModeline \"1280x720_60.00\" 74.50 1280 1344 1472 1664 720 723 728 748 -hsync +vsync\n"))
	if err != nil {
		t.Fatalf("parseCVTModeline: %v", err)
	}
	if name != "1280x720_60.00" {
		t.Fatalf("name = %q", name)
	}
	if len(args) < 4 || args[0] != name || args[1] != "74.50" {
		t.Fatalf("args = %v", args)
	}
	if _, _, err := parseCVTModeline([]byte("invalid")); err == nil {
		t.Fatal("expected invalid cvt output to fail")
	}
}

func TestAbs32(t *testing.T) {
	cases := []struct {
		in   int32
		want int64
	}{
		{5, 5}, {-5, 5}, {0, 0}, {-1, 1}, {-1 << 31, 1 << 31},
	}
	for _, tc := range cases {
		if got := abs32(tc.in); got != tc.want {
			t.Errorf("abs32(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestWrapExecErr(t *testing.T) {
	base := errors.New("exit status 1")
	got := wrapExecErr("desc", base)
	if !strings.Contains(got.Error(), "desc") || !strings.Contains(got.Error(), "exit status 1") {
		t.Errorf("wrapExecErr = %q, missing desc or underlying error", got.Error())
	}
}

func TestWrapExecErrOutput(t *testing.T) {
	base := errors.New("exit status 1")

	withOutput := wrapExecErrOutput("desc", []byte("  boom  \n"), base)
	if !strings.Contains(withOutput.Error(), "boom") {
		t.Errorf("wrapExecErrOutput = %q, want it to include trimmed output", withOutput.Error())
	}
	if strings.Contains(withOutput.Error(), "  boom  ") {
		t.Errorf("wrapExecErrOutput = %q, output should be trimmed", withOutput.Error())
	}

	noOutput := wrapExecErrOutput("desc", nil, base)
	if !strings.Contains(noOutput.Error(), "desc") || !strings.Contains(noOutput.Error(), "exit status 1") {
		t.Errorf("wrapExecErrOutput(nil output) = %q", noOutput.Error())
	}
}

// ---------------------------------------------------------------------------
// End-to-end coverage using fake xdotool/import/xrandr binaries on PATH.
//
// This exercises the real connect.Request → validation → exec.CommandContext
// → connect.Response wiring without needing an X11 display or the real
// ImageMagick/xdotool tools — genuinely unavailable in this environment (no
// KVM/Linux desktop). It substitutes trivial shell scripts standing in for
// those binaries so the plumbing above and below the exec boundary is
// covered; the real xdotool/import/xrandr behavior against a live X server
// is NOT verified here and needs manual/integration testing on a booted
// sandbox with a desktop template.
// ---------------------------------------------------------------------------

// withFakeBin prepends a directory containing the given fake executables to
// PATH for the duration of the test. Each entry maps a binary name to the
// shell script body (after the shebang line) that should run in its place.
func withFakeBin(t *testing.T, bins map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for name, body := range bins {
		script := "#!/bin/sh\n" + body
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestDesktopCommandUsesSandboxDisplay(t *testing.T) {
	withFakeBin(t, map[string]string{
		"xdotool": `printf '%s' "$DISPLAY"
`,
	})

	sandboxCtx := &sandboxContext{}
	sandboxCtx.merge(map[string]string{"DISPLAY": ":77"}, "", "")
	service := newDesktopService(sandboxCtx)
	cmd, err := service.commandContext(context.Background(), "xdotool")
	if err != nil {
		t.Fatalf("commandContext: %v", err)
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("run fake xdotool: %v", err)
	}
	if got, want := string(out), ":77"; got != want {
		t.Fatalf("DISPLAY = %q, want %q", got, want)
	}
}

func TestDesktopCommandDefaultsDisplay(t *testing.T) {
	withFakeBin(t, map[string]string{
		"xdotool": `printf '%s' "$DISPLAY"
`,
	})
	t.Setenv("DISPLAY", "")

	service := newDesktopService(nil)
	cmd, err := service.commandContext(context.Background(), "xdotool")
	if err != nil {
		t.Fatalf("commandContext: %v", err)
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("run fake xdotool: %v", err)
	}
	if got, want := string(out), defaultDesktopDisplay; got != want {
		t.Fatalf("DISPLAY = %q, want %q", got, want)
	}
}

func TestSendPointer_EndToEnd_LogsExactArgs(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "args.log")
	withFakeBin(t, map[string]string{
		"xdotool": fmt.Sprintf(`echo "$@" > %q
exit 0
`, logFile),
	})

	s := newDesktopService(nil)
	resp, err := s.SendPointer(context.Background(), connect.NewRequest(&pb.PointerEvent{
		X:      42,
		Y:      7,
		Button: pb.PointerButton_POINTER_BUTTON_RIGHT,
		Action: pb.PointerAction_POINTER_ACTION_CLICK,
	}))
	if err != nil {
		t.Fatalf("SendPointer: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	got, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	want := "mousemove 42 7 click 3\n"
	if string(got) != want {
		t.Errorf("xdotool invoked with %q, want %q", got, want)
	}
}

func TestSendPointer_EndToEnd_ExecFailurePropagates(t *testing.T) {
	withFakeBin(t, map[string]string{
		"xdotool": "echo 'no display' >&2\nexit 1\n",
	})

	s := newDesktopService(nil)
	_, err := s.SendPointer(context.Background(), connect.NewRequest(&pb.PointerEvent{
		X: 1, Y: 1, Action: pb.PointerAction_POINTER_ACTION_MOVE,
	}))
	if err == nil {
		t.Fatal("expected error when xdotool fails")
	}
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != connect.CodeInternal {
		t.Errorf("error = %v, want CodeInternal", err)
	}
	if !strings.Contains(err.Error(), "no display") {
		t.Errorf("error = %v, want it to surface the fake tool's stderr", err)
	}
}

func TestSendPointer_ValidationErrorNeverShellsOut(t *testing.T) {
	// No fake xdotool on PATH at all — if validation didn't short-circuit
	// before exec, this would fail with "executable file not found" instead
	// of the expected InvalidArgument, so this also proves validation runs
	// first.
	s := newDesktopService(nil)
	_, err := s.SendPointer(context.Background(), connect.NewRequest(&pb.PointerEvent{
		X: -1, Y: 0,
	}))
	if err == nil {
		t.Fatal("expected error for negative coordinate")
	}
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != connect.CodeInvalidArgument {
		t.Errorf("error = %v, want CodeInvalidArgument", err)
	}
}

func TestSendKey_EndToEnd(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "args.log")
	withFakeBin(t, map[string]string{
		"xdotool": fmt.Sprintf(`echo "$@" > %q
exit 0
`, logFile),
	})

	s := newDesktopService(nil)
	_, err := s.SendKey(context.Background(), connect.NewRequest(&pb.KeyEvent{
		Input:     &pb.KeyEvent_Key{Key: "Delete"},
		Modifiers: []string{"ctrl", "alt"},
	}))
	if err != nil {
		t.Fatalf("SendKey: %v", err)
	}
	got, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	want := "key -- ctrl+alt+Delete\n"
	if string(got) != want {
		t.Errorf("xdotool invoked with %q, want %q", got, want)
	}
}

func TestSendKey_ValidationErrorNeverShellsOut(t *testing.T) {
	s := newDesktopService(nil)
	_, err := s.SendKey(context.Background(), connect.NewRequest(&pb.KeyEvent{}))
	if err == nil {
		t.Fatal("expected error when neither key nor text is set")
	}
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != connect.CodeInvalidArgument {
		t.Errorf("error = %v, want CodeInvalidArgument", err)
	}
}

func TestScroll_EndToEnd(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "args.log")
	withFakeBin(t, map[string]string{
		"xdotool": fmt.Sprintf(`echo "$@" >> %q
exit 0
`, logFile),
	})

	s := newDesktopService(nil)
	_, err := s.Scroll(context.Background(), connect.NewRequest(&pb.ScrollEvent{Dy: 3}))
	if err != nil {
		t.Fatalf("Scroll: %v", err)
	}
	got, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	want := "click --repeat 3 5\n"
	if string(got) != want {
		t.Errorf("xdotool invoked with %q, want %q", got, want)
	}
}

func TestResize_EndToEnd(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "args.log")
	withFakeBin(t, map[string]string{
		"xrandr": fmt.Sprintf(`echo "$@" >> %q
if [ "$1" = "--query" ]; then
  echo "screen connected 1280x800+0+0"
fi
exit 0
`, logFile),
		"cvt": `echo '# 1280x720 59.86 Hz'
echo 'Modeline "1280x720_60.00" 74.50 1280 1344 1472 1664 720 723 728 748 -hsync +vsync'
`,
		"xdotool": `if [ "$1" = "getdisplaygeometry" ]; then echo "1280 720"; exit 0; fi
exit 1
`,
	})

	s := newDesktopService(nil)
	_, err := s.Resize(context.Background(), connect.NewRequest(&pb.DesktopResizeRequest{Width: 1280, Height: 720}))
	if err != nil {
		t.Fatalf("Resize: %v", err)
	}
	got, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	for _, want := range []string{
		"--query\n",
		"--newmode 1280x720_60.00 74.50",
		"--addmode screen 1280x720_60.00\n",
		"--output screen --mode 1280x720_60.00\n",
	} {
		if !strings.Contains(string(got), want) {
			t.Errorf("xrandr log %q does not contain %q", got, want)
		}
	}
}

func TestResize_ValidationErrorNeverShellsOut(t *testing.T) {
	s := newDesktopService(nil)
	_, err := s.Resize(context.Background(), connect.NewRequest(&pb.DesktopResizeRequest{Width: 0, Height: 0}))
	if err == nil {
		t.Fatal("expected error for zero dimensions")
	}
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != connect.CodeInvalidArgument {
		t.Errorf("error = %v, want CodeInvalidArgument", err)
	}
}

// ---------------------------------------------------------------------------
// Stream — exercised through a real connect client/server round trip since
// connect.ServerStream has no exported constructor for direct unit testing.
// ---------------------------------------------------------------------------

func newDesktopTestServer(t *testing.T) boxdpbconnect.DesktopServiceClient {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(boxdpbconnect.NewDesktopServiceHandler(newDesktopService(nil)))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return boxdpbconnect.NewDesktopServiceClient(srv.Client(), srv.URL)
}

func TestStream_EndToEnd_StartAndDataEvents(t *testing.T) {
	withFakeBin(t, map[string]string{
		"xdotool": `if [ "$1" = "getdisplaygeometry" ]; then echo "800 600"; exit 0; fi
exit 1
`,
		"import": `printf 'FAKEPNGDATA'
`,
	})

	client := newDesktopTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := client.Stream(ctx, connect.NewRequest(&pb.FrameConfig{Fps: maxDesktopFPS}))
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	defer stream.Close()

	if !stream.Receive() {
		t.Fatalf("expected a Start event, receive failed: %v", stream.Err())
	}
	start := stream.Msg().GetStart()
	if start == nil {
		t.Fatalf("first event = %+v, want a Start event", stream.Msg())
	}
	if start.GetWidth() != 800 || start.GetHeight() != 600 {
		t.Errorf("start dims = %dx%d, want 800x600", start.GetWidth(), start.GetHeight())
	}
	if start.GetFormat() != pb.FrameFormat_FRAME_FORMAT_PNG {
		t.Errorf("start format = %v, want PNG", start.GetFormat())
	}

	if !stream.Receive() {
		t.Fatalf("expected a Data event, receive failed: %v", stream.Err())
	}
	data := stream.Msg().GetData()
	if data == nil {
		t.Fatalf("second event = %+v, want a Data event", stream.Msg())
	}
	if string(data.GetImage()) != "FAKEPNGDATA" {
		t.Errorf("frame image = %q, want %q", data.GetImage(), "FAKEPNGDATA")
	}
	if data.GetSequence() != 1 {
		t.Errorf("sequence = %d, want 1", data.GetSequence())
	}
	if data.GetTimestampUnixMs() == 0 {
		t.Error("timestamp is zero")
	}
}

func TestStream_UnsupportedFormat_InvalidArgument(t *testing.T) {
	// No fake binaries on PATH: format validation must reject the request
	// before boxd ever tries to query display geometry or capture a frame.
	client := newDesktopTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Stream(ctx, connect.NewRequest(&pb.FrameConfig{Format: pb.FrameFormat(99)}))
	if err != nil {
		// Some connect transports surface the handler's immediate error here
		// instead of via the first Receive; accept either.
		var ce *connect.Error
		if !errors.As(err, &ce) || ce.Code() != connect.CodeInvalidArgument {
			t.Fatalf("Stream error = %v, want CodeInvalidArgument", err)
		}
		return
	}
	defer stream.Close()

	if stream.Receive() {
		t.Fatalf("expected no events for an invalid stream, got %+v", stream.Msg())
	}
	var ce *connect.Error
	if !errors.As(stream.Err(), &ce) || ce.Code() != connect.CodeInvalidArgument {
		t.Errorf("stream.Err() = %v, want CodeInvalidArgument", stream.Err())
	}
}

func TestStream_MissingDisplay_FailedPrecondition(t *testing.T) {
	// No xdotool on PATH at all: displayGeometry must fail fast rather than
	// attempt to capture frames against a nonexistent display.
	client := newDesktopTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Stream(ctx, connect.NewRequest(&pb.FrameConfig{}))
	if err == nil {
		defer stream.Close()
		if stream.Receive() {
			t.Fatalf("expected no events when xdotool is unavailable, got %+v", stream.Msg())
		}
		err = stream.Err()
	}
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != connect.CodeFailedPrecondition {
		t.Errorf("error = %v, want CodeFailedPrecondition", err)
	}
}

func TestStream_CaptureFailsRepeatedly_EndsWithError(t *testing.T) {
	withFakeBin(t, map[string]string{
		"xdotool": `if [ "$1" = "getdisplaygeometry" ]; then echo "800 600"; exit 0; fi
exit 1
`,
		"import": `echo 'capture broken' >&2
exit 1
`,
	})

	client := newDesktopTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := client.Stream(ctx, connect.NewRequest(&pb.FrameConfig{Fps: maxDesktopFPS}))
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	defer stream.Close()

	if !stream.Receive() {
		t.Fatalf("expected a Start event, receive failed: %v", stream.Err())
	}
	if stream.Msg().GetStart() == nil {
		t.Fatalf("first event = %+v, want a Start event", stream.Msg())
	}

	// Drain until the stream ends (either an End event followed by close, or
	// Receive returning false with an error).
	var sawEnd bool
	for stream.Receive() {
		if end := stream.Msg().GetEnd(); end != nil {
			sawEnd = true
			if end.GetStatus() != "error" {
				t.Errorf("end status = %q, want %q", end.GetStatus(), "error")
			}
		}
	}
	if !sawEnd {
		t.Error("never saw an End event with status=error after repeated capture failures")
	}
	var ce *connect.Error
	if !errors.As(stream.Err(), &ce) || ce.Code() != connect.CodeInternal {
		t.Errorf("final stream.Err() = %v, want CodeInternal", stream.Err())
	}
}

func TestStream_ClientCancel_EndsCleanly(t *testing.T) {
	withFakeBin(t, map[string]string{
		"xdotool": `if [ "$1" = "getdisplaygeometry" ]; then echo "800 600"; exit 0; fi
exit 1
`,
		"import": `printf 'FAKEPNGDATA'
`,
	})

	client := newDesktopTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream, err := client.Stream(ctx, connect.NewRequest(&pb.FrameConfig{Fps: maxDesktopFPS}))
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	defer stream.Close()

	if !stream.Receive() { // Start
		t.Fatalf("expected Start event: %v", stream.Err())
	}
	if !stream.Receive() { // first Data frame
		t.Fatalf("expected Data event: %v", stream.Err())
	}

	cancel()

	// Drain until closed; a well-behaved server either sends an End event
	// before the connection drops or the client just observes cancellation —
	// both are acceptable outcomes, this just proves the server doesn't hang
	// or panic on client cancellation.
	deadline := time.Now().Add(5 * time.Second)
	for stream.Receive() {
		if time.Now().After(deadline) {
			t.Fatal("stream did not end after client cancellation")
		}
	}
	if err := stream.Err(); err != nil && !errors.Is(err, context.Canceled) {
		var ce *connect.Error
		if !errors.As(err, &ce) {
			t.Errorf("unexpected non-connect error after cancel: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// Screenshot (unary)
// ---------------------------------------------------------------------------

func TestScreenshot_EndToEnd(t *testing.T) {
	// A real (tiny) PNG so the handler's header decode sees genuine
	// dimensions rather than a placeholder string.
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 5, 3))); err != nil {
		t.Fatalf("encode test png: %v", err)
	}
	pngFile := filepath.Join(t.TempDir(), "frame.png")
	if err := os.WriteFile(pngFile, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write test png: %v", err)
	}
	withFakeBin(t, map[string]string{
		"import": fmt.Sprintf(`cat %q
`, pngFile),
	})

	client := newDesktopTestServer(t)
	resp, err := client.Screenshot(context.Background(), connect.NewRequest(&pb.ScreenshotRequest{}))
	if err != nil {
		t.Fatalf("Screenshot: %v", err)
	}
	if !bytes.Equal(resp.Msg.GetImage(), buf.Bytes()) {
		t.Error("image bytes do not round-trip")
	}
	if resp.Msg.GetWidth() != 5 || resp.Msg.GetHeight() != 3 {
		t.Errorf("dims = %dx%d, want 5x3", resp.Msg.GetWidth(), resp.Msg.GetHeight())
	}
	if resp.Msg.GetFormat() != pb.FrameFormat_FRAME_FORMAT_PNG {
		t.Errorf("format = %v, want PNG", resp.Msg.GetFormat())
	}
}

func TestScreenshot_UnsupportedFormat_InvalidArgument(t *testing.T) {
	s := newDesktopService(nil)
	_, err := s.Screenshot(context.Background(), connect.NewRequest(&pb.ScreenshotRequest{
		Format: pb.FrameFormat(99),
	}))
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != connect.CodeInvalidArgument {
		t.Errorf("error = %v, want CodeInvalidArgument", err)
	}
}

func TestScreenshot_InvalidPNG_Internal(t *testing.T) {
	withFakeBin(t, map[string]string{
		"import": `printf 'NOTAPNG'
`,
	})
	s := newDesktopService(nil)
	_, err := s.Screenshot(context.Background(), connect.NewRequest(&pb.ScreenshotRequest{}))
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != connect.CodeInternal {
		t.Errorf("error = %v, want CodeInternal for undecodable capture output", err)
	}
}

func TestScreenshot_WorksWhileStreamSlotHeld(t *testing.T) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 1, 1))); err != nil {
		t.Fatalf("encode test png: %v", err)
	}
	pngFile := filepath.Join(t.TempDir(), "frame.png")
	if err := os.WriteFile(pngFile, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write test png: %v", err)
	}
	withFakeBin(t, map[string]string{
		"import": fmt.Sprintf(`cat %q
`, pngFile),
	})

	s := newDesktopService(nil)
	// Simulate an active Stream holding the per-sandbox slot.
	s.streamSlot <- struct{}{}
	defer func() { <-s.streamSlot }()

	if _, err := s.Screenshot(context.Background(), connect.NewRequest(&pb.ScreenshotRequest{})); err != nil {
		t.Fatalf("Screenshot while stream active: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SendActions (batch)
// ---------------------------------------------------------------------------

func TestBatchCommands(t *testing.T) {
	t.Run("empty rejected", func(t *testing.T) {
		if _, err := batchCommands(nil); err == nil {
			t.Error("expected error for empty batch")
		}
	})

	t.Run("too many rejected", func(t *testing.T) {
		actions := make([]*pb.Action, maxBatchActions+1)
		for i := range actions {
			actions[i] = &pb.Action{Action: &pb.Action_Pointer{Pointer: &pb.PointerEvent{X: 1, Y: 1}}}
		}
		if _, err := batchCommands(actions); err == nil {
			t.Error("expected error for oversized batch")
		}
	})

	t.Run("invalid action reports its index", func(t *testing.T) {
		_, err := batchCommands([]*pb.Action{
			{Action: &pb.Action_Pointer{Pointer: &pb.PointerEvent{X: 1, Y: 1}}},
			{Action: &pb.Action_Pointer{Pointer: &pb.PointerEvent{X: -1, Y: 1}}},
		})
		if err == nil || !strings.Contains(err.Error(), "action 1") {
			t.Errorf("error = %v, want it to name action 1", err)
		}
	})

	t.Run("unset action rejected", func(t *testing.T) {
		if _, err := batchCommands([]*pb.Action{{}}); err == nil {
			t.Error("expected error for action with no payload")
		}
	})

	t.Run("scroll expands to per-axis commands", func(t *testing.T) {
		cmds, err := batchCommands([]*pb.Action{
			{Action: &pb.Action_Scroll{Scroll: &pb.ScrollEvent{Dx: 1, Dy: -2}}},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cmds) != 1 || len(cmds[0]) != 2 {
			t.Errorf("cmds = %v, want one action with two xdotool invocations", cmds)
		}
	})
}

func TestSendActions_EndToEnd_OrderedExecution(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "args.log")
	withFakeBin(t, map[string]string{
		"xdotool": fmt.Sprintf(`echo "$@" >> %q
exit 0
`, logFile),
	})

	client := newDesktopTestServer(t)
	resp, err := client.SendActions(context.Background(), connect.NewRequest(&pb.ActionBatch{
		Actions: []*pb.Action{
			{Action: &pb.Action_Pointer{Pointer: &pb.PointerEvent{
				X: 10, Y: 20, Action: pb.PointerAction_POINTER_ACTION_CLICK,
			}}},
			{Action: &pb.Action_Key{Key: &pb.KeyEvent{Input: &pb.KeyEvent_Text{Text: "hi"}}}},
			{Action: &pb.Action_Scroll{Scroll: &pb.ScrollEvent{Dy: 3}}},
		},
	}))
	if err != nil {
		t.Fatalf("SendActions: %v", err)
	}
	if resp.Msg.GetExecuted() != 3 {
		t.Errorf("executed = %d, want 3", resp.Msg.GetExecuted())
	}

	got, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	want := "mousemove 10 20 click 1\n" +
		"type --delay 0 -- hi\n" +
		"click --repeat 3 5\n"
	if string(got) != want {
		t.Errorf("xdotool invocations:\n%s\nwant:\n%s", got, want)
	}
}

func TestSendActions_StopsAtFirstFailure(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "args.log")
	// The fake fails on the key action, so the batch must report index 1 and
	// never run the trailing scroll.
	withFakeBin(t, map[string]string{
		"xdotool": fmt.Sprintf(`echo "$@" >> %q
if [ "$1" = "key" ]; then echo "boom" >&2; exit 1; fi
exit 0
`, logFile),
	})

	client := newDesktopTestServer(t)
	_, err := client.SendActions(context.Background(), connect.NewRequest(&pb.ActionBatch{
		Actions: []*pb.Action{
			{Action: &pb.Action_Pointer{Pointer: &pb.PointerEvent{X: 1, Y: 1}}},
			{Action: &pb.Action_Key{Key: &pb.KeyEvent{Input: &pb.KeyEvent_Key{Key: "Return"}}}},
			{Action: &pb.Action_Scroll{Scroll: &pb.ScrollEvent{Dy: 1}}},
		},
	}))
	if err == nil {
		t.Fatal("expected error when an action fails")
	}
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != connect.CodeInternal {
		t.Errorf("error = %v, want CodeInternal", err)
	}
	if !strings.Contains(err.Error(), "action 1") {
		t.Errorf("error = %v, want it to name the failing index", err)
	}

	got, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if strings.Contains(string(got), "click --repeat") {
		t.Errorf("scroll ran after a failed action:\n%s", got)
	}
}

func TestSendActions_ValidationErrorNeverShellsOut(t *testing.T) {
	// No fake xdotool on PATH: an invalid action anywhere in the batch must
	// reject the whole request before anything executes.
	client := newDesktopTestServer(t)
	_, err := client.SendActions(context.Background(), connect.NewRequest(&pb.ActionBatch{
		Actions: []*pb.Action{
			{Action: &pb.Action_Pointer{Pointer: &pb.PointerEvent{X: 1, Y: 1}}},
			{Action: &pb.Action_Pointer{Pointer: &pb.PointerEvent{X: -5, Y: 1}}},
		},
	}))
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != connect.CodeInvalidArgument {
		t.Errorf("error = %v, want CodeInvalidArgument", err)
	}
}
