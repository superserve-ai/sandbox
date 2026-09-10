package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	pb "github.com/superserve-ai/sandbox/proto/boxdpb"
	"github.com/superserve-ai/sandbox/proto/boxdpb/boxdpbconnect"
)

// ---------------------------------------------------------------------------
// Desktop service (Connect RPC) — GUI screenshot capture and input injection
// ---------------------------------------------------------------------------
//
// Screenshot capture shells out to ImageMagick's `import -window root png:-`,
// writing the PNG straight to stdout instead of a temp file — no disk I/O or
// cleanup, and it composites the whole root window (all workspaces/windows)
// in one shot the way `xwd | convert` would need two processes and an
// intermediate format for. PNG is lossless, which matters for reading text
// and UI chrome in a screenshot the caller may OCR or diff; a future format
// (e.g. JPEG for lower-bandwidth streaming) can extend FrameFormat without
// an RPC break.
//
// Input injection shells out to xdotool for the same reasons runProcess
// shells out to the requested command: it's the de facto standard for
// synthesizing X11 input, already battle-tested, and reimplementing XTest
// calls in Go would buy nothing. Every xdotool invocation is bound to the
// request context via exec.CommandContext, matching runProcess's
// cancellation convention.
// desktopService embeds UnimplementedDesktopServiceHandler so the type stays
// source-compatible with future RPCs added to the proto (they'd return
// CodeUnimplemented here until implemented), matching processService and
// filesystemService's pattern.
type desktopService struct {
	boxdpbconnect.UnimplementedDesktopServiceHandler
}

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

// defaultDesktopFPS is used when FrameConfig.fps is 0.
const defaultDesktopFPS = 4

// maxDesktopFPS bounds the capture cadence. `import` forks a process and
// reads the whole framebuffer per call; anything higher burns CPU for a
// control-loop use case (click, look, click) without a visible benefit over
// a real screen-share protocol, which this RPC is not trying to be.
const maxDesktopFPS = 15

// screenshotTimeout bounds a single `import` invocation so a wedged X
// server stalls one frame, not the whole stream.
const screenshotTimeout = 5 * time.Second

// xdotoolTimeout bounds a single xdotool invocation (pointer/key/scroll/
// geometry/resize).
const xdotoolTimeout = 5 * time.Second

// maxConsecutiveCaptureFailures ends the stream after this many capture
// failures in a row, so a permanently broken X server (crashed Xvfb, no
// DISPLAY) doesn't spin the ticker forever; a transient single failure is
// logged and skipped so one bad frame doesn't kill a long-lived stream.
const maxConsecutiveCaptureFailures = 5

// maxCoordinate bounds pointer coordinates and resize dimensions to a
// generous but finite range. There's no cheap way to validate against the
// *current* display size without querying geometry on every call (racing
// concurrent resizes for no real benefit), so this only catches obviously
// malformed input (negative values, accidental overflow-sized numbers)
// rather than enforcing an exact bound.
const maxCoordinate = 1 << 16 // 65536

// maxScrollRepeat bounds how many synthetic wheel clicks a single Scroll
// call can generate, so a client-supplied dx/dy can't turn one RPC into an
// unbounded burst of xdotool invocations.
const maxScrollRepeat = 500

func newDesktopService() *desktopService {
	return &desktopService{}
}

// ---------------------------------------------------------------------------
// Stream — screenshot capture
// ---------------------------------------------------------------------------

// normalizeFrameConfig validates cfg and derives the effective format and
// capture interval. Pulled out of Stream as a pure function so the
// validation and fps-clamping logic is unit-testable without a live
// connect.ServerStream (which has no exported constructor).
func normalizeFrameConfig(cfg *pb.FrameConfig) (format pb.FrameFormat, interval time.Duration, err error) {
	format = cfg.GetFormat()
	if format == pb.FrameFormat_FRAME_FORMAT_UNSPECIFIED {
		format = pb.FrameFormat_FRAME_FORMAT_PNG
	}
	if format != pb.FrameFormat_FRAME_FORMAT_PNG {
		return 0, 0, fmt.Errorf("unsupported frame format %v: only PNG is supported", format)
	}

	fps := cfg.GetFps()
	if fps == 0 {
		fps = defaultDesktopFPS
	}
	if fps > maxDesktopFPS {
		fps = maxDesktopFPS
	}
	return format, time.Second / time.Duration(fps), nil
}

func (s *desktopService) Stream(ctx context.Context, req *connect.Request[pb.FrameConfig], stream *connect.ServerStream[pb.Frame]) error {
	format, interval, err := normalizeFrameConfig(req.Msg)
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}

	width, height, err := displayGeometry(ctx)
	if err != nil {
		return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("query display geometry: %w", err))
	}

	if err := stream.Send(&pb.Frame{Event: &pb.Frame_Start{Start: &pb.FrameStartEvent{
		Width:  width,
		Height: height,
		Format: format,
	}}}); err != nil {
		return err
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var seq uint64
	var consecutiveFailures int
	for {
		select {
		case <-ctx.Done():
			// Best-effort: the client is gone, so this Send will likely fail
			// too, but it costs nothing to try and it's how a well-behaved
			// consumer (draining after cancel) would learn the stream ended
			// cleanly rather than mid-frame.
			_ = stream.Send(&pb.Frame{Event: &pb.Frame_End{End: &pb.FrameEndEvent{Status: "cancelled"}}})
			return nil
		case <-ticker.C:
			img, err := captureScreenshot(ctx)
			if err != nil {
				consecutiveFailures++
				log.Printf("desktop: screenshot capture failed (%d/%d consecutive): %v",
					consecutiveFailures, maxConsecutiveCaptureFailures, err)
				if consecutiveFailures >= maxConsecutiveCaptureFailures {
					_ = stream.Send(&pb.Frame{Event: &pb.Frame_End{End: &pb.FrameEndEvent{
						Status: "error",
						Error:  err.Error(),
					}}})
					return connect.NewError(connect.CodeInternal,
						fmt.Errorf("screenshot capture failed %d times consecutively: %w", consecutiveFailures, err))
				}
				continue
			}
			consecutiveFailures = 0
			seq++
			if err := stream.Send(&pb.Frame{Event: &pb.Frame_Data{Data: &pb.FrameDataEvent{
				Image:           img,
				TimestampUnixMs: time.Now().UnixMilli(),
				Sequence:        seq,
			}}}); err != nil {
				return err
			}
		}
	}
}

// captureScreenshot runs ImageMagick's `import` against the root window and
// returns the PNG bytes written to stdout. Bound to a per-capture timeout
// derived from ctx so one wedged capture can't stall the stream forever.
func captureScreenshot(ctx context.Context) ([]byte, error) {
	capCtx, cancel := context.WithTimeout(ctx, screenshotTimeout)
	defer cancel()

	cmd := exec.CommandContext(capCtx, "import", "-window", "root", "png:-")
	out, err := cmd.Output()
	if err != nil {
		return nil, wrapExecErr("import -window root", err)
	}
	if len(out) == 0 {
		return nil, errors.New("import -window root: empty output")
	}
	return out, nil
}

// displayGeometry queries the virtual display's current resolution via
// xdotool, which boxd also uses for pointer/key injection.
func displayGeometry(ctx context.Context) (width, height uint32, err error) {
	geomCtx, cancel := context.WithTimeout(ctx, xdotoolTimeout)
	defer cancel()

	cmd := exec.CommandContext(geomCtx, "xdotool", "getdisplaygeometry")
	out, err := cmd.Output()
	if err != nil {
		return 0, 0, wrapExecErr("xdotool getdisplaygeometry", err)
	}
	fields := strings.Fields(string(out))
	if len(fields) != 2 {
		return 0, 0, fmt.Errorf("xdotool getdisplaygeometry: unexpected output %q", out)
	}
	w, err := strconv.ParseUint(fields[0], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("xdotool getdisplaygeometry: parse width %q: %w", fields[0], err)
	}
	h, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("xdotool getdisplaygeometry: parse height %q: %w", fields[1], err)
	}
	return uint32(w), uint32(h), nil
}

// ---------------------------------------------------------------------------
// SendPointer
// ---------------------------------------------------------------------------

// pointerButtonArg maps a PointerButton to xdotool's 1/2/3 X11 button
// numbering (left/middle/right). Unspecified defaults to left, matching the
// proto doc comment.
func pointerButtonArg(b pb.PointerButton) (string, error) {
	switch b {
	case pb.PointerButton_POINTER_BUTTON_UNSPECIFIED, pb.PointerButton_POINTER_BUTTON_LEFT:
		return "1", nil
	case pb.PointerButton_POINTER_BUTTON_MIDDLE:
		return "2", nil
	case pb.PointerButton_POINTER_BUTTON_RIGHT:
		return "3", nil
	default:
		return "", fmt.Errorf("unknown pointer button %v", b)
	}
}

func validCoordinate(v int32) bool {
	return v >= 0 && v < maxCoordinate
}

// pointerArgs validates a PointerEvent and builds the xdotool argument list
// for it. Pure and side-effect-free so request validation is testable
// without shelling out.
func pointerArgs(x, y int32, button pb.PointerButton, action pb.PointerAction) ([]string, error) {
	if !validCoordinate(x) || !validCoordinate(y) {
		return nil, fmt.Errorf("coordinates out of range: (%d, %d)", x, y)
	}
	buttonArg, err := pointerButtonArg(button)
	if err != nil {
		return nil, err
	}

	xs, ys := strconv.Itoa(int(x)), strconv.Itoa(int(y))
	switch action {
	case pb.PointerAction_POINTER_ACTION_UNSPECIFIED, pb.PointerAction_POINTER_ACTION_MOVE:
		return []string{"mousemove", xs, ys}, nil
	case pb.PointerAction_POINTER_ACTION_DOWN:
		return []string{"mousemove", xs, ys, "mousedown", buttonArg}, nil
	case pb.PointerAction_POINTER_ACTION_UP:
		return []string{"mousemove", xs, ys, "mouseup", buttonArg}, nil
	case pb.PointerAction_POINTER_ACTION_CLICK:
		return []string{"mousemove", xs, ys, "click", buttonArg}, nil
	case pb.PointerAction_POINTER_ACTION_DOUBLE_CLICK:
		return []string{"mousemove", xs, ys, "click", "--repeat", "2", buttonArg}, nil
	default:
		return nil, fmt.Errorf("unknown pointer action %v", action)
	}
}

func (s *desktopService) SendPointer(ctx context.Context, req *connect.Request[pb.PointerEvent]) (*connect.Response[pb.PointerResponse], error) {
	args, err := pointerArgs(req.Msg.GetX(), req.Msg.GetY(), req.Msg.GetButton(), req.Msg.GetAction())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := runXdotool(ctx, args...); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&pb.PointerResponse{}), nil
}

// ---------------------------------------------------------------------------
// SendKey
// ---------------------------------------------------------------------------

// keyArgs validates a KeyEvent and builds the xdotool argument list for it.
// Takes the whole message (rather than just the oneof) because the
// generated oneof interface type (isKeyEvent_Input) is unexported.
func keyArgs(msg *pb.KeyEvent) ([]string, error) {
	switch in := msg.GetInput().(type) {
	case *pb.KeyEvent_Key:
		if in.Key == "" {
			return nil, errors.New("key is empty")
		}
		chord := strings.Join(append(append([]string{}, msg.GetModifiers()...), in.Key), "+")
		return []string{"key", "--", chord}, nil
	case *pb.KeyEvent_Text:
		if in.Text == "" {
			return nil, errors.New("text is empty")
		}
		// Modifiers don't apply to literal text entry; xdotool type has no
		// concept of a held modifier while typing a string.
		return []string{"type", "--", in.Text}, nil
	default:
		return nil, errors.New("one of key or text is required")
	}
}

func (s *desktopService) SendKey(ctx context.Context, req *connect.Request[pb.KeyEvent]) (*connect.Response[pb.KeyResponse], error) {
	args, err := keyArgs(req.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := runXdotool(ctx, args...); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&pb.KeyResponse{}), nil
}

// ---------------------------------------------------------------------------
// Scroll
// ---------------------------------------------------------------------------

// scrollCommands validates a scroll delta and builds the xdotool argument
// lists needed to realize it (one per nonzero axis; each axis maps to a
// distinct X11 wheel button, so they can't be combined into a single
// invocation). X11 wheel buttons: 4 = up, 5 = down, 6 = left, 7 = right.
// Negative dy scrolls up (content moves down), matching typical wheel
// conventions.
func scrollCommands(dx, dy int32) ([][]string, error) {
	if dx == 0 && dy == 0 {
		return nil, nil
	}
	if abs32(dx) > maxScrollRepeat || abs32(dy) > maxScrollRepeat {
		return nil, fmt.Errorf("scroll delta out of range: (%d, %d), max magnitude %d", dx, dy, maxScrollRepeat)
	}

	var cmds [][]string
	if dy != 0 {
		button := "5"
		if dy < 0 {
			button = "4"
		}
		cmds = append(cmds, []string{"click", "--repeat", strconv.Itoa(int(abs32(dy))), button})
	}
	if dx != 0 {
		button := "7"
		if dx < 0 {
			button = "6"
		}
		cmds = append(cmds, []string{"click", "--repeat", strconv.Itoa(int(abs32(dx))), button})
	}
	return cmds, nil
}

func (s *desktopService) Scroll(ctx context.Context, req *connect.Request[pb.ScrollEvent]) (*connect.Response[pb.ScrollResponse], error) {
	cmds, err := scrollCommands(req.Msg.GetDx(), req.Msg.GetDy())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	for _, args := range cmds {
		if err := runXdotool(ctx, args...); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
	}
	return connect.NewResponse(&pb.ScrollResponse{}), nil
}

func abs32(v int32) int32 {
	if v < 0 {
		return -v
	}
	return v
}

// ---------------------------------------------------------------------------
// Resize
// ---------------------------------------------------------------------------

// validateResizeDims rejects zero and absurdly large dimensions. It doesn't
// enforce a minimum meaningful resolution beyond nonzero, since that's a
// policy choice best left to the caller (SDK/console), not boxd.
func validateResizeDims(width, height uint32) error {
	if width == 0 || height == 0 || width > maxCoordinate || height > maxCoordinate {
		return fmt.Errorf("invalid resize dimensions: %dx%d", width, height)
	}
	return nil
}

func (s *desktopService) Resize(ctx context.Context, req *connect.Request[pb.DesktopResizeRequest]) (*connect.Response[pb.DesktopResizeResponse], error) {
	width, height := req.Msg.GetWidth(), req.Msg.GetHeight()
	if err := validateResizeDims(width, height); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	// xdotool has no display-resize primitive (getdisplaygeometry is
	// read-only); xrandr is the standard tool for changing an X11 display's
	// resolution, so Resize shells out to it instead.
	resizeCtx, cancel := context.WithTimeout(ctx, xdotoolTimeout)
	defer cancel()
	mode := fmt.Sprintf("%dx%d", width, height)
	cmd := exec.CommandContext(resizeCtx, "xrandr", "-s", mode)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, connect.NewError(connect.CodeInternal, wrapExecErrOutput("xrandr -s "+mode, out, err))
	}

	return connect.NewResponse(&pb.DesktopResizeResponse{}), nil
}

// ---------------------------------------------------------------------------
// Shared exec helpers
// ---------------------------------------------------------------------------

// runXdotool runs xdotool with the given args, bound to a per-call timeout
// derived from ctx, matching the cancellation convention runProcess uses for
// user-requested commands.
func runXdotool(ctx context.Context, args ...string) error {
	callCtx, cancel := context.WithTimeout(ctx, xdotoolTimeout)
	defer cancel()

	cmd := exec.CommandContext(callCtx, "xdotool", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return wrapExecErrOutput("xdotool "+strings.Join(args, " "), out, err)
	}
	return nil
}

// wrapExecErr wraps an exec error, surfacing stderr (populated by
// cmd.Output() on *exec.ExitError) when present so the caller sees why the
// external tool failed, not just its exit status.
func wrapExecErr(desc string, err error) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) && len(ee.Stderr) > 0 {
		return fmt.Errorf("%s: %w: %s", desc, err, bytes.TrimSpace(ee.Stderr))
	}
	return fmt.Errorf("%s: %w", desc, err)
}

// wrapExecErrOutput is wrapExecErr's counterpart for callers using
// CombinedOutput, which returns stdout+stderr directly rather than via
// ExitError.Stderr.
func wrapExecErrOutput(desc string, out []byte, err error) error {
	if len(out) > 0 {
		return fmt.Errorf("%s: %w: %s", desc, err, bytes.TrimSpace(out))
	}
	return fmt.Errorf("%s: %w", desc, err)
}
