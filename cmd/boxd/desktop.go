package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image/png"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	pb "github.com/superserve-ai/sandbox/proto/boxdpb"
	"github.com/superserve-ai/sandbox/proto/boxdpb/boxdpbconnect"
)

// ---------------------------------------------------------------------------
// Desktop service (Connect RPC) — GUI screenshot capture and input injection
// ---------------------------------------------------------------------------
//
// Capture shells out to ImageMagick's `import` (PNG to stdout, no temp
// files); input injection shells out to xdotool. Every invocation is bound
// to the request context via exec.CommandContext.
type desktopService struct {
	boxdpbconnect.UnimplementedDesktopServiceHandler
	ctx        *sandboxContext
	mutationMu sync.Mutex
	streamSlot chan struct{}
}

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

// defaultDesktopFPS is used when FrameConfig.fps is 0.
const defaultDesktopFPS = 4

// maxDesktopFPS bounds the capture cadence; each frame forks `import` and
// reads the whole framebuffer.
const maxDesktopFPS = 15

// screenshotTimeout bounds a single `import` invocation so a wedged X
// server stalls one frame, not the whole stream.
const screenshotTimeout = 5 * time.Second

// xdotoolTimeout bounds a single xdotool invocation (pointer/key/scroll/
// geometry/resize).
const xdotoolTimeout = 5 * time.Second

// desktopResizeTimeout covers modeline generation plus the xrandr update and
// verification sequence.
const desktopResizeTimeout = 15 * time.Second

// maxConsecutiveCaptureFailures ends the stream after this many capture
// failures in a row, so a permanently broken X server (crashed Xvfb, no
// DISPLAY) doesn't spin the ticker forever; a transient single failure is
// logged and skipped so one bad frame doesn't kill a long-lived stream.
const maxConsecutiveCaptureFailures = 5

// maxCoordinate bounds pointer coordinates. Deliberately not validated
// against the live display size (that would race concurrent resizes); this
// only rejects obviously malformed input.
const maxCoordinate = 1 << 16 // 65536

// maxScrollRepeat bounds how many synthetic wheel clicks a single Scroll
// call can generate, so a client-supplied dx/dy can't turn one RPC into an
// unbounded burst of xdotool invocations.
const maxScrollRepeat = 500

const (
	defaultDesktopDisplay = ":1"
	maxKeyLength          = 256
	maxTextLength         = 64 * 1024
	maxModifiers          = 8
	maxModifierLength     = 32
	maxScreenshotBytes    = 32 * 1024 * 1024
	maxDesktopDimension   = 8192
	minDesktopWidth       = 320
	minDesktopHeight      = 200
)

func newDesktopService(ctx *sandboxContext) *desktopService {
	if ctx == nil {
		ctx = &sandboxContext{}
	}
	return &desktopService{
		ctx:        ctx,
		streamSlot: make(chan struct{}, 1),
	}
}

// ---------------------------------------------------------------------------
// Stream — screenshot capture
// ---------------------------------------------------------------------------

// normalizeFrameConfig validates cfg and derives the effective format and
// capture interval.
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

	select {
	case s.streamSlot <- struct{}{}:
		defer func() { <-s.streamSlot }()
	default:
		return connect.NewError(connect.CodeResourceExhausted, errors.New("a desktop frame stream is already active"))
	}

	width, height, err := s.displayGeometry(ctx)
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

	var seq uint64
	var consecutiveFailures int
	for {
		frameStart := time.Now()
		img, err := s.captureScreenshot(ctx)
		switch {
		case ctx.Err() != nil:
			// Best-effort; the client may already be gone.
			_ = stream.Send(&pb.Frame{Event: &pb.Frame_End{End: &pb.FrameEndEvent{Status: "cancelled"}}})
			return nil
		case err != nil:
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
		default:
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

		// Pace off capture completion, not a free-running ticker: a ticker
		// always has a tick queued when capture overruns the interval,
		// which degrades the loop into back-to-back forks at 100% duty.
		// The floor guarantees idle time even when over budget, so a slow
		// X server lowers FPS instead of monopolizing a core.
		wait := interval - time.Since(frameStart)
		if minGap := interval / 4; wait < minGap {
			wait = minGap
		}
		select {
		case <-ctx.Done():
			_ = stream.Send(&pb.Frame{Event: &pb.Frame_End{End: &pb.FrameEndEvent{Status: "cancelled"}}})
			return nil
		case <-time.After(wait):
		}
	}
}

// Screenshot captures a single frame. It deliberately does not take the
// stream slot: the agent control loop (screenshot -> decide -> act) must keep
// working while a viewer holds a long-lived Stream open. Dimensions come from
// the PNG header rather than a second xdotool round trip.
func (s *desktopService) Screenshot(ctx context.Context, req *connect.Request[pb.ScreenshotRequest]) (*connect.Response[pb.ScreenshotResponse], error) {
	format := req.Msg.GetFormat()
	if format == pb.FrameFormat_FRAME_FORMAT_UNSPECIFIED {
		format = pb.FrameFormat_FRAME_FORMAT_PNG
	}
	if format != pb.FrameFormat_FRAME_FORMAT_PNG {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("unsupported frame format %v: only PNG is supported", format))
	}

	img, err := s.captureScreenshot(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(img))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("decode screenshot header: %w", err))
	}
	return connect.NewResponse(&pb.ScreenshotResponse{
		Image:  img,
		Width:  uint32(cfg.Width),
		Height: uint32(cfg.Height),
		Format: format,
	}), nil
}

// captureScreenshot runs ImageMagick's `import` against the root window and
// returns the PNG bytes written to stdout. Bound to a per-capture timeout
// derived from ctx so one wedged capture can't stall the stream forever.
func (s *desktopService) captureScreenshot(ctx context.Context) ([]byte, error) {
	capCtx, cancel := context.WithTimeout(ctx, screenshotTimeout)
	defer cancel()

	cmd, err := s.commandContext(capCtx, "import", "-window", "root", "png:-")
	if err != nil {
		return nil, fmt.Errorf("resolve import: %w", err)
	}
	out, err := cmd.Output()
	if err != nil {
		return nil, wrapExecErr("import -window root", err)
	}
	if len(out) == 0 {
		return nil, errors.New("import -window root: empty output")
	}
	if len(out) > maxScreenshotBytes {
		return nil, fmt.Errorf("import -window root: screenshot is %d bytes, limit is %d", len(out), maxScreenshotBytes)
	}
	return out, nil
}

// displayGeometry queries the virtual display's current resolution via
// xdotool, which boxd also uses for pointer/key injection.
func (s *desktopService) displayGeometry(ctx context.Context) (width, height uint32, err error) {
	geomCtx, cancel := context.WithTimeout(ctx, xdotoolTimeout)
	defer cancel()

	cmd, err := s.commandContext(geomCtx, "xdotool", "getdisplaygeometry")
	if err != nil {
		return 0, 0, fmt.Errorf("resolve xdotool: %w", err)
	}
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
// for it.
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
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	if err := s.runXdotool(ctx, args...); err != nil {
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
	if len(msg.GetModifiers()) > maxModifiers {
		return nil, fmt.Errorf("too many modifiers: %d, max %d", len(msg.GetModifiers()), maxModifiers)
	}
	for _, modifier := range msg.GetModifiers() {
		if modifier == "" || len(modifier) > maxModifierLength || strings.IndexByte(modifier, 0) >= 0 {
			return nil, fmt.Errorf("invalid modifier %q", modifier)
		}
	}
	switch in := msg.GetInput().(type) {
	case *pb.KeyEvent_Key:
		if in.Key == "" {
			return nil, errors.New("key is empty")
		}
		if len(in.Key) > maxKeyLength || strings.IndexByte(in.Key, 0) >= 0 {
			return nil, fmt.Errorf("key is invalid or exceeds %d bytes", maxKeyLength)
		}
		chord := strings.Join(append(append([]string{}, msg.GetModifiers()...), in.Key), "+")
		return []string{"key", "--", chord}, nil
	case *pb.KeyEvent_Text:
		if in.Text == "" {
			return nil, errors.New("text is empty")
		}
		if len(in.Text) > maxTextLength || strings.IndexByte(in.Text, 0) >= 0 {
			return nil, fmt.Errorf("text is invalid or exceeds %d bytes", maxTextLength)
		}
		// Modifiers don't apply to literal text entry. --delay 0 drops
		// xdotool's default 12ms/char pacing, which is for human visibility;
		// at that rate a long paste takes seconds.
		return []string{"type", "--delay", "0", "--", in.Text}, nil
	default:
		return nil, errors.New("one of key or text is required")
	}
}

func (s *desktopService) SendKey(ctx context.Context, req *connect.Request[pb.KeyEvent]) (*connect.Response[pb.KeyResponse], error) {
	args, err := keyArgs(req.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	if err := s.runXdotool(ctx, args...); err != nil {
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

	// --delay 0 drops xdotool's default 100ms pause between repeated
	// clicks; without it any repeat above ~50 outlives xdotoolTimeout and
	// gets killed mid-scroll.
	var cmds [][]string
	if dy != 0 {
		button := "5"
		if dy < 0 {
			button = "4"
		}
		cmds = append(cmds, []string{"click", "--repeat", strconv.Itoa(int(abs32(dy))), "--delay", "0", button})
	}
	if dx != 0 {
		button := "7"
		if dx < 0 {
			button = "6"
		}
		cmds = append(cmds, []string{"click", "--repeat", strconv.Itoa(int(abs32(dx))), "--delay", "0", button})
	}
	return cmds, nil
}

func (s *desktopService) Scroll(ctx context.Context, req *connect.Request[pb.ScrollEvent]) (*connect.Response[pb.ScrollResponse], error) {
	cmds, err := scrollCommands(req.Msg.GetDx(), req.Msg.GetDy())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	for _, args := range cmds {
		if err := s.runXdotool(ctx, args...); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
	}
	return connect.NewResponse(&pb.ScrollResponse{}), nil
}

// ---------------------------------------------------------------------------
// SendActions — ordered input batch
// ---------------------------------------------------------------------------

// maxBatchActions bounds a single SendActions request, which bounds the
// worst-case input-lock hold time.
const maxBatchActions = 64

// batchCommands validates every action in the batch and lowers each to its
// xdotool argument lists, reusing the exact validation of the unary RPCs.
// Returned as one slice per action so execution can report the failing index.
func batchCommands(actions []*pb.Action) ([][][]string, error) {
	if len(actions) == 0 {
		return nil, errors.New("actions is empty")
	}
	if len(actions) > maxBatchActions {
		return nil, fmt.Errorf("too many actions: %d, max %d", len(actions), maxBatchActions)
	}
	cmds := make([][][]string, len(actions))
	for i, action := range actions {
		switch a := action.GetAction().(type) {
		case *pb.Action_Pointer:
			args, err := pointerArgs(a.Pointer.GetX(), a.Pointer.GetY(), a.Pointer.GetButton(), a.Pointer.GetAction())
			if err != nil {
				return nil, fmt.Errorf("action %d: %w", i, err)
			}
			cmds[i] = [][]string{args}
		case *pb.Action_Key:
			args, err := keyArgs(a.Key)
			if err != nil {
				return nil, fmt.Errorf("action %d: %w", i, err)
			}
			cmds[i] = [][]string{args}
		case *pb.Action_Scroll:
			scroll, err := scrollCommands(a.Scroll.GetDx(), a.Scroll.GetDy())
			if err != nil {
				return nil, fmt.Errorf("action %d: %w", i, err)
			}
			cmds[i] = scroll
		default:
			return nil, fmt.Errorf("action %d: one of pointer, key, or scroll is required", i)
		}
	}
	return cmds, nil
}

func (s *desktopService) SendActions(ctx context.Context, req *connect.Request[pb.ActionBatch]) (*connect.Response[pb.ActionBatchResponse], error) {
	cmds, err := batchCommands(req.Msg.GetActions())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	for i, actionCmds := range cmds {
		for _, args := range actionCmds {
			if err := s.runXdotool(ctx, args...); err != nil {
				return nil, connect.NewError(connect.CodeInternal,
					fmt.Errorf("action %d failed after %d executed: %w", i, i, err))
			}
		}
	}
	return connect.NewResponse(&pb.ActionBatchResponse{Executed: uint32(len(cmds))}), nil
}

func abs32(v int32) int64 {
	if v < 0 {
		return -int64(v)
	}
	return int64(v)
}

// ---------------------------------------------------------------------------
// Resize
// ---------------------------------------------------------------------------

// validateResizeDims bounds the framebuffer allocation and requires the width
// alignment used by VESA CVT modelines.
func validateResizeDims(width, height uint32) error {
	if width < minDesktopWidth || height < minDesktopHeight ||
		width > maxDesktopDimension || height > maxDesktopDimension || width%8 != 0 {
		return fmt.Errorf("invalid resize dimensions: %dx%d", width, height)
	}
	return nil
}

func connectedOutput(query []byte) (string, error) {
	for _, line := range strings.Split(string(query), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "connected" {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("xrandr --query: no connected output in %q", bytes.TrimSpace(query))
}

func parseCVTModeline(output []byte) (string, []string, error) {
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "Modeline" {
			continue
		}
		name := strings.Trim(fields[1], `"`)
		if name == "" {
			break
		}
		args := append([]string{name}, fields[2:]...)
		return name, args, nil
	}
	return "", nil, fmt.Errorf("cvt: no modeline in %q", bytes.TrimSpace(output))
}

func (s *desktopService) Resize(ctx context.Context, req *connect.Request[pb.DesktopResizeRequest]) (*connect.Response[pb.DesktopResizeResponse], error) {
	width, height := req.Msg.GetWidth(), req.Msg.GetHeight()
	if err := validateResizeDims(width, height); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()

	// Xvfb exposes only its initial mode. Generate and attach a CVT modeline
	// before selecting it so arbitrary supported desktop sizes work rather than
	// only resolutions that happened to exist at boot.
	resizeCtx, cancel := context.WithTimeout(ctx, desktopResizeTimeout)
	defer cancel()

	queryCmd, err := s.commandContext(resizeCtx, "xrandr", "--query")
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("resolve xrandr: %w", err))
	}
	query, err := queryCmd.CombinedOutput()
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, wrapExecErrOutput("xrandr --query", query, err))
	}
	outputName, err := connectedOutput(query)
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}

	cvtCmd, err := s.commandContext(resizeCtx, "cvt", strconv.FormatUint(uint64(width), 10), strconv.FormatUint(uint64(height), 10), "60")
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("resolve cvt: %w", err))
	}
	cvtOutput, err := cvtCmd.CombinedOutput()
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, wrapExecErrOutput("cvt", cvtOutput, err))
	}
	modeName, modelineArgs, err := parseCVTModeline(cvtOutput)
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}

	// Newmode/addmode can legitimately fail when a previous call already
	// installed the same mode. The final mode switch is authoritative: if it
	// succeeds, the mode exists and is attached to this output.
	newModeCmd, err := s.commandContext(resizeCtx, "xrandr", append([]string{"--newmode"}, modelineArgs...)...)
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("resolve xrandr: %w", err))
	}
	newModeOutput, _ := newModeCmd.CombinedOutput()

	addModeCmd, err := s.commandContext(resizeCtx, "xrandr", "--addmode", outputName, modeName)
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("resolve xrandr: %w", err))
	}
	addModeOutput, _ := addModeCmd.CombinedOutput()

	setModeCmd, err := s.commandContext(resizeCtx, "xrandr", "--output", outputName, "--mode", modeName)
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("resolve xrandr: %w", err))
	}
	if setModeOutput, setModeErr := setModeCmd.CombinedOutput(); setModeErr != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf(
			"set desktop mode %s: %w (newmode: %s; addmode: %s)",
			modeName,
			wrapExecErrOutput("xrandr --output", setModeOutput, setModeErr),
			strings.TrimSpace(string(newModeOutput)),
			strings.TrimSpace(string(addModeOutput)),
		))
	}
	actualWidth, actualHeight, err := s.displayGeometry(resizeCtx)
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("verify resized display: %w", err))
	}
	if actualWidth != width || actualHeight != height {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf(
			"display geometry after resize is %dx%d, want %dx%d",
			actualWidth, actualHeight, width, height,
		))
	}

	return connect.NewResponse(&pb.DesktopResizeResponse{}), nil
}

// ---------------------------------------------------------------------------
// Shared exec helpers
// ---------------------------------------------------------------------------

// runXdotool runs xdotool with the given args, bound to a per-call timeout
// derived from ctx, matching the cancellation convention runProcess uses for
// user-requested commands.
func (s *desktopService) runXdotool(ctx context.Context, args ...string) error {
	callCtx, cancel := context.WithTimeout(ctx, xdotoolTimeout)
	defer cancel()

	cmd, err := s.commandContext(callCtx, "xdotool", args...)
	if err != nil {
		return fmt.Errorf("resolve xdotool: %w", err)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return wrapExecErrOutput("xdotool "+strings.Join(args, " "), out, err)
	}
	return nil
}

// commandContext gives desktop tools the sandbox's effective environment.
// In particular, DISPLAY is supplied by the desktop template through /init;
// boxd itself starts before template defaults are applied and therefore does
// not inherit that value in its process environment.
func (s *desktopService) commandContext(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
	envVars, _, _ := s.ctx.snapshot()

	pathValue := os.Getenv("PATH")
	if pathValue == "" {
		pathValue = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	}
	display := os.Getenv("DISPLAY")
	if display == "" {
		display = defaultDesktopDisplay
	}

	env := append(os.Environ(), "PATH="+pathValue, "DISPLAY="+display)
	for key, value := range envVars {
		env = append(env, key+"="+value)
	}

	resolved, err := lookPathIn(name, pathFromEnv(env))
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, resolved, args...)
	cmd.Env = env
	return cmd, nil
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
