package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"image"
	"image/jpeg"
	"image/png"
	"io"
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
// Pointer/scroll injection and frame capture use a persistent X11 connection
// (desktop_x11.go) when one is available, falling back to shelling out
// (xdotool / ImageMagick `import`). Keyboard input always shells out to
// xdotool, which owns keysym resolution and text-entry keymap handling.
type desktopService struct {
	boxdpbconnect.UnimplementedDesktopServiceHandler
	ctx          *sandboxContext
	mutationMu   sync.Mutex
	streamSlot   chan struct{}
	captureSlots chan struct{}
	// x11 holds the persistent display connection (desktop_x11.go). When it
	// is unavailable, every operation falls back to the shell tools.
	x11 x11Holder
}

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

// defaultDesktopFPS is used when FrameConfig.fps is 0.
const defaultDesktopFPS = 4

// maxDesktopFPS bounds the capture cadence; each frame reads the whole
// framebuffer (and forks `import` on the fallback path).
const maxDesktopFPS = 15

// screenshotTimeout bounds a single fallback `import` invocation so a
// wedged X server stalls one frame, not the whole stream.
const screenshotTimeout = 5 * time.Second

// xdotoolTimeout bounds a single xdotool invocation (pointer/key/scroll/
// geometry/resize).
const xdotoolTimeout = 5 * time.Second

// desktopResizeTimeout covers modeline generation plus the xrandr update and
// verification sequence.
const desktopResizeTimeout = 15 * time.Second

// maxConsecutiveCaptureFailures ends the stream after this many capture
// failures in a row, so a permanently broken X server (crashed Xvnc, no
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
	// maxConcurrentCaptures bounds simultaneous `import` processes (each up to
	// maxScreenshotBytes of buffer) across unary screenshots and stream
	// frames, so concurrent viewers cannot exhaust the sandbox.
	maxConcurrentCaptures = 4
	// maxDesktopMessageBytes caps a decoded request message. The edge proxy
	// caps the encoded body at the same size, but a compressed body can
	// expand past that inside boxd, before the action-count and text-length
	// checks run. Sized like the proxy cap: a 64-action batch of 64KiB text
	// under worst-case JSON escaping, plus headroom.
	maxDesktopMessageBytes = 32 << 20
	maxDesktopDimension    = 8192
	minDesktopWidth        = 320
	minDesktopHeight       = 200
)

// desktopHandlerOptions are applied wherever the DesktopService handler is
// mounted, so tests exercise the same limits as boxd itself.
func desktopHandlerOptions() []connect.HandlerOption {
	return []connect.HandlerOption{connect.WithReadMaxBytes(maxDesktopMessageBytes)}
}

func newDesktopService(ctx *sandboxContext) *desktopService {
	if ctx == nil {
		ctx = &sandboxContext{}
	}
	return &desktopService{
		ctx:          ctx,
		streamSlot:   make(chan struct{}, 1),
		captureSlots: make(chan struct{}, maxConcurrentCaptures),
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
	if _, err := screenshotFormat(format); err != nil {
		return 0, 0, err
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
	var lastFrameHash uint64
	for {
		frameStart := time.Now()
		img, err := s.captureScreenshot(ctx, format, nil)
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
			// An unchanged frame (identical encoded bytes; encoding is
			// deterministic) is sent as a keepalive, not a duplicate image.
			hash := fnv64(img)
			if seq > 0 && hash == lastFrameHash {
				if err := stream.Send(&pb.Frame{Event: &pb.Frame_Keepalive{Keepalive: &pb.KeepAlive{}}}); err != nil {
					return err
				}
				break
			}
			lastFrameHash = hash
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

// displayName resolves the X display for the persistent backend, preferring
// the sandbox environment (boxd starts before template defaults apply, so
// its own process env may lack DISPLAY).
func (s *desktopService) displayName() string {
	envVars, _, _ := s.ctx.snapshot()
	if d := envVars["DISPLAY"]; d != "" {
		return d
	}
	if d := os.Getenv("DISPLAY"); d != "" {
		return d
	}
	return defaultDesktopDisplay
}

func fnv64(b []byte) uint64 {
	h := fnv.New64a()
	_, _ = h.Write(b)
	return h.Sum64()
}

// encodeFramePNG encodes a captured frame. BestSpeed: encode latency
// matters more than size for transient frames.
// jpegQuality trades a little detail for frames a few times smaller than
// PNG; text on a desktop stays legible to a model well above this.
const jpegQuality = 80

func encodeFrame(frame *image.RGBA, format pb.FrameFormat) ([]byte, error) {
	var buf bytes.Buffer
	var err error
	if format == pb.FrameFormat_FRAME_FORMAT_JPEG {
		err = jpeg.Encode(&buf, frame, &jpeg.Options{Quality: jpegQuality})
	} else {
		enc := png.Encoder{CompressionLevel: png.BestSpeed}
		err = enc.Encode(&buf, frame)
	}
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// importFormat is the ImageMagick output spec for a frame format.
func importFormat(format pb.FrameFormat) string {
	if format == pb.FrameFormat_FRAME_FORMAT_JPEG {
		return "jpeg:-"
	}
	return "png:-"
}

// Screenshot captures a single frame. It deliberately does not take the
// stream slot: the agent control loop (screenshot -> decide -> act) must keep
// working while a viewer holds a long-lived Stream open. Dimensions come from
// the PNG header rather than a second xdotool round trip.
func (s *desktopService) Screenshot(ctx context.Context, req *connect.Request[pb.ScreenshotRequest]) (*connect.Response[pb.ScreenshotResponse], error) {
	format, err := screenshotFormat(req.Msg.GetFormat())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	resp, err := s.screenshotResponse(ctx, format, nil)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(resp), nil
}

// screenshotFormat resolves a requested frame format; only PNG exists today.
func screenshotFormat(format pb.FrameFormat) (pb.FrameFormat, error) {
	switch format {
	case pb.FrameFormat_FRAME_FORMAT_UNSPECIFIED, pb.FrameFormat_FRAME_FORMAT_PNG:
		return pb.FrameFormat_FRAME_FORMAT_PNG, nil
	case pb.FrameFormat_FRAME_FORMAT_JPEG:
		return pb.FrameFormat_FRAME_FORMAT_JPEG, nil
	default:
		return 0, fmt.Errorf("unsupported frame format %v: PNG and JPEG are supported", format)
	}
}

// screenshotResponse captures one frame and reads its dimensions from the
// PNG header. Shared by Screenshot and Step.
func (s *desktopService) screenshotResponse(ctx context.Context, format pb.FrameFormat, watch *frameWatch) (*pb.ScreenshotResponse, error) {
	img, err := s.captureScreenshot(ctx, format, watch)
	if err != nil {
		return nil, err
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(img))
	if err != nil {
		return nil, fmt.Errorf("decode screenshot header: %w", err)
	}
	return &pb.ScreenshotResponse{
		Image:  img,
		Width:  uint32(cfg.Width),
		Height: uint32(cfg.Height),
		Format: format,
	}, nil
}

// frameWatch is a change wait armed before a Step's actions: the frame hash
// to compare against and how long to wait for a different one. changed is
// set by the capture.
type frameWatch struct {
	baseline uint64
	deadline time.Time
	changed  bool
}

// armFrameWatch snapshots the display for a later change comparison. nil
// means the backend cannot compare (no X11 connection or no DAMAGE), and
// the caller keeps a fixed settle.
func (s *desktopService) armFrameWatch(ctx context.Context) *frameWatch {
	armCtx, cancel := context.WithTimeout(ctx, screenshotTimeout)
	defer cancel()
	w := &frameWatch{}
	attempted, err := s.runX11(armCtx, func(_ context.Context, b *x11Backend) error {
		var err error
		w.baseline, err = b.armChangeWatch()
		return err
	})
	if !attempted || err != nil {
		return nil
	}
	return w
}

// captureScreenshot returns the current frame encoded as format: the
// persistent X11 backend (in-process capture + encode, cursor composited)
// when available, else ImageMagick's `import`. With watch, the X11 capture
// waits for a changed frame first. Bound to a per-capture timeout derived
// from ctx so one wedged capture can't stall the stream forever.
func (s *desktopService) captureScreenshot(ctx context.Context, format pb.FrameFormat, watch *frameWatch) ([]byte, error) {
	// One slot per capture on either backend: the X11 path also holds a
	// full frame plus its PNG encoding in memory.
	select {
	case s.captureSlots <- struct{}{}:
		defer func() { <-s.captureSlots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	// One capture deadline for both backends: a stalled X server must not
	// hold a capture slot for as long as a stream stays connected.
	capCtx, cancel := context.WithTimeout(ctx, screenshotTimeout)
	defer cancel()
	var encoded []byte
	attempted, err := s.runX11(capCtx, func(ctx context.Context, b *x11Backend) error {
		var frame *image.RGBA
		var err error
		if watch != nil {
			frame, watch.changed, err = b.captureChanged(ctx, watch.baseline, watch.deadline)
		} else {
			frame, err = b.Capture()
		}
		if err != nil {
			return err
		}
		encoded, err = encodeFrame(frame, format)
		return err
	})
	if attempted && err == nil {
		if len(encoded) > maxScreenshotBytes {
			return nil, fmt.Errorf("screenshot is %d bytes, limit is %d", len(encoded), maxScreenshotBytes)
		}
		return encoded, nil
	}
	if capCtx.Err() != nil {
		return nil, capCtx.Err()
	}
	// A read is safe to redo through the shell path. The X11 failure is the
	// one worth knowing about, so it is kept if the shell path fails too.
	var x11Err error
	if attempted {
		x11Err = err
		log.Printf("desktop: x11 capture failed, using the shell path: %v", err)
	}
	if watch != nil {
		// The backend that armed the watch is gone; the shell path cannot
		// compare, so it keeps the settle instead.
		select {
		case <-time.After(time.Until(watch.deadline)):
		case <-capCtx.Done():
			return nil, capCtx.Err()
		}
	}

	cmd, err := s.commandContext(capCtx, "import", "-window", "root", "-quality", strconv.Itoa(jpegQuality), importFormat(format))
	if err != nil {
		return nil, shellCaptureError(x11Err, fmt.Errorf("resolve import: %w", err))
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, shellCaptureError(x11Err, fmt.Errorf("import -window root: %w", err))
	}
	if err := cmd.Start(); err != nil {
		return nil, shellCaptureError(x11Err, fmt.Errorf("import -window root: %w", err))
	}
	// Read one byte past the cap at most, so an oversized frame is rejected
	// without ever being buffered; killing import makes Wait return promptly.
	out, readErr := io.ReadAll(io.LimitReader(stdout, maxScreenshotBytes+1))
	if readErr != nil || len(out) > maxScreenshotBytes {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if readErr != nil {
			return nil, shellCaptureError(x11Err, fmt.Errorf("import -window root: read: %w", readErr))
		}
		return nil, shellCaptureError(x11Err, fmt.Errorf("import -window root: screenshot exceeds %d bytes", maxScreenshotBytes))
	}
	if err := cmd.Wait(); err != nil {
		return nil, shellCaptureError(x11Err, wrapExecErrOutput("import -window root", stderr.Bytes(), err))
	}
	if len(out) == 0 {
		return nil, shellCaptureError(x11Err, errors.New("import -window root: empty output"))
	}
	return out, nil
}

// shellCaptureError reports a shell-path capture failure together with the
// X11 failure that sent the capture there, when there was one.
func shellCaptureError(x11Err, shellErr error) error {
	if x11Err == nil {
		return shellErr
	}
	return fmt.Errorf("%w (after x11 capture failed: %v)", shellErr, x11Err)
}

// displayGeometry queries the virtual display's current resolution — via the
// persistent connection when available, else xdotool.
func (s *desktopService) displayGeometry(ctx context.Context) (width, height uint32, err error) {
	geomCtx, cancel := context.WithTimeout(ctx, xdotoolTimeout)
	defer cancel()
	if attempted, x11Err := s.runX11(geomCtx, func(_ context.Context, b *x11Backend) error {
		width, height, err = b.Geometry()
		return err
	}); attempted && x11Err == nil {
		return width, height, nil
	}
	if geomCtx.Err() != nil {
		return 0, 0, geomCtx.Err()
	}

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

// execPointer delivers a validated pointer event: persistent backend when
// reachable, xdotool only when no backend was available. Once the backend
// has been asked, its error is returned as is; replaying through xdotool
// could deliver a click twice. Callers hold mutationMu.
func (s *desktopService) execPointer(ctx context.Context, ev *pb.PointerEvent, fallbackArgs []string) error {
	inputCtx, cancel := context.WithTimeout(ctx, xdotoolTimeout)
	defer cancel()
	if attempted, err := s.runX11(inputCtx, func(_ context.Context, b *x11Backend) error {
		return b.Pointer(ev.GetX(), ev.GetY(), ev.GetButton(), ev.GetAction())
	}); attempted {
		return err
	}
	return s.runXdotool(ctx, fallbackArgs...)
}

// execScroll delivers a validated scroll event; same backend/fallback rule.
func (s *desktopService) execScroll(ctx context.Context, ev *pb.ScrollEvent, fallbackCmds [][]string) error {
	inputCtx, cancel := context.WithTimeout(ctx, xdotoolTimeout)
	defer cancel()
	if attempted, err := s.runX11(inputCtx, func(_ context.Context, b *x11Backend) error {
		return b.Scroll(ev.GetDx(), ev.GetDy())
	}); attempted {
		return err
	}
	for _, args := range fallbackCmds {
		if err := s.runXdotool(ctx, args...); err != nil {
			return err
		}
	}
	return nil
}

func (s *desktopService) SendPointer(ctx context.Context, req *connect.Request[pb.PointerEvent]) (*connect.Response[pb.PointerResponse], error) {
	args, err := pointerArgs(req.Msg.GetX(), req.Msg.GetY(), req.Msg.GetButton(), req.Msg.GetAction())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	if err := s.execPointer(ctx, req.Msg, args); err != nil {
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
		text, err := normalizeKeyText(in.Text)
		if err != nil {
			return nil, err
		}
		// Modifiers don't apply to literal text entry. --delay 0 drops
		// xdotool's default 12ms/char pacing, which is for human visibility;
		// at that rate a long paste takes seconds. --clearmodifiers lifts an
		// active Caps or Shift Lock for the duration, so the text comes out
		// as written (the X11 path does the same itself).
		return []string{"type", "--delay", "0", "--clearmodifiers", "--", text}, nil
	default:
		return nil, errors.New("one of key or text is required")
	}
}

// execKey delivers a validated key event through the persistent connection
// when it can plan the keystrokes, else through xdotool. The X11 path only
// declines before sending anything, so the fallback never replays input.
func (s *desktopService) execKey(ctx context.Context, ev *pb.KeyEvent, fallbackArgs []string) error {
	inputCtx, cancel := context.WithTimeout(ctx, xdotoolTimeout)
	defer cancel()
	attempted, err := s.runX11(inputCtx, func(_ context.Context, b *x11Backend) error {
		return b.Key(ev)
	})
	if attempted && !errors.Is(err, errBackendKept) {
		return err
	}
	return s.runXdotool(ctx, fallbackArgs...)
}

func (s *desktopService) SendKey(ctx context.Context, req *connect.Request[pb.KeyEvent]) (*connect.Response[pb.KeyResponse], error) {
	args, err := keyArgs(req.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	if err := s.execKey(ctx, req.Msg, args); err != nil {
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
	if err := s.execScroll(ctx, req.Msg, cmds); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&pb.ScrollResponse{}), nil
}

// ---------------------------------------------------------------------------
// SendActions — ordered input batch
// ---------------------------------------------------------------------------

// maxBatchActions bounds a single SendActions request, which bounds the
// worst-case input-lock hold time.
const maxBatchActions = 64

// loweredAction is one fully validated batch step, ready to execute under
// the input lock via whichever backend is available.
type loweredAction func(ctx context.Context) error

// lowerActions validates every action in the batch and lowers each to an
// executor, reusing the exact validation of the unary RPCs. One entry per
// action so execution can report the failing index.
func (s *desktopService) lowerActions(actions []*pb.Action) ([]loweredAction, error) {
	if len(actions) == 0 {
		return nil, errors.New("actions is empty")
	}
	if len(actions) > maxBatchActions {
		return nil, fmt.Errorf("too many actions: %d, max %d", len(actions), maxBatchActions)
	}
	lowered := make([]loweredAction, len(actions))
	for i, action := range actions {
		switch a := action.GetAction().(type) {
		case *pb.Action_Pointer:
			args, err := pointerArgs(a.Pointer.GetX(), a.Pointer.GetY(), a.Pointer.GetButton(), a.Pointer.GetAction())
			if err != nil {
				return nil, fmt.Errorf("action %d: %w", i, err)
			}
			ev := a.Pointer
			lowered[i] = func(ctx context.Context) error { return s.execPointer(ctx, ev, args) }
		case *pb.Action_Key:
			args, err := keyArgs(a.Key)
			if err != nil {
				return nil, fmt.Errorf("action %d: %w", i, err)
			}
			ev := a.Key
			lowered[i] = func(ctx context.Context) error { return s.execKey(ctx, ev, args) }
		case *pb.Action_Scroll:
			cmds, err := scrollCommands(a.Scroll.GetDx(), a.Scroll.GetDy())
			if err != nil {
				return nil, fmt.Errorf("action %d: %w", i, err)
			}
			ev := a.Scroll
			lowered[i] = func(ctx context.Context) error { return s.execScroll(ctx, ev, cmds) }
		default:
			return nil, fmt.Errorf("action %d: one of pointer, key, or scroll is required", i)
		}
	}
	return lowered, nil
}

func (s *desktopService) SendActions(ctx context.Context, req *connect.Request[pb.ActionBatch]) (*connect.Response[pb.ActionBatchResponse], error) {
	lowered, err := s.lowerActions(req.Msg.GetActions())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	for i, run := range lowered {
		if err := run(ctx); err != nil {
			return nil, connect.NewError(connect.CodeInternal,
				fmt.Errorf("action %d failed after %d executed: %w", i, i, err))
		}
	}
	return connect.NewResponse(&pb.ActionBatchResponse{Executed: uint32(len(lowered))}), nil
}

// ---------------------------------------------------------------------------
// Step — action batch plus frame in one request
// ---------------------------------------------------------------------------

// maxStepSettle caps the pause between a batch and its capture. The input
// lock is held across it, so a long settle would stall every other input.
const maxStepSettle = 2 * time.Second

// defaultChangeWait bounds wait_for_change when the request sets no settle.
const defaultChangeWait = time.Second

func (s *desktopService) Step(ctx context.Context, req *connect.Request[pb.StepRequest]) (*connect.Response[pb.StepResponse], error) {
	format, err := screenshotFormat(req.Msg.GetFormat())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	settle := time.Duration(req.Msg.GetSettleMs()) * time.Millisecond
	if settle > maxStepSettle {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("settle_ms %d exceeds max %d", req.Msg.GetSettleMs(), maxStepSettle/time.Millisecond))
	}
	if req.Msg.GetWaitForChange() && settle == 0 {
		settle = defaultChangeWait
	}
	lowered, err := s.lowerActions(req.Msg.GetActions())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	// The lock also covers the settle and the capture, so the frame shows
	// the state this batch produced and nothing that arrived after it.
	phase := time.Now()
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	resp := &pb.StepResponse{Executed: uint32(len(lowered)), QueueMs: millisSince(&phase)}
	var watch *frameWatch
	if req.Msg.GetWaitForChange() {
		watch = s.armFrameWatch(ctx)
	}
	// Arming reads and hashes a frame; it is capture work done early.
	armMs := millisSince(&phase)
	for i, run := range lowered {
		if err := run(ctx); err != nil {
			resp.Executed = uint32(i)
			resp.ActionError = fmt.Sprintf("action %d failed after %d executed: %v", i, i, err)
			break
		}
	}
	resp.ActionsMs = millisSince(&phase)
	if watch != nil {
		watch.deadline = time.Now().Add(settle)
	} else if settle > 0 {
		select {
		case <-time.After(settle):
		case <-ctx.Done():
		}
	}
	resp.SettleMs = millisSince(&phase)
	// Input already landed by now, so a capture failure is reported in the
	// response rather than as an RPC error the caller might retry.
	shot, err := s.screenshotResponse(ctx, format, watch)
	resp.CaptureMs = armMs + millisSince(&phase)
	if err != nil {
		resp.CaptureError = err.Error()
	} else {
		resp.Screenshot = shot
		resp.Changed = watch != nil && watch.changed
	}
	return connect.NewResponse(resp), nil
}

// millisSince returns the milliseconds since *from and moves *from to now,
// so consecutive calls measure consecutive phases.
func millisSince(from *time.Time) uint32 {
	now := time.Now()
	ms := now.Sub(*from).Milliseconds()
	*from = now
	return uint32(ms)
}

// resizeRepaintWait bounds how long Resize waits for clients to draw at the
// new size. A display where nothing draws after the switch waits it out.
const resizeRepaintWait = 2 * time.Second

// markRepaint drops the repaint reports queued before a mode switch, so
// awaitRepaint only credits drawing done after it. False when the display
// backend cannot report repaints.
func (s *desktopService) markRepaint(ctx context.Context) bool {
	attempted, err := s.runX11(ctx, func(_ context.Context, b *x11Backend) error { return b.markRepaint() })
	return attempted && err == nil
}

// awaitRepaint blocks until the display shows something drawn since the
// switch, or until bound; without a display backend it returns at once. A
// desktop that already redrew during the mode switch costs one read.
func (s *desktopService) awaitRepaint(ctx context.Context, marked bool, bound time.Duration) {
	// The reads get a little longer than the wait: a quiet display ends it
	// with a plain false and keeps the connection, while a server that stops
	// replying mid-read still releases the input lock soon after the bound.
	deadline := time.Now().Add(bound)
	ctx, cancel := context.WithDeadline(ctx, deadline.Add(time.Second))
	defer cancel()
	_, _ = s.runX11(ctx, func(ctx context.Context, b *x11Backend) error {
		ok, err := b.awaitPainted(ctx, marked, deadline)
		if err == nil && !ok {
			log.Printf("desktop: display still blank %v after resize", bound)
		}
		return err
	})
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

	// The X server exposes only its initial mode. Generate and attach a CVT modeline
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
	marked := s.markRepaint(resizeCtx)
	if setModeOutput, setModeErr := setModeCmd.CombinedOutput(); setModeErr != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf(
			"set desktop mode %s: %w (newmode: %s; addmode: %s)",
			modeName,
			wrapExecErrOutput("xrandr --output", setModeOutput, setModeErr),
			strings.TrimSpace(string(newModeOutput)),
			strings.TrimSpace(string(addModeOutput)),
		))
	}
	// The switch leaves the display blank until clients repaint; a capture
	// right after would show that, so wait until something is drawn, bounded.
	s.awaitRepaint(resizeCtx, marked, resizeRepaintWait)
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

// desktopHelperPath is the only place desktop helpers (xdotool, import,
// xrandr, cvt) are resolved from. boxd runs them as root, so the sandbox's
// own PATH must not take part: a user-writable directory on it would let the
// sandbox user substitute a helper and run it with boxd's privileges.
var desktopHelperPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// commandContext runs a desktop helper with a minimal environment: PATH,
// DISPLAY and a UTF-8 LC_CTYPE only. The helpers run with boxd's privileges, so nothing else from
// the sandbox's environment may reach them — LD_PRELOAD or an ImageMagick
// config override would otherwise run sandbox-controlled code as root.
// DISPLAY comes from the desktop template through /init; boxd itself starts
// before template defaults are applied and does not have it in its own
// environment.
func (s *desktopService) commandContext(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
	display := s.displayName()

	resolved, err := lookPathIn(name, desktopHelperPath)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, resolved, args...)
	// LC_CTYPE: xdotool converts typed text through the current locale, and
	// the C locale rejects anything beyond ASCII. C.UTF-8 is built into glibc.
	cmd.Env = []string{"PATH=" + desktopHelperPath, "DISPLAY=" + display, "LC_CTYPE=C.UTF-8"}
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
