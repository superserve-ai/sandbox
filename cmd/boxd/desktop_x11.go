package main

import (
	"context"
	"errors"
	"fmt"
	"image"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xfixes"
	"github.com/jezek/xgb/xproto"
	"github.com/jezek/xgb/xtest"

	pb "github.com/superserve-ai/sandbox/proto/boxdpb"
)

// ---------------------------------------------------------------------------
// Persistent X11 backend — pointer/scroll injection and frame capture over
// one long-lived display connection (XTest + GetImage + XFixes cursor),
// replacing a process fork per action/frame. Keyboard input stays on the
// xdotool path: correct text entry needs keysym-to-keycode resolution and
// temporary keymap remapping, which xdotool already implements.
//
// Every method is synchronous with the X server (a GetInputFocus round trip
// after each injected sequence): a reply means the events reached the
// server, mirroring the flush a short-lived tool performs by exiting.
// ---------------------------------------------------------------------------

// x11ReprobeInterval limits how often a failed backend init is retried, so
// a sandbox without an X server (non-desktop template) pays one dial attempt
// per interval, not per RPC.
const x11ReprobeInterval = 30 * time.Second

// x11DialTimeout bounds the initial handshake and extension queries, which
// otherwise block without observing any request context.
const x11DialTimeout = 5 * time.Second

// maxRawFrameBytes bounds one GetImage reply (4 bytes per pixel): the raw
// frame is held in memory for conversion and PNG encoding, and up to
// maxConcurrentCaptures of them may exist at once. 64 MiB covers 4K; a
// larger display falls back to `import`, whose memory is its own process.
const maxRawFrameBytes = 64 << 20

// errFrameTooLarge is returned by Capture for a display above
// maxRawFrameBytes; the caller falls back to the shell path.
var errFrameTooLarge = fmt.Errorf("display exceeds %d bytes of raw frame", maxRawFrameBytes)

type x11Backend struct {
	conn *xgb.Conn
	// sock is the connection's socket, kept so Close can force it shut:
	// xgb's own Close is graceful and finishes with a round trip, which
	// never completes against a server that has stopped replying.
	sock      net.Conn
	root      xproto.Window
	hasXfixes bool
	// keys is the keyboard mapping (desktop_x11_key.go), fetched lazily;
	// keysDirty is set by a MappingNotify this backend did not cause, and
	// ownRemaps counts the ones it did and has not yet seen back.
	keys      *x11Keymap
	keysDirty bool
	ownRemaps int
}

// parseDisplay resolves a DISPLAY value to the socket to dial and the screen
// number, for the forms an X client accepts: ":1", ":1.0", "/path/sock:1",
// "host:1" and "protocol/host:1".
func parseDisplay(display string) (network, address string, screen int, err error) {
	colon := strings.LastIndex(display, ":")
	if colon < 0 {
		return "", "", 0, fmt.Errorf("bad display %q", display)
	}
	number, screenStr, _ := strings.Cut(display[colon+1:], ".")
	n, err := strconv.Atoi(number)
	if err != nil || n < 0 {
		return "", "", 0, fmt.Errorf("bad display %q", display)
	}
	if screenStr != "" {
		if screen, err = strconv.Atoi(screenStr); err != nil || screen < 0 {
			return "", "", 0, fmt.Errorf("bad display %q", display)
		}
	}
	head := display[:colon]
	switch {
	case strings.HasPrefix(head, "/"):
		return "unix", head + ":" + number, screen, nil
	case head == "" || head == "unix":
		return "unix", "/tmp/.X11-unix/X" + number, screen, nil
	}
	network = "tcp"
	if proto, host, ok := strings.Cut(head, "/"); ok {
		network, head = proto, host
	}
	return network, net.JoinHostPort(head, strconv.Itoa(6000+n)), screen, nil
}

// newX11Backend initialises a backend on an established connection. The
// caller owns conn on error.
func newX11Backend(conn *xgb.Conn, screen int) (*x11Backend, error) {
	setup := xproto.Setup(conn)
	// DefaultScreen indexes Roots unchecked; DISPLAY comes from the sandbox
	// environment, so a bad screen must be an error, not a panic.
	if screen >= len(setup.Roots) {
		return nil, fmt.Errorf("display has %d screen(s), no screen %d", len(setup.Roots), screen)
	}
	conn.DefaultScreen = screen
	if err := xtest.Init(conn); err != nil {
		return nil, fmt.Errorf("XTEST extension: %w", err)
	}
	b := &x11Backend{
		conn: conn,
		root: setup.Roots[screen].Root,
	}
	// Cursor compositing is best-effort: without XFixes, frames simply have
	// no pointer drawn in them.
	if err := xfixes.Init(conn); err == nil {
		if _, err := xfixes.QueryVersion(conn, 4, 0).Reply(); err == nil {
			b.hasXfixes = true
		}
	}
	return b, nil
}

// Close shuts the backend down even if the server is unresponsive: closing
// the socket first fails any pending reply and lets xgb's goroutines exit.
func (b *x11Backend) Close() {
	if b.sock != nil {
		_ = b.sock.Close()
	}
	if b.conn != nil {
		b.conn.Close()
	}
}

// sync round-trips to the X server so every queued event is known-delivered
// before the RPC returns, then surfaces any error the server raised for
// them. Events are sent unchecked, so one round trip covers a whole action
// instead of one per event.
func (b *x11Backend) sync() error {
	if _, err := xproto.GetInputFocus(b.conn).Reply(); err != nil {
		return err
	}
	return b.drainEvents()
}

// drainEvents consumes everything the server has already sent, without a
// round trip: errors for unchecked requests, and keyboard mapping changes
// made by other clients (our own remaps are expected and counted down).
func (b *x11Backend) drainEvents() error {
	if b.conn == nil {
		return nil
	}
	for {
		ev, xerr := b.conn.PollForEvent()
		if xerr != nil {
			return fmt.Errorf("x server rejected input: %v", xerr)
		}
		if ev == nil {
			return nil
		}
		if m, ok := ev.(xproto.MappingNotifyEvent); ok && m.Request == xproto.MappingKeyboard {
			if b.ownRemaps > 0 {
				b.ownRemaps--
			} else {
				b.keysDirty = true
			}
		}
	}
}

// fakeInput queues one XTEST event; delivery is confirmed by sync.
func (b *x11Backend) fakeInput(typ byte, detail byte, x, y int16) {
	xtest.FakeInput(b.conn, typ, detail, xproto.TimeCurrentTime, b.root, x, y, 0)
}

func (b *x11Backend) move(x, y int16) {
	// Detail 0 = absolute coordinates on the root window's screen.
	b.fakeInput(xproto.MotionNotify, 0, x, y)
}

func (b *x11Backend) button(press bool, button byte) {
	typ := byte(xproto.ButtonRelease)
	if press {
		typ = xproto.ButtonPress
	}
	b.fakeInput(typ, button, 0, 0)
}

func (b *x11Backend) click(button byte) {
	b.button(true, button)
	b.button(false, button)
}

// x11PointerButton maps the proto button to the X11 core button number.
func x11PointerButton(button pb.PointerButton) (byte, error) {
	switch button {
	case pb.PointerButton_POINTER_BUTTON_UNSPECIFIED, pb.PointerButton_POINTER_BUTTON_LEFT:
		return 1, nil
	case pb.PointerButton_POINTER_BUTTON_MIDDLE:
		return 2, nil
	case pb.PointerButton_POINTER_BUTTON_RIGHT:
		return 3, nil
	default:
		return 0, fmt.Errorf("unknown pointer button %v", button)
	}
}

func (b *x11Backend) Pointer(x, y int32, button pb.PointerButton, action pb.PointerAction) error {
	btn, err := x11PointerButton(button)
	if err != nil {
		return err
	}
	switch action {
	case pb.PointerAction_POINTER_ACTION_UNSPECIFIED, pb.PointerAction_POINTER_ACTION_MOVE,
		pb.PointerAction_POINTER_ACTION_DOWN, pb.PointerAction_POINTER_ACTION_UP,
		pb.PointerAction_POINTER_ACTION_CLICK, pb.PointerAction_POINTER_ACTION_DOUBLE_CLICK:
	default:
		return fmt.Errorf("unknown pointer action %v", action)
	}
	b.move(int16(x), int16(y))
	switch action {
	case pb.PointerAction_POINTER_ACTION_DOWN:
		b.button(true, btn)
	case pb.PointerAction_POINTER_ACTION_UP:
		b.button(false, btn)
	case pb.PointerAction_POINTER_ACTION_CLICK:
		b.click(btn)
	case pb.PointerAction_POINTER_ACTION_DOUBLE_CLICK:
		b.click(btn)
		b.click(btn)
	}
	return b.sync()
}

// scrollSteps lowers a scroll delta to X11 wheel-button click runs.
// Buttons: 4 = up, 5 = down, 6 = left, 7 = right.
func scrollSteps(dx, dy int32) []struct {
	Button byte
	Count  int
} {
	var steps []struct {
		Button byte
		Count  int
	}
	if dy != 0 {
		button := byte(5)
		if dy < 0 {
			button = 4
		}
		steps = append(steps, struct {
			Button byte
			Count  int
		}{button, int(abs32(dy))})
	}
	if dx != 0 {
		button := byte(7)
		if dx < 0 {
			button = 6
		}
		steps = append(steps, struct {
			Button byte
			Count  int
		}{button, int(abs32(dx))})
	}
	return steps
}

func (b *x11Backend) Scroll(dx, dy int32) error {
	for _, step := range scrollSteps(dx, dy) {
		for i := 0; i < step.Count; i++ {
			b.click(step.Button)
		}
	}
	return b.sync()
}

func (b *x11Backend) Geometry() (width, height uint32, err error) {
	geom, err := xproto.GetGeometry(b.conn, xproto.Drawable(b.root)).Reply()
	if err != nil {
		return 0, 0, err
	}
	return uint32(geom.Width), uint32(geom.Height), nil
}

// Capture reads the root window as an RGBA frame with the cursor composited
// in (when XFixes is available). PNG encoding is the caller's concern.
func (b *x11Backend) Capture() (*image.RGBA, error) {
	geom, err := xproto.GetGeometry(b.conn, xproto.Drawable(b.root)).Reply()
	if err != nil {
		return nil, fmt.Errorf("root geometry: %w", err)
	}
	if rawFrameTooLarge(geom.Width, geom.Height) {
		return nil, errFrameTooLarge
	}
	img, err := xproto.GetImage(b.conn, xproto.ImageFormatZPixmap, xproto.Drawable(b.root),
		0, 0, geom.Width, geom.Height, 0xffffffff).Reply()
	if err != nil {
		return nil, fmt.Errorf("get image: %w", err)
	}
	if img.Depth != 24 && img.Depth != 32 {
		return nil, fmt.Errorf("unsupported root depth %d", img.Depth)
	}
	frame, err := bgrxToRGBA(img.Data, int(geom.Width), int(geom.Height))
	if err != nil {
		return nil, err
	}
	if b.hasXfixes {
		if cursor, err := xfixes.GetCursorImage(b.conn).Reply(); err == nil {
			compositeCursor(frame, cursor.CursorImage, int(cursor.Width), int(cursor.Height),
				int(cursor.X)-int(cursor.Xhot), int(cursor.Y)-int(cursor.Yhot))
		}
	}
	return frame, nil
}

// rawFrameTooLarge reports whether a display's raw frame would exceed
// maxRawFrameBytes.
func rawFrameTooLarge(width, height uint16) bool {
	return int(width)*int(height)*4 > maxRawFrameBytes
}

// bgrxToRGBA converts a little-endian ZPixmap (depth 24/32: B,G,R,X bytes
// per pixel) into an RGBA image in place: the returned frame shares `data`,
// so a capture holds one copy of the pixels, not two.
func bgrxToRGBA(data []byte, width, height int) (*image.RGBA, error) {
	n := width * height * 4
	if len(data) < n {
		return nil, fmt.Errorf("short pixmap: got %d bytes for %dx%d", len(data), width, height)
	}
	pix := data[:n]
	for i := 0; i < n; i += 4 {
		pix[i], pix[i+2] = pix[i+2], pix[i]
		pix[i+3] = 0xff
	}
	return &image.RGBA{Pix: pix, Stride: width * 4, Rect: image.Rect(0, 0, width, height)}, nil
}

// compositeCursor alpha-blends an XFixes cursor (premultiplied ARGB words)
// onto the frame at (originX, originY) — the cursor position minus hotspot.
func compositeCursor(frame *image.RGBA, cursor []uint32, width, height, originX, originY int) {
	bounds := frame.Bounds()
	for row := 0; row < height; row++ {
		fy := originY + row
		if fy < bounds.Min.Y || fy >= bounds.Max.Y {
			continue
		}
		for col := 0; col < width; col++ {
			fx := originX + col
			if fx < bounds.Min.X || fx >= bounds.Max.X {
				continue
			}
			argb := cursor[row*width+col]
			alpha := uint32(argb >> 24)
			if alpha == 0 {
				continue
			}
			cr := (argb >> 16) & 0xff
			cg := (argb >> 8) & 0xff
			cb := argb & 0xff
			offset := frame.PixOffset(fx, fy)
			// Premultiplied source over opaque destination.
			frame.Pix[offset+0] = uint8(cr + (uint32(frame.Pix[offset+0])*(255-alpha))/255)
			frame.Pix[offset+1] = uint8(cg + (uint32(frame.Pix[offset+1])*(255-alpha))/255)
			frame.Pix[offset+2] = uint8(cb + (uint32(frame.Pix[offset+2])*(255-alpha))/255)
		}
	}
}

// ---------------------------------------------------------------------------
// Lazy holder with fallback
// ---------------------------------------------------------------------------

// x11Holder lazily connects the persistent backend and re-probes on a
// cooldown after failures, so the shell fallback keeps working when no X
// server is reachable (non-desktop sandboxes, or X restarting).
type x11Holder struct {
	mu      sync.Mutex
	backend *x11Backend
	// display is the DISPLAY the backend (or the last probe) was for. The
	// sandbox env can change it after startup, and a cached connection to
	// the old server, or a cooldown from probing it, must not outlive that.
	display   string
	lastProbe time.Time
	probing   bool // a dial is in flight; concurrent callers use the shell path
	disabled  bool // tests force the shell path
}

// dialX11 connects under ctx and x11DialTimeout. The socket is opened here
// rather than by the X library so the handshake and extension queries are
// bounded by a socket deadline and aborted by closing the socket: a server
// that accepts but never answers leaves nothing parked behind.
func dialX11(ctx context.Context, display string) (*x11Backend, error) {
	network, address, screen, err := parseDisplay(display)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, x11DialTimeout)
	defer cancel()
	var dialer net.Dialer
	netConn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("connect to display %q: %w", display, err)
	}
	deadline, _ := ctx.Deadline()
	_ = netConn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = netConn.Close() })

	conn, err := xgb.NewConnNet(netConn)
	if err != nil {
		stop()
		_ = netConn.Close()
		return nil, fmt.Errorf("x11 handshake with %q: %w", display, err)
	}
	backend, err := newX11Backend(conn, screen)
	if err != nil {
		stop()
		_ = netConn.Close()
		conn.Close()
		return nil, err
	}
	backend.sock = netConn
	if !stop() {
		// ctx ended during init and the socket is already closed.
		backend.Close()
		return nil, ctx.Err()
	}
	_ = netConn.SetDeadline(time.Time{})
	return backend, nil
}

// get returns the live backend, dialing if needed. A nil return means "use
// the shell fallback". The lock is not held across the dial: a server that
// accepts the connection but never completes the handshake must not stall
// every other desktop call behind it.
func (h *x11Holder) get(ctx context.Context, display string) *x11Backend {
	h.mu.Lock()
	if h.disabled || h.probing {
		h.mu.Unlock()
		return nil
	}
	if h.backend != nil && h.display != display {
		h.backend.Close()
		h.backend = nil
	}
	if h.backend != nil {
		backend := h.backend
		h.mu.Unlock()
		return backend
	}
	if h.display == display && time.Since(h.lastProbe) < x11ReprobeInterval {
		h.mu.Unlock()
		return nil
	}
	h.display = display
	h.lastProbe = time.Now()
	h.probing = true
	h.mu.Unlock()

	backend, err := dialX11(ctx, display)

	h.mu.Lock()
	defer h.mu.Unlock()
	h.probing = false
	if err != nil {
		return nil
	}
	h.backend = backend
	return backend
}

// drop discards a backend after a call-time failure so the next call
// re-probes (fresh connection) or falls back.
func (h *x11Holder) drop(backend *x11Backend) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.backend == backend && backend != nil {
		backend.Close()
		h.backend = nil
	}
}

// runX11 runs op on the persistent backend when one is available.
// attempted=false means no backend was reachable and nothing was sent, so
// the caller may use the shell path. Once attempted, the op's error is the
// caller's to handle: for input it must not be retried through the shell,
// since the X server may already have applied part of it.
//
// A failing op drops the connection so the next call re-probes. If ctx ends
// while the op is blocked on a reply, the connection is closed (which
// releases the pending reply) and ctx's error is returned, so request
// timeouts and client cancellation still free the capture slot and the
// mutation lock.
func (s *desktopService) runX11(ctx context.Context, op func(context.Context, *x11Backend) error) (attempted bool, err error) {
	backend := s.x11.get(ctx, s.displayName())
	if backend == nil {
		return false, nil
	}
	done := make(chan error, 1)
	go func() { done <- op(ctx, backend) }()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, errBackendKept) {
			s.x11.drop(backend)
		}
		return true, err
	case <-ctx.Done():
		s.x11.drop(backend)
		select {
		case <-done:
		case <-time.After(time.Second):
			// The op is parked in the X library; it ends on its own once
			// the closed socket surfaces, and this backend is already gone.
		}
		return true, ctx.Err()
	}
}
