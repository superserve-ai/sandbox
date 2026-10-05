package main

import (
	"context"
	"fmt"
	"image"
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

// maxRawFrameBytes bounds one GetImage reply (4 bytes per pixel): the raw
// frame is held in memory for conversion and PNG encoding, and up to
// maxConcurrentCaptures of them may exist at once. 64 MiB covers 4K; a
// larger display falls back to `import`, whose memory is its own process.
const maxRawFrameBytes = 64 << 20

// errFrameTooLarge is returned by Capture for a display above
// maxRawFrameBytes; the caller falls back to the shell path.
var errFrameTooLarge = fmt.Errorf("display exceeds %d bytes of raw frame", maxRawFrameBytes)

type x11Backend struct {
	conn      *xgb.Conn
	root      xproto.Window
	hasXfixes bool
}

func newX11Backend(display string) (*x11Backend, error) {
	conn, err := xgb.NewConnDisplay(display)
	if err != nil {
		return nil, fmt.Errorf("connect to display %q: %w", display, err)
	}
	if err := xtest.Init(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("XTEST extension: %w", err)
	}
	b := &x11Backend{
		conn: conn,
		root: xproto.Setup(conn).DefaultScreen(conn).Root,
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

func (b *x11Backend) Close() {
	if b.conn != nil {
		b.conn.Close()
	}
}

// sync round-trips to the X server so buffered events are known-delivered
// before the RPC returns.
func (b *x11Backend) sync() error {
	_, err := xproto.GetInputFocus(b.conn).Reply()
	return err
}

func (b *x11Backend) fakeInput(typ byte, detail byte, x, y int16) error {
	return xtest.FakeInputChecked(b.conn, typ, detail, xproto.TimeCurrentTime, b.root, x, y, 0).Check()
}

func (b *x11Backend) move(x, y int16) error {
	// Detail 0 = absolute coordinates on the root window's screen.
	return b.fakeInput(xproto.MotionNotify, 0, x, y)
}

func (b *x11Backend) button(press bool, button byte) error {
	typ := byte(xproto.ButtonRelease)
	if press {
		typ = xproto.ButtonPress
	}
	return b.fakeInput(typ, button, 0, 0)
}

func (b *x11Backend) click(button byte) error {
	if err := b.button(true, button); err != nil {
		return err
	}
	return b.button(false, button)
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
	if err := b.move(int16(x), int16(y)); err != nil {
		return err
	}
	switch action {
	case pb.PointerAction_POINTER_ACTION_UNSPECIFIED, pb.PointerAction_POINTER_ACTION_MOVE:
		// Move only.
	case pb.PointerAction_POINTER_ACTION_DOWN:
		if err := b.button(true, btn); err != nil {
			return err
		}
	case pb.PointerAction_POINTER_ACTION_UP:
		if err := b.button(false, btn); err != nil {
			return err
		}
	case pb.PointerAction_POINTER_ACTION_CLICK:
		if err := b.click(btn); err != nil {
			return err
		}
	case pb.PointerAction_POINTER_ACTION_DOUBLE_CLICK:
		if err := b.click(btn); err != nil {
			return err
		}
		if err := b.click(btn); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown pointer action %v", action)
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
			if err := b.click(step.Button); err != nil {
				return err
			}
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
	mu        sync.Mutex
	backend   *x11Backend
	lastProbe time.Time
	disabled  bool // tests force the shell path
}

// get returns the live backend, dialing if needed. A nil return means "use
// the shell fallback".
func (h *x11Holder) get(display string) *x11Backend {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.disabled {
		return nil
	}
	if h.backend != nil {
		return h.backend
	}
	if time.Since(h.lastProbe) < x11ReprobeInterval {
		return nil
	}
	h.lastProbe = time.Now()
	backend, err := newX11Backend(display)
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
func (s *desktopService) runX11(ctx context.Context, op func(*x11Backend) error) (attempted bool, err error) {
	backend := s.x11.get(s.displayName())
	if backend == nil {
		return false, nil
	}
	done := make(chan error, 1)
	go func() { done <- op(backend) }()
	select {
	case err := <-done:
		if err != nil {
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
