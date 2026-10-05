package main

import (
	"context"
	"errors"
	"image"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	pb "github.com/superserve-ai/sandbox/proto/boxdpb"
)

func TestBgrxToRGBA(t *testing.T) {
	// One 2x1 pixmap: pure red then pure blue, little-endian BGRX.
	data := []byte{
		0x00, 0x00, 0xff, 0x00, // red
		0xff, 0x00, 0x00, 0x00, // blue
	}
	frame, err := bgrxToRGBA(data, 2, 1)
	if err != nil {
		t.Fatalf("bgrxToRGBA: %v", err)
	}
	if got := frame.RGBAAt(0, 0); got.R != 255 || got.G != 0 || got.B != 0 || got.A != 255 {
		t.Errorf("pixel 0 = %+v, want opaque red", got)
	}
	if got := frame.RGBAAt(1, 0); got.R != 0 || got.G != 0 || got.B != 255 || got.A != 255 {
		t.Errorf("pixel 1 = %+v, want opaque blue", got)
	}

	if _, err := bgrxToRGBA(data, 4, 4); err == nil {
		t.Error("expected error for short pixmap")
	}
}

func TestCompositeCursor(t *testing.T) {
	frame := image.NewRGBA(image.Rect(0, 0, 4, 4)) // all black, alpha 0

	// 2x2 cursor: opaque white, transparent, half-transparent red (premult), opaque green.
	cursor := []uint32{
		0xffffffff,
		0x00000000,
		0x80800000,
		0xff00ff00,
	}
	compositeCursor(frame, cursor, 2, 2, 1, 1)

	if got := frame.RGBAAt(1, 1); got.R != 255 || got.G != 255 || got.B != 255 {
		t.Errorf("(1,1) = %+v, want white (opaque cursor pixel)", got)
	}
	if got := frame.RGBAAt(2, 1); got.R != 0 || got.G != 0 || got.B != 0 {
		t.Errorf("(2,1) = %+v, want untouched (transparent cursor pixel)", got)
	}
	if got := frame.RGBAAt(1, 2); got.R != 0x80 {
		t.Errorf("(1,2).R = %d, want 0x80 (premultiplied red over black)", got.R)
	}
	if got := frame.RGBAAt(2, 2); got.G != 255 {
		t.Errorf("(2,2) = %+v, want green", got)
	}

	// Off-frame origin must not panic and must clip.
	compositeCursor(frame, cursor, 2, 2, -1, 3)
	compositeCursor(frame, cursor, 2, 2, 3, 3)
}

func TestScrollSteps(t *testing.T) {
	steps := scrollSteps(-2, 3)
	if len(steps) != 2 {
		t.Fatalf("steps = %+v, want dy then dx", steps)
	}
	if steps[0].Button != 5 || steps[0].Count != 3 {
		t.Errorf("dy step = %+v, want button 5 x3 (scroll down)", steps[0])
	}
	if steps[1].Button != 6 || steps[1].Count != 2 {
		t.Errorf("dx step = %+v, want button 6 x2 (scroll left)", steps[1])
	}
	if scrollSteps(0, 0) != nil {
		t.Error("no-op scroll should lower to no steps")
	}
}

func TestX11Holder_DisabledAndCooldown(t *testing.T) {
	var h x11Holder
	h.disabled = true
	if h.get(context.Background(), ":1") != nil {
		t.Fatal("disabled holder must never return a backend")
	}

	h = x11Holder{}
	// An unconnectable display: first get probes and fails...
	if h.get(context.Background(), "/nonexistent-display:99") != nil {
		t.Fatal("expected probe failure")
	}
	probed := h.lastProbe
	// ...and the next get inside the cooldown must not re-dial.
	if h.get(context.Background(), "/nonexistent-display:99") != nil {
		t.Fatal("expected fallback inside cooldown")
	}
	if h.lastProbe != probed {
		t.Error("cooldown violated: re-probed immediately")
	}
	// After the cooldown, it probes again.
	h.lastProbe = time.Now().Add(-2 * x11ReprobeInterval)
	_ = h.get(context.Background(), "/nonexistent-display:99")
	if h.lastProbe == probed {
		t.Error("expected a fresh probe after the cooldown")
	}
}

func TestX11Holder_DropOnlyDropsCurrent(t *testing.T) {
	var h x11Holder
	// drop of a nil/stale backend is a no-op and must not panic.
	h.drop(nil)
	stale := &x11Backend{}
	h.drop(stale)
}

func TestStream_UnchangedFramesBecomeKeepalives(t *testing.T) {
	withFakeBin(t, map[string]string{
		"xdotool": `if [ "$1" = "getdisplaygeometry" ]; then echo "800 600"; exit 0; fi
exit 1
`,
		"import": `printf 'SAMEFRAME'
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

	if !stream.Receive() || stream.Msg().GetStart() == nil {
		t.Fatalf("expected Start event, got %+v (err %v)", stream.Msg(), stream.Err())
	}
	if !stream.Receive() || stream.Msg().GetData() == nil {
		t.Fatalf("expected first Data event, got %+v (err %v)", stream.Msg(), stream.Err())
	}
	// Identical capture bytes: everything after the first frame is a
	// keepalive, never a duplicate image.
	for i := 0; i < 3; i++ {
		if !stream.Receive() {
			t.Fatalf("receive %d failed: %v", i, stream.Err())
		}
		if stream.Msg().GetData() != nil {
			t.Fatalf("event %d is a duplicate Data frame, want keepalive", i)
		}
		if stream.Msg().GetKeepalive() == nil {
			t.Fatalf("event %d = %+v, want keepalive", i, stream.Msg())
		}
	}
}

func TestRawFrameTooLarge(t *testing.T) {
	cases := map[[2]uint16]bool{
		{1280, 800}:  false,
		{3840, 2160}: false, // 4K, ~33 MiB
		{4096, 4096}: false, // exactly the cap
		{4097, 4096}: true,
		{8192, 8192}: true, // 256 MiB raw
	}
	for dims, want := range cases {
		if got := rawFrameTooLarge(dims[0], dims[1]); got != want {
			t.Errorf("rawFrameTooLarge(%dx%d) = %v, want %v", dims[0], dims[1], got, want)
		}
	}
}

// A backend with no connection: the ops below never touch it, so these
// tests exercise runX11's control flow alone.
func withFakeBackend(s *desktopService) *x11Backend {
	b := &x11Backend{}
	s.x11.backend = b
	return b
}

func TestRunX11_OpErrorIsReturnedAndDropsTheBackend(t *testing.T) {
	s := newDesktopService(&sandboxContext{})
	withFakeBackend(s)
	attempted, err := s.runX11(context.Background(), func(*x11Backend) error {
		return errors.New("sync failed")
	})
	if !attempted || err == nil || err.Error() != "sync failed" {
		t.Fatalf("attempted=%v err=%v, want attempted with the op's error", attempted, err)
	}
	if s.x11.backend != nil {
		t.Fatal("failed backend was not dropped")
	}
}

func TestRunX11_CancellationReleasesABlockedOp(t *testing.T) {
	s := newDesktopService(&sandboxContext{})
	withFakeBackend(s)
	release := make(chan struct{})
	defer close(release)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	attempted, err := s.runX11(ctx, func(*x11Backend) error {
		<-release // stands in for a reply that never comes
		return nil
	})
	if !attempted || !errors.Is(err, context.Canceled) {
		t.Fatalf("attempted=%v err=%v, want context.Canceled", attempted, err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("runX11 did not return promptly after cancellation")
	}
	if s.x11.backend != nil {
		t.Fatal("backend was not dropped on cancellation")
	}
}

func TestRunX11_NoBackendIsNotAttempted(t *testing.T) {
	s := newTestDesktopService(nil)
	attempted, err := s.runX11(context.Background(), func(*x11Backend) error { return nil })
	if attempted || err != nil {
		t.Fatalf("attempted=%v err=%v, want not attempted", attempted, err)
	}
}

// A server that accepts the socket but never completes the handshake: the
// dial must give up on its own, and callers arriving meanwhile must fall
// back immediately instead of queueing behind the holder lock.
func TestX11Holder_HungHandshakeIsBoundedAndDoesNotBlockOthers(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "x11hang") // short path: unix socket limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	display := filepath.Join(dir, "x:0") // xgb dials "<socket>:<n>" for a "/" display
	ln, err := net.Listen("unix", display)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c) // held open, never answered
			mu.Unlock()
		}
	}()

	var h x11Holder
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	first := make(chan *x11Backend, 1)
	start := time.Now()
	go func() { first <- h.get(ctx, display) }()
	time.Sleep(50 * time.Millisecond)

	t0 := time.Now()
	if h.get(context.Background(), display) != nil {
		t.Fatal("second caller got a backend from a hung dial")
	}
	if time.Since(t0) > 100*time.Millisecond {
		t.Fatal("second caller waited behind the hung dial")
	}
	if b := <-first; b != nil {
		t.Fatal("hung dial produced a backend")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("hung dial was not bounded by the context")
	}
}
