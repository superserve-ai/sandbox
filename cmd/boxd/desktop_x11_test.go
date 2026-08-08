package main

import (
	"context"
	"image"
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
	if h.get(":1") != nil {
		t.Fatal("disabled holder must never return a backend")
	}

	h = x11Holder{}
	// An unconnectable display: first get probes and fails...
	if h.get("/nonexistent-display:99") != nil {
		t.Fatal("expected probe failure")
	}
	probed := h.lastProbe
	// ...and the next get inside the cooldown must not re-dial.
	if h.get("/nonexistent-display:99") != nil {
		t.Fatal("expected fallback inside cooldown")
	}
	if h.lastProbe != probed {
		t.Error("cooldown violated: re-probed immediately")
	}
	// After the cooldown, it probes again.
	h.lastProbe = time.Now().Add(-2 * x11ReprobeInterval)
	_ = h.get("/nonexistent-display:99")
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
