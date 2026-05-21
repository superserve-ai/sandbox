package uffd

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/rs/zerolog"
)

// firecracker-produced JSON from src/vmm/src/persist.rs:725-768. Verified
// against the upstream struct definition (GuestRegionUffdMapping) and the
// reference example handler in src/firecracker/examples/uffd/uffd_utils.rs.
const sampleMappingsJSON = `[
  {"base_host_virt_addr": 140737488355328, "size": 268435456, "offset": 0, "page_size": 4096, "page_size_kib": 4096}
]`

func TestParseGuestRegionMappings(t *testing.T) {
	var mappings []GuestRegionMapping
	if err := json.Unmarshal([]byte(sampleMappingsJSON), &mappings); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(mappings) != 1 {
		t.Fatalf("got %d mappings, want 1", len(mappings))
	}
	m := mappings[0]
	if m.BaseHostVirtAddr != 140737488355328 {
		t.Errorf("BaseHostVirtAddr = %d, want 140737488355328", m.BaseHostVirtAddr)
	}
	if m.Size != 268435456 {
		t.Errorf("Size = %d, want 268435456 (256 MiB)", m.Size)
	}
	if m.Offset != 0 {
		t.Errorf("Offset = %d, want 0", m.Offset)
	}
	if m.PageSize != 4096 {
		t.Errorf("PageSize = %d, want 4096", m.PageSize)
	}
}

func TestGuestRegionMapping_Contains(t *testing.T) {
	r := &GuestRegionMapping{
		BaseHostVirtAddr: 0x1000_0000,
		Size:             0x1000_0000,
	}
	cases := []struct {
		name string
		addr uint64
		want bool
	}{
		{"start of region", 0x1000_0000, true},
		{"middle of region", 0x1800_0000, true},
		{"last byte", 0x1FFF_FFFF, true},
		{"first byte after region", 0x2000_0000, false},
		{"before region", 0x0FFF_FFFF, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.contains(tc.addr); got != tc.want {
				t.Errorf("contains(%#x) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}

func TestHandler_FindRegion(t *testing.T) {
	h := &Handler{
		mappings: []GuestRegionMapping{
			{BaseHostVirtAddr: 0x1000_0000, Size: 0x1000_0000},
			{BaseHostVirtAddr: 0x3000_0000, Size: 0x2000_0000},
		},
	}
	if r := h.findRegion(0x1500_0000); r == nil || r.BaseHostVirtAddr != 0x1000_0000 {
		t.Errorf("findRegion(0x1500_0000): got %+v, want region 1", r)
	}
	if r := h.findRegion(0x4000_0000); r == nil || r.BaseHostVirtAddr != 0x3000_0000 {
		t.Errorf("findRegion(0x4000_0000): got %+v, want region 2", r)
	}
	if r := h.findRegion(0x2500_0000); r != nil {
		t.Errorf("findRegion(0x2500_0000) = %+v, want nil (gap between regions)", r)
	}
}

func TestIoctlNumbers(t *testing.T) {
	// These constants are computed from <linux/userfaultfd.h>'s _IOWR/_IOR
	// macros and should never change. Pinning them here so a code edit
	// can't silently break the kernel ABI.
	if UFFDIO_COPY != 0xC028AA03 {
		t.Errorf("UFFDIO_COPY = %#x, want 0xC028AA03", UFFDIO_COPY)
	}
	if UFFDIO_ZEROPAGE != 0xC020AA04 {
		t.Errorf("UFFDIO_ZEROPAGE = %#x, want 0xC020AA04", UFFDIO_ZEROPAGE)
	}
	if UFFDIO_UNREGISTER != 0x8010AA01 {
		t.Errorf("UFFDIO_UNREGISTER = %#x, want 0x8010AA01", UFFDIO_UNREGISTER)
	}
}

func TestUffdMsgSize(t *testing.T) {
	// uffd_msg is 32 bytes packed in the kernel ABI. Reading 32 bytes
	// from the UFFD fd is correct iff the Go struct also weighs 32 bytes.
	var msg uffdMsg
	want := uintptr(32)
	if got := unsafe.Sizeof(msg); got != want {
		t.Errorf("sizeof(uffdMsg) = %d, want %d", got, want)
	}
}

func TestHandler_CloseIdempotent(t *testing.T) {
	h := New(Config{Logger: zerolog.Nop()})
	if err := h.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	// Second call must be a no-op — closed CAS guards against double-Munmap
	// and double-close of listener/fd.
	if err := h.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestHandler_WaitHandshake_Success(t *testing.T) {
	h := New(Config{Logger: zerolog.Nop()})
	h.publishHandshake(nil)
	if err := h.WaitHandshake(context.Background()); err != nil {
		t.Errorf("WaitHandshake: %v", err)
	}
	// Idempotent: re-publish lets a second caller see the same outcome.
	if err := h.WaitHandshake(context.Background()); err != nil {
		t.Errorf("second WaitHandshake: %v", err)
	}
}

func TestHandler_WaitHandshake_Error(t *testing.T) {
	h := New(Config{Logger: zerolog.Nop()})
	want := errors.New("boom")
	h.publishHandshake(want)
	got := h.WaitHandshake(context.Background())
	if !errors.Is(got, want) {
		t.Errorf("WaitHandshake = %v, want %v", got, want)
	}
}

func TestHandler_WaitHandshake_CtxCancel(t *testing.T) {
	h := New(Config{Logger: zerolog.Nop()})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	err := h.WaitHandshake(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("WaitHandshake = %v, want context.Canceled", err)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Errorf("cancel didn't propagate promptly: %v", time.Since(start))
	}
}

// TestServeLoop_EINVALReturnsCleanly verifies that EINVAL from the read of
// the uffd fd (which happens when firecracker unmaps its VMAs before we
// drain the queue) makes serveLoop return nil rather than propagate an
// error to the caller.
func TestServeLoop_EINVALReturnsCleanly(t *testing.T) {
	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer wPipe.Close()
	// Prime the pipe so poll signals readable; readFn returns EINVAL.
	if _, err := wPipe.Write([]byte{0}); err != nil {
		t.Fatalf("prime pipe: %v", err)
	}

	h := New(Config{
		FaultWorkers: 1,
		Logger:       zerolog.Nop(),
	})
	h.file.Store(rPipe)
	h.readFn = func(fd int, p []byte) (int, error) {
		return 0, syscall.EINVAL
	}

	if err := h.serveLoop(context.Background()); err != nil {
		t.Errorf("serveLoop returned %v, want nil on EINVAL", err)
	}
}

// TestServeLoop_CtxCancelExitsPromptly verifies cancellation latency is
// bounded by the poll timeout (~pollTimeoutMs).
func TestServeLoop_CtxCancelExitsPromptly(t *testing.T) {
	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer wPipe.Close()

	h := New(Config{
		FaultWorkers: 1,
		Logger:       zerolog.Nop(),
	})
	h.file.Store(rPipe)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if err := h.serveLoop(ctx); err != nil {
		t.Errorf("serveLoop returned %v, want nil on cancel", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("serveLoop took %v to exit on cancel; want < 500ms", elapsed)
	}
}

// TestCloseFd_WaitsForInFlightControl verifies that closeFd blocks until
// any in-flight SyscallConn().Control callback returns.
func TestCloseFd_WaitsForInFlightControl(t *testing.T) {
	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer wPipe.Close()

	h := New(Config{Logger: zerolog.Nop()})
	h.file.Store(rPipe)

	sc, err := rPipe.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	inFlight := make(chan struct{})
	released := make(chan struct{})
	go func() {
		_ = sc.Control(func(_ uintptr) {
			close(inFlight)
			time.Sleep(200 * time.Millisecond)
			close(released)
		})
	}()
	<-inFlight // proven in-flight, not assumed

	// closeFd must wait for the Control callback to finish.
	start := time.Now()
	h.closeFd()
	elapsed := time.Since(start)
	select {
	case <-released:
	default:
		t.Errorf("closeFd returned before Control callback released")
	}
	if elapsed < 100*time.Millisecond {
		t.Errorf("closeFd took %v; expected to wait for in-flight Control (~200ms)", elapsed)
	}
}
