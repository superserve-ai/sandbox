package uffd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

// defaultFaultWorkers caps concurrent in-flight UFFDIO_COPY ioctls per
// VM. Bounded so handler teardown via g.Wait doesn't stall on a wedged
// worker.
const defaultFaultWorkers = 256


// GuestRegionMapping is the JSON Firecracker sends over the UDS alongside
// the userfaultfd fd. Field tags must match
// GuestRegionUffdMapping in src/vmm/src/persist.rs of our firecracker fork.
type GuestRegionMapping struct {
	BaseHostVirtAddr uint64 `json:"base_host_virt_addr"`
	Size             uint64 `json:"size"`
	Offset           uint64 `json:"offset"`
	PageSize         uint64 `json:"page_size"`
	PageSizeKib      uint64 `json:"page_size_kib,omitempty"`
}

func (r *GuestRegionMapping) contains(faultAddr uint64) bool {
	return faultAddr >= r.BaseHostVirtAddr && faultAddr < r.BaseHostVirtAddr+r.Size
}

type Config struct {
	SocketPath   string
	MemSnapPath  string
	FaultWorkers int // 0 -> defaultFaultWorkers

	// AccessLogPath, when set and present on disk, supplies a recorded
	// page-access order from template build time. The prefetcher replays
	// it. Missing file → sequential fallback.
	AccessLogPath string

	// PrefetchEnabled controls whether the prefetcher runs at all.
	PrefetchEnabled bool

	// OnPageFault, if non-nil, is invoked for each PageFault event with
	// the backing-file offset of the page about to be served. Used by
	// template-builder to record access patterns. Must be fast (called
	// on the fault hot path).
	OnPageFault func(offset uint64)

	Logger zerolog.Logger
}

type Stats struct {
	FaultsServed     atomic.Uint64
	BytesServed      atomic.Uint64
	CopyErrors       atomic.Uint64
	UnknownEvents    atomic.Uint64
	RemoveEvents     atomic.Uint64
	EagainRetries    atomic.Uint64
	Eexist           atomic.Uint64
	PrefetchedPages  atomic.Uint64
	PrefetchSkipped  atomic.Uint64 // EEXIST during prefetch (page already faulted by guest)
}

// Handler binds a UDS, receives a userfaultfd fd from Firecracker, then
// serves page faults from mem.snap for the life of the VM. One handler
// per VM.
type Handler struct {
	cfg      Config
	log      zerolog.Logger
	stats    Stats
	source   *Source
	listener *net.UnixListener

	// file owns the UFFD fd. All syscalls go through SyscallConn().Control(),
	// which holds an internal refcount during the callback. file.Close()
	// blocks until in-flight Control callbacks return, so the kernel-side
	// fd cannot be reused by another open while any handler op is still
	// touching it.
	file atomic.Pointer[os.File]

	mappings []GuestRegionMapping
	pageSize uint64

	// handshakeDone carries the AcceptHandshake outcome to WaitHandshake.
	handshakeDone chan error

	// prefetchWg lets Close wait for the prefetch goroutine before munmap.
	prefetchWg sync.WaitGroup

	closed atomic.Bool

	// readFn defaults to unix.Read; tests override to inject error paths.
	readFn func(fd int, p []byte) (n int, err error)
}

func New(cfg Config) *Handler {
	if cfg.FaultWorkers <= 0 {
		cfg.FaultWorkers = defaultFaultWorkers
	}
	h := &Handler{
		cfg:           cfg,
		log:           cfg.Logger.With().Str("component", "uffd").Logger(),
		handshakeDone: make(chan error, 1),
		readFn:        unix.Read,
	}
	return h
}

func (h *Handler) Stats() *Stats { return &h.stats }

// Start binds the Unix socket and mmaps mem.snap. After it returns,
// Firecracker's LoadSnapshot can be invoked safely.
func (h *Handler) Start() error {
	// UFFD handler runs BEFORE startFirecrackerViaSystemd, which is
	// where the per-VM rundir is normally created.
	if err := os.MkdirAll(filepath.Dir(h.cfg.SocketPath), 0o755); err != nil {
		return fmt.Errorf("mkdir socket dir: %w", err)
	}
	_ = os.Remove(h.cfg.SocketPath)

	src, err := OpenSource(h.cfg.MemSnapPath)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: h.cfg.SocketPath, Net: "unix"})
	if err != nil {
		_ = src.Close()
		return fmt.Errorf("listen %s: %w", h.cfg.SocketPath, err)
	}
	if err := os.Chmod(h.cfg.SocketPath, 0o600); err != nil {
		h.log.Warn().Err(err).Msg("chmod socket failed")
	}

	h.source = src
	h.listener = listener
	return nil
}


// AcceptHandshake blocks on the UDS listener until Firecracker connects
// and sends the UFFD fd + region mappings. ctx supplies the handshake
// deadline — kept separate from Serve's lifetime ctx so a slow handshake
// under burst doesn't share fate with the page-fault loop. The outcome
// is published to WaitHandshake.
func (h *Handler) AcceptHandshake(ctx context.Context) error {
	if h.listener == nil || h.source == nil {
		err := errors.New("AcceptHandshake called before Start (or after Close)")
		h.publishHandshake(err)
		return err
	}
	if err := h.acceptAndReceive(ctx); err != nil {
		err = fmt.Errorf("receive handshake: %w", err)
		h.publishHandshake(err)
		return err
	}
	h.publishHandshake(nil)
	return nil
}

func (h *Handler) publishHandshake(err error) {
	select {
	case h.handshakeDone <- err:
	default:
	}
}

// WaitHandshake returns the AcceptHandshake outcome, blocking until it
// completes or ctx is cancelled. Idempotent.
func (h *Handler) WaitHandshake(ctx context.Context) error {
	select {
	case err := <-h.handshakeDone:
		h.publishHandshake(err)
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Serve runs the page-fault loop (and prefetcher, if enabled) until ctx
// is cancelled or the UFFD fd is closed. AcceptHandshake must have
// returned nil first.
func (h *Handler) Serve(ctx context.Context) error {
	if h.cfg.PrefetchEnabled {
		h.prefetchWg.Add(1)
		go func() {
			defer h.prefetchWg.Done()
			h.runPrefetch(ctx)
		}()
	}
	return h.serveLoop(ctx)
}

func (h *Handler) Close() error {
	if !h.closed.CompareAndSwap(false, true) {
		return nil
	}
	var firstErr error
	if h.listener != nil {
		if err := h.listener.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("close listener: %w", err)
		}
	}
	if h.cfg.SocketPath != "" {
		_ = os.Remove(h.cfg.SocketPath)
	}
	h.closeFd()
	// Drain prefetch before munmap. Fault workers are already joined by
	// serveLoop's g.Wait; only the bare prefetch goroutine needs this.
	h.prefetchWg.Wait()
	if h.source != nil {
		if err := h.source.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("close source: %w", err)
		}
		h.source = nil
	}
	return firstErr
}

// closeFd drops the UFFD file. file.Close() blocks until in-flight
// SyscallConn callbacks return. Idempotent via atomic swap.
func (h *Handler) closeFd() {
	if f := h.file.Swap(nil); f != nil {
		_ = f.Close()
	}
}

// withFd runs fn with the UFFD fd held alive via SyscallConn().Control().
// Returns false if the file is gone.
func (h *Handler) withFd(fn func(fd uintptr)) bool {
	f := h.file.Load()
	if f == nil {
		return false
	}
	sc, err := f.SyscallConn()
	if err != nil {
		return false
	}
	if err := sc.Control(fn); err != nil {
		return false
	}
	return true
}

func (h *Handler) acceptAndReceive(ctx context.Context) error {
	// SetDeadline is the only way to make AcceptUnix interruptible; the
	// watchdog below sets it to the past on ctx cancel.
	if deadline, ok := ctx.Deadline(); ok {
		_ = h.listener.SetDeadline(deadline)
	} else {
		_ = h.listener.SetDeadline(time.Now().Add(30 * time.Second))
	}

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = h.listener.SetDeadline(time.Now())
		case <-stop:
		}
	}()

	conn, err := h.listener.AcceptUnix()
	if err != nil {
		return fmt.Errorf("accept: %w", err)
	}
	defer conn.Close()

	body := make([]byte, 4096)
	oob := make([]byte, unix.CmsgSpace(4))

	n, oobn, _, _, err := conn.ReadMsgUnix(body, oob)
	if err != nil {
		return fmt.Errorf("recvmsg: %w", err)
	}
	if n == 0 {
		return errors.New("empty message from firecracker")
	}

	cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return fmt.Errorf("parse cmsg: %w", err)
	}
	// Firecracker sends exactly one fd; cap defensively.
	uffdFd := -1
	for _, cm := range cmsgs {
		fds, err := unix.ParseUnixRights(&cm)
		if err != nil {
			continue
		}
		if len(fds) > 1 {
			for _, fd := range fds {
				_ = unix.Close(fd)
			}
			return fmt.Errorf("expected 1 fd in SCM_RIGHTS, got %d", len(fds))
		}
		if len(fds) == 1 {
			if uffdFd != -1 {
				_ = unix.Close(fds[0])
				return errors.New("multiple SCM_RIGHTS messages; expected one")
			}
			uffdFd = fds[0]
		}
	}
	if uffdFd == -1 {
		return errors.New("no UFFD fd received in SCM_RIGHTS")
	}

	// Keep the fd non-blocking (firecracker's default). serveLoop drives
	// readiness with poll() inside a SyscallConn callback.

	var mappings []GuestRegionMapping
	if err := json.Unmarshal(body[:n], &mappings); err != nil {
		_ = unix.Close(uffdFd)
		return fmt.Errorf("unmarshal mappings: %w (body=%q)", err, string(body[:n]))
	}
	if len(mappings) == 0 {
		_ = unix.Close(uffdFd)
		return errors.New("firecracker sent zero mappings")
	}
	pageSize := mappings[0].PageSize
	if pageSize == 0 {
		pageSize = mappings[0].PageSizeKib
	}
	if pageSize == 0 {
		_ = unix.Close(uffdFd)
		return fmt.Errorf("invalid page size in mappings: %+v", mappings[0])
	}

	file := os.NewFile(uintptr(uffdFd), fmt.Sprintf("uffd-%d", uffdFd))
	if file == nil {
		_ = unix.Close(uffdFd)
		return fmt.Errorf("os.NewFile returned nil for fd %d", uffdFd)
	}
	// Defensive: if a prior file is somehow still installed, close it.
	if old := h.file.Swap(file); old != nil {
		_ = old.Close()
	}
	h.mappings = mappings
	h.pageSize = pageSize

	h.log.Info().
		Int("regions", len(mappings)).
		Uint64("page_size", pageSize).
		Int("uffd_fd", uffdFd).
		Interface("mappings", mappings).
		Msg("uffd handshake complete")

	return nil
}

// pollTimeoutMs bounds how long each poll waits before the loop checks
// ctx, and also bounds how long closeFd may block on the in-flight
// Control callback. Real events wake poll immediately, so this knob
// doesn't affect throughput.
const pollTimeoutMs = 100

func (h *Handler) serveLoop(ctx context.Context) error {
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(h.cfg.FaultWorkers)

	// Bridge context cancellation to closeFd. file.Close() blocks until
	// in-flight Control callbacks return; the short poll timeout below
	// caps that wait to pollTimeoutMs.
	go func() {
		<-gctx.Done()
		h.closeFd()
	}()

	var msgBuf [32]byte
	for {
		if err := gctx.Err(); err != nil {
			return g.Wait()
		}
		var n int
		var readErr error
		var pollErr error
		var revents int16
		if !h.withFd(func(fd uintptr) {
			pollFds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			_, pollErr = unix.Poll(pollFds, pollTimeoutMs)
			if pollErr != nil {
				return
			}
			revents = pollFds[0].Revents
			if revents&unix.POLLIN != 0 {
				n, readErr = h.readFn(int(fd), msgBuf[:])
			}
		}) {
			return g.Wait()
		}
		if pollErr != nil {
			if errors.Is(pollErr, syscall.EINTR) {
				continue
			}
			return fmt.Errorf("poll uffd: %w", pollErr)
		}
		if revents&unix.POLLIN == 0 {
			if revents&(unix.POLLHUP|unix.POLLNVAL) != 0 {
				return g.Wait()
			}
			if revents&unix.POLLERR != 0 {
				h.log.Debug().Int16("revents", revents).Msg("uffd poll returned POLLERR without POLLIN")
			}
			continue
		}
		if readErr != nil {
			if errors.Is(readErr, syscall.EINTR) {
				continue
			}
			// EBADF means the fd is gone; EINVAL means firecracker
			// unmapped its VMAs. Either is a clean exit.
			if errors.Is(readErr, syscall.EBADF) || errors.Is(readErr, syscall.EINVAL) {
				if errors.Is(readErr, syscall.EINVAL) {
					h.log.Debug().Msg("uffd serveLoop exiting cleanly on EINVAL — firecracker likely unmapped VMAs")
				}
				return g.Wait()
			}
			// EAGAIN despite POLLIN — defensive, retry.
			if errors.Is(readErr, syscall.EAGAIN) || errors.Is(readErr, syscall.EWOULDBLOCK) {
				h.stats.EagainRetries.Add(1)
				continue
			}
			return fmt.Errorf("read uffd_msg: %w", readErr)
		}
		if n == 0 {
			return g.Wait()
		}
		if n < int(unsafe.Sizeof(uffdMsg{})) {
			h.log.Warn().Int("bytes", n).Msg("short uffd_msg read; skipping")
			continue
		}
		msg := *(*uffdMsg)(unsafe.Pointer(&msgBuf[0]))
		switch msg.Event {
		case UFFD_EVENT_PAGEFAULT:
			pf := msg.asPageFault()
			h.servePagefault(g, pf.Address, h.pageSize)
		case UFFD_EVENT_REMOVE:
			h.stats.RemoveEvents.Add(1)
			rm := msg.asRemove()
			h.handleRemove(rm.Start, rm.End)
		default:
			h.stats.UnknownEvents.Add(1)
			h.log.Debug().Uint8("event", msg.Event).Msg("ignoring unknown uffd event")
		}
	}
}

// servePagefault dispatches a single fault to the worker pool. The pool
// blocks if all FaultWorkers slots are busy — natural backpressure.
func (h *Handler) servePagefault(g *errgroup.Group, faultAddr, pageSize uint64) {
	g.Go(func() error {
		pageAddr := faultAddr &^ (pageSize - 1)

		region := h.findRegion(pageAddr)
		if region == nil {
			h.log.Error().
				Str("fault_addr", fmt.Sprintf("%#x", faultAddr)).
				Str("page_addr", fmt.Sprintf("%#x", pageAddr)).
				Uint64("page_size", pageSize).
				Interface("mappings", h.mappings).
				Msg("page fault address outside all regions; killing handler")
			return fmt.Errorf("address %#x outside guest regions", faultAddr)
		}

		offset := region.Offset + (pageAddr - region.BaseHostVirtAddr)
		if h.cfg.OnPageFault != nil {
			h.cfg.OnPageFault(offset)
		}
		srcPtr, err := h.source.PagePointer(offset, pageSize)
		if err != nil {
			h.stats.CopyErrors.Add(1)
			return fmt.Errorf("source page lookup: %w", err)
		}

		var copyErr error
		if !h.withFd(func(fd uintptr) {
			_, copyErr = ioctlCopy(fd, pageAddr, srcPtr, pageSize, 0)
		}) {
			return nil
		}
		if copyErr != nil {
			// EEXIST: another fault on the same page raced ahead of us;
			// it's already mapped. Benign.
			if errors.Is(copyErr, syscall.EEXIST) {
				h.stats.Eexist.Add(1)
				return nil
			}
			// EAGAIN: a REMOVE event is pending in the kernel queue;
			// all ioctls return EAGAIN until it's drained. The kernel
			// re-fires the fault after we handle the REMOVE.
			if errors.Is(copyErr, syscall.EAGAIN) {
				h.stats.EagainRetries.Add(1)
				return nil
			}
			h.stats.CopyErrors.Add(1)
			return fmt.Errorf("UFFDIO_COPY at %#x: %w", pageAddr, copyErr)
		}
		h.stats.FaultsServed.Add(1)
		h.stats.BytesServed.Add(pageSize)
		return nil
	})
}

// handleRemove responds to balloon-device removals by zeroing the range.
// Without this, subsequent faults on these pages would resolve to stale
// mem.snap contents instead of zero pages.
func (h *Handler) handleRemove(start, end uint64) {
	if end <= start {
		return
	}
	length := end - start
	var err error
	if !h.withFd(func(fd uintptr) {
		err = ioctlZeropage(fd, start, length)
	}) {
		return
	}
	if err != nil {
		// EAGAIN: another REMOVE event is queued ahead of us — the next
		// REMOVE will cover this range, so skipping the zero is correct.
		if errors.Is(err, syscall.EAGAIN) {
			h.stats.EagainRetries.Add(1)
			return
		}
		h.log.Warn().Err(err).Uint64("start", start).Uint64("end", end).Msg("UFFDIO_ZEROPAGE failed")
	}
}

func (h *Handler) findRegion(faultAddr uint64) *GuestRegionMapping {
	for i := range h.mappings {
		if h.mappings[i].contains(faultAddr) {
			return &h.mappings[i]
		}
	}
	return nil
}

