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

// uffdClosed is the sentinel value of Handler.uffdFd before the fd is
// received and after it has been closed.
const uffdClosed = ^uintptr(0)

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

	// fdMu (RLock per ioctl, Lock around close) prevents an ioctl from
	// racing with close + kernel fd-reuse. uffdFd is atomic so the
	// lock-free serveLoop read is sound under Go's memory model.
	fdMu   sync.RWMutex
	uffdFd atomic.Uintptr // uffdClosed when not held

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
	h.uffdFd.Store(uffdClosed)
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

// closeFd closes the userfaultfd under the write lock so no in-flight
// ioctl can be operating on the fd when the kernel frees the slot
// (preventing fd-number reuse from redirecting a worker's ioctl to an
// unrelated open). Idempotent.
func (h *Handler) closeFd() {
	h.fdMu.Lock()
	defer h.fdMu.Unlock()
	fd := h.uffdFd.Load()
	if fd == uffdClosed {
		return
	}
	_ = unix.Close(int(fd))
	h.uffdFd.Store(uffdClosed)
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

	// Firecracker creates UFFD with O_NONBLOCK; clear it so unix.Read
	// blocks (cancellation closes the fd → EBADF wakes the read).
	if flags, err := unix.FcntlInt(uintptr(uffdFd), unix.F_GETFL, 0); err == nil {
		_, _ = unix.FcntlInt(uintptr(uffdFd), unix.F_SETFL, flags&^unix.O_NONBLOCK)
	}

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

	h.uffdFd.Store(uintptr(uffdFd))
	h.mappings = mappings
	h.pageSize = pageSize

	h.log.Info().
		Int("regions", len(mappings)).
		Uint64("page_size", pageSize).
		Int("uffd_fd", uffdFd).
		Msg("uffd handshake complete")

	return nil
}

func (h *Handler) serveLoop(ctx context.Context) error {
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(h.cfg.FaultWorkers)

	// Closing the UFFD fd is the only way to wake a blocking read on it,
	// so bridge context cancellation to a close here.
	go func() {
		<-gctx.Done()
		h.closeFd()
	}()

	var msgBuf [32]byte
	for {
		if err := gctx.Err(); err != nil {
			return g.Wait()
		}
		fd := h.uffdFd.Load()
		if fd == uffdClosed {
			return g.Wait()
		}
		n, err := h.readFn(int(fd), msgBuf[:])
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			// EBADF: cancellation goroutine closed the fd. EINVAL: kernel
			// returned "invalid argument", typically because Firecracker
			// exited and unmapped its VMAs before we drained the queue.
			// Both mean "nothing more to read here" — exit cleanly.
			if errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.EINVAL) {
				if errors.Is(err, syscall.EINVAL) {
					h.log.Debug().Msg("uffd serveLoop exiting cleanly on EINVAL — firecracker likely unmapped VMAs")
				}
				return g.Wait()
			}
			return fmt.Errorf("read uffd_msg: %w", err)
		}
		if n == 0 {
			return g.Wait() // Firecracker exited.
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
			h.log.Error().Uint64("addr", faultAddr).Msg("page fault address outside all regions; killing handler")
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

		h.fdMu.RLock()
		fd := h.uffdFd.Load()
		if fd == uffdClosed {
			h.fdMu.RUnlock()
			return nil
		}
		_, copyErr := ioctlCopy(fd, pageAddr, srcPtr, pageSize, 0)
		h.fdMu.RUnlock()
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
	h.fdMu.RLock()
	fd := h.uffdFd.Load()
	if fd == uffdClosed {
		h.fdMu.RUnlock()
		return
	}
	err := ioctlZeropage(fd, start, length)
	h.fdMu.RUnlock()
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

