package uffd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// runPrefetch warms guest memory pre-emptively. Replays AccessLogPath if
// present (only pages the guest will touch); otherwise walks the
// snapshot sequentially. Pages already faulted by the guest return
// EEXIST from UFFDIO_COPY and are skipped cheaply.
func (h *Handler) runPrefetch(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			h.log.Error().Interface("panic", r).Msg("prefetch panicked")
		}
	}()

	pageSize := h.pageSize
	if pageSize == 0 {
		h.log.Warn().Msg("prefetch: no page size, skipping")
		return
	}
	if h.uffdFd.Load() == uffdClosed {
		return
	}

	offsets, ordered := h.prefetchOffsets()
	h.log.Info().Bool("ordered", ordered).Int("offsets", len(offsets)).Msg("prefetch starting")

	for _, off := range offsets {
		if ctx.Err() != nil {
			return
		}
		stop, err := h.prefetchOne(off, pageSize)
		if err != nil {
			// Abort on first non-benign error; on-demand fault serving
			// is unaffected.
			h.log.Warn().Err(err).Uint64("offset", off).Msg("prefetch aborted")
			return
		}
		if stop {
			return
		}
	}
	h.log.Debug().Uint64("served", h.stats.PrefetchedPages.Load()).Msg("prefetch complete")
}

// prefetchOne returns stop=true when the fd has been closed under us,
// signaling the caller to exit the prefetch loop.
func (h *Handler) prefetchOne(offset, pageSize uint64) (stop bool, err error) {
	region := h.regionForOffset(offset)
	if region == nil {
		return false, nil
	}
	dst := region.BaseHostVirtAddr + (offset - region.Offset)
	srcPtr, perr := h.source.PagePointer(offset, pageSize)
	if perr != nil {
		return false, perr
	}

	h.fdMu.RLock()
	fd := h.uffdFd.Load()
	if fd == uffdClosed {
		h.fdMu.RUnlock()
		return true, nil
	}
	_, copyErr := ioctlCopy(fd, dst, srcPtr, pageSize, 0)
	h.fdMu.RUnlock()
	if copyErr != nil {
		if errors.Is(copyErr, syscall.EEXIST) {
			h.stats.PrefetchSkipped.Add(1)
			return false, nil
		}
		if errors.Is(copyErr, syscall.EAGAIN) {
			// REMOVE pending in queue; main fault loop will drain it.
			// Guest will re-fault this page later if it needs it.
			h.stats.PrefetchSkipped.Add(1)
			return false, nil
		}
		return false, fmt.Errorf("prefetch UFFDIO_COPY at %#x: %w", dst, copyErr)
	}
	h.stats.PrefetchedPages.Add(1)
	return false, nil
}

func (h *Handler) regionForOffset(offset uint64) *GuestRegionMapping {
	for i := range h.mappings {
		r := &h.mappings[i]
		if offset >= r.Offset && offset < r.Offset+r.Size {
			return r
		}
	}
	return nil
}

// prefetchOffsets returns page-aligned offsets to prefetch in order.
// The bool is true when access.log drove the order, false for fallback.
func (h *Handler) prefetchOffsets() ([]uint64, bool) {
	if h.cfg.AccessLogPath != "" {
		if offsets, err := readAccessLog(h.cfg.AccessLogPath, h.pageSize); err == nil && len(offsets) > 0 {
			return offsets, true
		}
	}
	// Sequential fallback: walk every region from start to end.
	var out []uint64
	for _, r := range h.mappings {
		for off := r.Offset; off < r.Offset+r.Size; off += h.pageSize {
			out = append(out, off)
		}
	}
	return out, false
}

// readAccessLog parses newline-separated decimal offsets. Misaligned
// lines and blank/# lines are silently skipped.
func readAccessLog(path string, pageSize uint64) ([]uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var offsets []uint64
	seen := make(map[uint64]struct{})
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		s := strings.TrimSpace(scanner.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			continue
		}
		if n%pageSize != 0 {
			continue
		}
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		offsets = append(offsets, n)
	}
	if err := scanner.Err(); err != nil {
		return offsets, err
	}
	return offsets, nil
}
