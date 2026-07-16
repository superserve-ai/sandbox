// Presence-aware comparison. A layered diff overlay's meaning is the pair
// (bytes, presence): the .presence side-car says which pages the overlay
// provides; every other page is resolved from the template base. Raw
// byte comparison is blind to that second half — a transfer that materializes
// holes or punches holes through written zero pages can leave two files
// byte-identical while their restored guests differ. This mode compares what a
// layered restore would actually serve: presence bits page by page, and page
// bytes only where both sides claim the page.
//
// The side-car format itself lives in internal/presence — the repo's single
// source of truth, shared with vmd's convergence sweep.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/superserve-ai/sandbox/internal/presence"
)

type presenceResult struct {
	totalPages int
	// presenceDiff: pages one side provides and the other resolves from the
	// base — the mismatch class raw byte comparison cannot see.
	presenceDiff []int
	// contentDiff: pages both sides provide, with different bytes.
	contentDiff []int
}

// comparePresenceAware compares two overlay/side-car pairs as a layered
// restore would resolve them. Pages absent on both sides are equal by
// definition (both defer to the base, whose equality is checked separately
// with a plain byte comparison of the base files).
func comparePresenceAware(pathA, pathB string, pageSize int) (presenceResult, error) {
	pa, err := presence.Read(pathA)
	if err != nil {
		return presenceResult{}, err
	}
	pb, err := presence.Read(pathB)
	if err != nil {
		return presenceResult{}, err
	}
	if pa.PageSize != uint64(pageSize) {
		return presenceResult{}, fmt.Errorf("%s.presence: page size %d does not match -page-size %d", pathA, pa.PageSize, pageSize)
	}
	if pb.PageSize != uint64(pageSize) {
		return presenceResult{}, fmt.Errorf("%s.presence: page size %d does not match -page-size %d", pathB, pb.PageSize, pageSize)
	}
	if pa.NPages != pb.NPages {
		return presenceResult{}, fmt.Errorf("side-cars disagree on page count: %d vs %d", pa.NPages, pb.NPages)
	}
	fa, err := os.Open(pathA)
	if err != nil {
		return presenceResult{}, err
	}
	defer fa.Close()
	fb, err := os.Open(pathB)
	if err != nil {
		return presenceResult{}, err
	}
	defer fb.Close()
	for _, f := range []*os.File{fa, fb} {
		st, err := f.Stat()
		if err != nil {
			return presenceResult{}, err
		}
		// Exact size, not a page-count ceiling: an overlay truncated by less
		// than one page would round up to the right count, and if that final
		// page is absent in both bitmaps the compare loop never touches it —
		// "identical" for an artifact the restore would reject as short.
		if want := pa.NPages * uint64(pageSize); uint64(st.Size()) != want {
			return presenceResult{}, fmt.Errorf("%s: %d bytes on disk, side-car geometry needs %d", f.Name(), st.Size(), want)
		}
	}

	res := presenceResult{totalPages: int(pa.NPages)}
	bufA := make([]byte, pageSize)
	bufB := make([]byte, pageSize)
	for page := 0; page < int(pa.NPages); page++ {
		sa, sb := pa.IsSet(page), pb.IsSet(page)
		if sa != sb {
			res.presenceDiff = append(res.presenceDiff, page)
			continue
		}
		if !sa {
			continue // both resolve this page from the base
		}
		off := int64(page) * int64(pageSize)
		nA, errA := fa.ReadAt(bufA, off)
		if errA != nil && !errors.Is(errA, io.EOF) {
			return res, fmt.Errorf("read %s page %d: %w", pathA, page, errA)
		}
		nB, errB := fb.ReadAt(bufB, off)
		if errB != nil && !errors.Is(errB, io.EOF) {
			return res, fmt.Errorf("read %s page %d: %w", pathB, page, errB)
		}
		if nA != nB || !bytes.Equal(bufA[:nA], bufB[:nB]) {
			res.contentDiff = append(res.contentDiff, page)
		}
	}
	return res, nil
}
