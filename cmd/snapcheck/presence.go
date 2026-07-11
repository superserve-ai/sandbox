// Presence-aware comparison. A layered diff overlay's meaning is the pair
// (bytes, presence): the .presence side-car says which pages the overlay
// provides; every other page is resolved from the template base. Raw
// byte comparison is blind to that second half — a transfer that materializes
// holes or punches holes through written zero pages can leave two files
// byte-identical while their restored guests differ. This mode compares what a
// layered restore would actually serve: presence bits page by page, and page
// bytes only where both sides claim the page.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc64"
	"io"
	"os"
)

const (
	presenceMagic = "FCPRSNC1"
	// presenceHeaderLen is magic + page_size (u64 LE) + npages (u64 LE).
	presenceHeaderLen = 24
	// presenceUnderivable is the 1-byte side-car content marking a memory file
	// whose save could not derive a presence bitmap.
	presenceUnderivable = 0x55
)

// crc64Table is the Jones polynomial (0xad93d23594c935a9) in the bit-reversed
// form stdlib's reflected implementation expects.
var crc64Table = crc64.MakeTable(0x95ac9329ac4bc9b5)

// crc64Sum computes the zero-init/zero-xorout CRC-64 variant the snapshotting
// side writes. stdlib bakes in all-ones init and xorout; seeding Update with ^0
// cancels both inversions. Pinned to the snapshotter's implementation by
// TestCRC64MatchesSnapshotter's known-answer values.
func crc64Sum(data []byte) uint64 {
	return ^crc64.Update(^uint64(0), crc64Table, data)
}

type presenceBitmap struct {
	pageSize uint64
	npages   uint64
	bits     []uint64
}

func (p presenceBitmap) isSet(i int) bool {
	w := i >> 6
	return w < len(p.bits) && p.bits[w]&(1<<(uint(i)&63)) != 0
}

// readPresence parses `<memPath>.presence`: magic, page_size, npages, bitmap
// words, trailing CRC64 over everything before it.
func readPresence(memPath string) (presenceBitmap, error) {
	path := memPath + ".presence"
	b, err := os.ReadFile(path)
	if err != nil {
		return presenceBitmap{}, err
	}
	switch {
	case len(b) == 0:
		return presenceBitmap{}, fmt.Errorf("%s: empty (torn snapshot save)", path)
	case len(b) == 1 && b[0] == presenceUnderivable:
		return presenceBitmap{}, fmt.Errorf("%s: marked un-layerable by its save", path)
	}
	if len(b) < presenceHeaderLen+8 || string(b[:8]) != presenceMagic {
		return presenceBitmap{}, fmt.Errorf("%s: unrecognized header", path)
	}
	payload, trailer := b[:len(b)-8], b[len(b)-8:]
	if got, want := crc64Sum(payload), binary.LittleEndian.Uint64(trailer); got != want {
		return presenceBitmap{}, fmt.Errorf("%s: checksum mismatch (computed %#x, stored %#x)", path, got, want)
	}
	p := presenceBitmap{
		pageSize: binary.LittleEndian.Uint64(b[8:16]),
		npages:   binary.LittleEndian.Uint64(b[16:24]),
	}
	words := (p.npages + 63) / 64
	if uint64(len(b)) != presenceHeaderLen+words*8+8 {
		return presenceBitmap{}, fmt.Errorf("%s: %d bytes, want %d for %d pages",
			path, len(b), presenceHeaderLen+words*8+8, p.npages)
	}
	p.bits = make([]uint64, words)
	for i := range p.bits {
		p.bits[i] = binary.LittleEndian.Uint64(b[presenceHeaderLen+i*8:])
	}
	return p, nil
}

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
	pa, err := readPresence(pathA)
	if err != nil {
		return presenceResult{}, err
	}
	pb, err := readPresence(pathB)
	if err != nil {
		return presenceResult{}, err
	}
	if pa.pageSize != uint64(pageSize) {
		return presenceResult{}, fmt.Errorf("%s.presence: page size %d does not match -page-size %d", pathA, pa.pageSize, pageSize)
	}
	if pb.pageSize != uint64(pageSize) {
		return presenceResult{}, fmt.Errorf("%s.presence: page size %d does not match -page-size %d", pathB, pb.pageSize, pageSize)
	}
	if pa.npages != pb.npages {
		return presenceResult{}, fmt.Errorf("side-cars disagree on page count: %d vs %d", pa.npages, pb.npages)
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
		if got := (uint64(st.Size()) + uint64(pageSize) - 1) / uint64(pageSize); got != pa.npages {
			return presenceResult{}, fmt.Errorf("%s: %d pages on disk, side-car says %d", f.Name(), got, pa.npages)
		}
	}

	res := presenceResult{totalPages: int(pa.npages)}
	bufA := make([]byte, pageSize)
	bufB := make([]byte, pageSize)
	for page := 0; page < int(pa.npages); page++ {
		sa, sb := pa.isSet(page), pb.isSet(page)
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
