package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Known-answer values computed with the CRC-64 implementation the
// snapshotting side uses. If this fails, readPresence would reject every
// genuine side-car (or worse, a fixed table here would accept corrupt ones).
func TestCRC64MatchesSnapshotter(t *testing.T) {
	cases := []struct {
		in   string
		want uint64
	}{
		{"123456789", 0xe9c6d914c4b8d9ca},
		{"", 0},
		{"FCPRSNC1", 0x9fee52a36dd3c749},
	}
	for _, c := range cases {
		if got := crc64Sum([]byte(c.in)); got != c.want {
			t.Errorf("crc64(%q) = %#x, want %#x", c.in, got, c.want)
		}
	}
}

// writeSidecar encodes a presence side-car in the on-disk layout: magic,
// page_size, npages, bitmap words, trailing CRC64.
func writeSidecar(t *testing.T, memPath string, pageSize, npages int, bits []uint64) {
	t.Helper()
	b := []byte(presenceMagic)
	b = binary.LittleEndian.AppendUint64(b, uint64(pageSize))
	b = binary.LittleEndian.AppendUint64(b, uint64(npages))
	for _, w := range bits {
		b = binary.LittleEndian.AppendUint64(b, w)
	}
	b = binary.LittleEndian.AppendUint64(b, crc64Sum(b))
	if err := os.WriteFile(memPath+".presence", b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadPresence(t *testing.T) {
	dir := t.TempDir()
	mem := filepath.Join(dir, "mem.diff")

	writeSidecar(t, mem, 4096, 4, []uint64{0b0110})
	p, err := readPresence(mem)
	if err != nil {
		t.Fatalf("valid side-car: %v", err)
	}
	if p.pageSize != 4096 || p.npages != 4 {
		t.Errorf("geometry: got (%d,%d)", p.pageSize, p.npages)
	}
	if p.isSet(0) || !p.isSet(1) || !p.isSet(2) || p.isSet(3) {
		t.Error("bits decoded wrong")
	}

	// Sentinels get distinct, actionable errors.
	if err := os.WriteFile(mem+".presence", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPresence(mem); err == nil || !strings.Contains(err.Error(), "torn snapshot save") {
		t.Errorf("empty side-car: %v", err)
	}
	if err := os.WriteFile(mem+".presence", []byte{presenceUnderivable}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPresence(mem); err == nil || !strings.Contains(err.Error(), "un-layerable") {
		t.Errorf("marker side-car: %v", err)
	}

	// One flipped bit fails the checksum.
	writeSidecar(t, mem, 4096, 4, []uint64{0b0110})
	raw, err := os.ReadFile(mem + ".presence")
	if err != nil {
		t.Fatal(err)
	}
	raw[presenceHeaderLen] ^= 0x01
	if err := os.WriteFile(mem+".presence", raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPresence(mem); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Errorf("corrupted side-car: %v", err)
	}
}

// The incident this mode exists for: a zero-eliding transfer turns a
// dirtied-to-zero page into a hole. The two overlays are byte-identical —
// raw comparison calls them equal — but if the destination's side-car no
// longer claims the page, a layered restore serves stale base bytes there.
func TestPresenceAwareCatchesWhatBytesCannot(t *testing.T) {
	const ps = 4096
	dir := t.TempDir()

	writeOverlay := func(name string, holePage2 bool) string {
		p := filepath.Join(dir, name)
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(4 * ps); err != nil {
			t.Fatal(err)
		}
		// Page 1: real data. Page 2: written zeros on the source, elided to a
		// hole on the copy — identical bytes when read either way.
		if _, err := f.WriteAt(bytes.Repeat([]byte{0xAA}, ps), ps); err != nil {
			t.Fatal(err)
		}
		if !holePage2 {
			if _, err := f.WriteAt(make([]byte, ps), 2*ps); err != nil {
				t.Fatal(err)
			}
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		return p
	}

	src := writeOverlay("src.diff", false)
	dst := writeOverlay("dst.diff", true)

	// Raw bytes: identical — the blindness under test.
	raw, err := compareFiles(src, dst, ps)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw.diffPages) != 0 {
		t.Fatalf("byte compare should be blind here, got diffs %v", raw.diffPages)
	}

	// Side-car pair intact (transfer carried it): logically identical.
	writeSidecar(t, src, ps, 4, []uint64{0b0110})
	writeSidecar(t, dst, ps, 4, []uint64{0b0110})
	res, err := comparePresenceAware(src, dst, ps)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.presenceDiff) != 0 || len(res.contentDiff) != 0 {
		t.Fatalf("intact pair: got %+v, want identical", res)
	}

	// Destination side-car regenerated from the mangled extents: page 2 flips
	// from "overlay zeros" to "base bytes" — only presence-aware compare sees it.
	writeSidecar(t, dst, ps, 4, []uint64{0b0010})
	res, err = comparePresenceAware(src, dst, ps)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.presenceDiff) != 1 || res.presenceDiff[0] != 2 {
		t.Fatalf("presence diff: got %+v, want page 2", res.presenceDiff)
	}

	// Both present with different bytes is a content diff.
	writeSidecar(t, dst, ps, 4, []uint64{0b0110})
	f, err := os.OpenFile(dst, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(bytes.Repeat([]byte{0xBB}, ps), ps); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	res, err = comparePresenceAware(src, dst, ps)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.contentDiff) != 1 || res.contentDiff[0] != 1 {
		t.Fatalf("content diff: got %+v, want page 1", res.contentDiff)
	}

	// A sub-page truncation must fail geometry, never report identical: the
	// ceiling page count would still match, and a truncated final page absent
	// in both bitmaps would be skipped by the compare loop entirely.
	if err := os.Truncate(dst, int64(4*ps-100)); err != nil {
		t.Fatal(err)
	}
	if _, err := comparePresenceAware(src, dst, ps); err == nil {
		t.Error("truncated overlay: want geometry error, got nil")
	}
}
