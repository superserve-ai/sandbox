package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/superserve-ai/sandbox/internal/presence"
)

// Format-level tests (sentinels, CRC, geometry, atomic write) live with the
// format in internal/presence; these tests cover the compare semantics.

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
	if err := presence.Write(src, ps, 4, []uint64{0b0110}); err != nil {
		t.Fatal(err)
	}
	if err := presence.Write(dst, ps, 4, []uint64{0b0110}); err != nil {
		t.Fatal(err)
	}
	res, err := comparePresenceAware(src, dst, ps)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.presenceDiff) != 0 || len(res.contentDiff) != 0 {
		t.Fatalf("intact pair: got %+v, want identical", res)
	}

	// Destination side-car regenerated from the mangled extents: page 2 flips
	// from "overlay zeros" to "base bytes" — only presence-aware compare sees it.
	if err := presence.Write(dst, ps, 4, []uint64{0b0010}); err != nil {
		t.Fatal(err)
	}
	res, err = comparePresenceAware(src, dst, ps)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.presenceDiff) != 1 || res.presenceDiff[0] != 2 {
		t.Fatalf("presence diff: got %+v, want page 2", res.presenceDiff)
	}

	// Both present with different bytes is a content diff.
	if err := presence.Write(dst, ps, 4, []uint64{0b0110}); err != nil {
		t.Fatal(err)
	}
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
