package presence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Known-answer values computed with the CRC-64 implementation the
// snapshotting side uses (Jones polynomial, reflected, zero init/xorout).
// If this fails, Read would reject every genuine side-car — or a wrong
// table would accept corrupt ones.
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
		if got := presenceCRC([]byte(c.in)); got != c.want {
			t.Errorf("crc64(%q) = %#x, want %#x", c.in, got, c.want)
		}
	}
}

func TestEncodeReadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	mem := filepath.Join(dir, "mem.diff")

	if err := Write(mem, 4096, 130, []uint64{^uint64(0), 0b11, 0}); err != nil {
		t.Fatalf("write: %v", err)
	}
	p, err := Read(mem)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if p.PageSize != 4096 || p.NPages != 130 {
		t.Errorf("geometry: got (%d,%d)", p.PageSize, p.NPages)
	}
	if !p.IsSet(0) || !p.IsSet(63) || !p.IsSet(64) || !p.IsSet(65) || p.IsSet(66) || p.IsSet(129) {
		t.Error("bits decoded wrong")
	}

	// Word-count mismatch is rejected at write time.
	if err := Write(mem, 4096, 130, []uint64{0}); err == nil {
		t.Error("short bitmap: want error")
	}
}

func TestReadRejectsSentinelsAndCorruption(t *testing.T) {
	dir := t.TempDir()
	mem := filepath.Join(dir, "mem.diff")
	sc := SidecarPath(mem)

	// Missing surfaces the raw not-exist error (callers fall back / gate).
	if _, err := Read(mem); !os.IsNotExist(err) {
		t.Errorf("missing: got %v, want IsNotExist", err)
	}

	// 0-byte torn-save sentinel carries the exact marker orchestrators match.
	if err := os.WriteFile(sc, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(mem); err == nil || !strings.Contains(err.Error(), "(torn snapshot save)") {
		t.Errorf("torn sentinel: %v", err)
	}

	// The 1-byte un-layerable marker gets a distinct, non-torn error.
	if err := os.WriteFile(sc, []byte{Underivable}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(mem); err == nil || !strings.Contains(err.Error(), "un-layerable") ||
		strings.Contains(err.Error(), "torn") {
		t.Errorf("marker sentinel: %v", err)
	}

	// Garbage header.
	if err := os.WriteFile(sc, make([]byte, 64), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(mem); err == nil || !strings.Contains(err.Error(), "unrecognized header") {
		t.Errorf("garbage: %v", err)
	}

	// One flipped bit anywhere fails the checksum — without it, a flipped
	// word silently mis-layers 64 pages.
	if err := Write(mem, 4096, 4, []uint64{0b0110}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(sc)
	if err != nil {
		t.Fatal(err)
	}
	raw[presenceHeaderLen] ^= 0x01
	if err := os.WriteFile(sc, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(mem); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Errorf("corrupted: %v", err)
	}
}

func TestWriteIsAtomic(t *testing.T) {
	dir := t.TempDir()
	mem := filepath.Join(dir, "mem.diff")

	// Overwrite an existing side-car: the temp file must not linger and the
	// destination must decode cleanly (rename, never truncate-in-place).
	if err := Write(mem, 4096, 4, []uint64{0b0001}); err != nil {
		t.Fatal(err)
	}
	if err := Write(mem, 4096, 4, []uint64{0b1111}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(SidecarPath(mem) + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file left behind: %v", err)
	}
	p, err := Read(mem)
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsSet(3) {
		t.Error("overwrite content not visible")
	}
}
