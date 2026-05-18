package templatedelta

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// writeRustEquivalentDelta produces a delta file in exactly the format the
// firecracker fork's `write_delta` produces, given a synthetic bitmap and
// per-block content. Used by tests to round-trip against
// FlattenInto without needing the actual firecracker binary.
func writeRustEquivalentDelta(t *testing.T, path string, blockSize uint32, totalBlocks uint64, dirty map[uint64][]byte) {
	t.Helper()

	bitmapWords := (totalBlocks + 63) / 64
	bitmapLen := uint32(bitmapWords * 8)
	bitmap := make([]byte, bitmapLen)
	for i := range dirty {
		bitmap[i/8] |= 1 << (i % 8)
	}
	bitmapCRC := crc64Bare(0, bitmap)

	var buf bytes.Buffer
	put64 := func(v uint64) {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], v)
		buf.Write(b[:])
	}
	put32 := func(v uint32) {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], v)
		buf.Write(b[:])
	}

	put64(deltaMagic)
	put32(deltaVersion)
	put32(blockSize)
	put64(totalBlocks)
	put64(uint64(len(dirty)))
	put32(bitmapLen)
	buf.Write(bitmap)
	put64(bitmapCRC)

	// Blocks in ascending bit-index order.
	var dataCRC uint64
	for i := uint64(0); i < totalBlocks; i++ {
		block, ok := dirty[i]
		if !ok {
			continue
		}
		if len(block) != int(blockSize) {
			t.Fatalf("test bug: block %d has %d bytes, expected %d", i, len(block), blockSize)
		}
		buf.Write(block)
		dataCRC = crc64Bare(dataCRC, block)
	}
	put64(dataCRC)

	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write delta: %v", err)
	}
}

func TestFlattenDeltaIntoBase_AppliesBlocks(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.ext4")
	deltaPath := filepath.Join(dir, "rootfs.delta")

	const blockSize uint32 = 4096
	const totalBlocks uint64 = 16 // 64 KB virtual disk
	diskSize := int64(blockSize) * int64(totalBlocks)

	// Start with a base full of 0xAA at every byte.
	baseInit := bytes.Repeat([]byte{0xAA}, int(diskSize))
	if err := os.WriteFile(basePath, baseInit, 0o644); err != nil {
		t.Fatalf("write base: %v", err)
	}

	// Delta dirties blocks 1, 5, and 14 with distinct content.
	mkBlock := func(b byte) []byte { return bytes.Repeat([]byte{b}, int(blockSize)) }
	dirty := map[uint64][]byte{
		1:  mkBlock(0x11),
		5:  mkBlock(0x55),
		14: mkBlock(0xEE),
	}
	writeRustEquivalentDelta(t, deltaPath, blockSize, totalBlocks, dirty)

	if err := FlattenInto(basePath, deltaPath); err != nil {
		t.Fatalf("flatten: %v", err)
	}

	// Base should now have dirty content at blocks 1, 5, 14 and 0xAA elsewhere.
	got, err := os.ReadFile(basePath)
	if err != nil {
		t.Fatalf("read base: %v", err)
	}
	for i := uint64(0); i < totalBlocks; i++ {
		want, ok := dirty[i]
		if !ok {
			want = mkBlock(0xAA)
		}
		offset := int(i) * int(blockSize)
		actual := got[offset : offset+int(blockSize)]
		if !bytes.Equal(actual, want) {
			t.Errorf("block %d mismatch: got %x..., want %x...", i, actual[:8], want[:8])
		}
	}
}

func TestFlattenDeltaIntoBase_EmptyDeltaAfter(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.ext4")
	deltaPath := filepath.Join(dir, "rootfs.delta")

	const blockSize uint32 = 4096
	const totalBlocks uint64 = 8

	if err := os.WriteFile(basePath, make([]byte, int(blockSize)*int(totalBlocks)), 0o644); err != nil {
		t.Fatalf("write base: %v", err)
	}
	mkBlock := func(b byte) []byte { return bytes.Repeat([]byte{b}, int(blockSize)) }
	writeRustEquivalentDelta(t, deltaPath, blockSize, totalBlocks, map[uint64][]byte{
		2: mkBlock(0x22),
		7: mkBlock(0x77),
	})

	if err := FlattenInto(basePath, deltaPath); err != nil {
		t.Fatalf("flatten: %v", err)
	}

	// Re-read the delta. It should now be the empty form: same header
	// (magic, version, block_size, total_blocks preserved), dirty_count=0,
	// all-zero bitmap of the original byte length, valid bitmap CRC, no
	// data section, data_crc=0.
	hdr, bitmap, dataStart, err := parseDeltaHeader(mustRead(t, deltaPath))
	if err != nil {
		t.Fatalf("parse rewritten delta: %v", err)
	}
	if hdr.blockSize != blockSize {
		t.Errorf("blockSize = %d, want %d", hdr.blockSize, blockSize)
	}
	if hdr.totalBlocks != totalBlocks {
		t.Errorf("totalBlocks = %d, want %d", hdr.totalBlocks, totalBlocks)
	}
	if hdr.dirtyCount != 0 {
		t.Errorf("dirtyCount = %d, want 0", hdr.dirtyCount)
	}
	for i, b := range bitmap {
		if b != 0 {
			t.Errorf("bitmap byte %d = 0x%02X, want 0", i, b)
		}
	}
	// File size after dataStart should be exactly 8 bytes (data_crc) with
	// no block content.
	full := mustRead(t, deltaPath)
	if got := len(full) - dataStart; got != 8 {
		t.Errorf("post-bitmap bytes = %d, want 8 (just data_crc)", got)
	}
	if got := binary.LittleEndian.Uint64(full[dataStart:]); got != 0 {
		t.Errorf("data_crc = 0x%016X, want 0", got)
	}
}

func TestFlattenDeltaIntoBase_RoundTripIdempotent(t *testing.T) {
	// After flatten, the rewritten delta should be re-parseable by
	// parseDeltaHeader without error (the same code path apply_delta
	// uses up to the data section).
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.ext4")
	deltaPath := filepath.Join(dir, "rootfs.delta")

	const blockSize uint32 = 512
	const totalBlocks uint64 = 100

	if err := os.WriteFile(basePath, make([]byte, int(blockSize)*int(totalBlocks)), 0o644); err != nil {
		t.Fatalf("write base: %v", err)
	}
	mkBlock := func(b byte) []byte { return bytes.Repeat([]byte{b}, int(blockSize)) }
	dirty := make(map[uint64][]byte)
	for i := uint64(0); i < totalBlocks; i += 7 {
		dirty[i] = mkBlock(byte(i))
	}
	writeRustEquivalentDelta(t, deltaPath, blockSize, totalBlocks, dirty)

	if err := FlattenInto(basePath, deltaPath); err != nil {
		t.Fatalf("first flatten: %v", err)
	}
	// Running flatten again on the now-empty delta should be a no-op.
	if err := FlattenInto(basePath, deltaPath); err != nil {
		t.Fatalf("second flatten (no-op): %v", err)
	}
}

// Cross-language CRC compatibility is validated end-to-end by the
// template-builder running against firecracker; these are just the
// trivial invariants.
func TestCRC64Bare_TrivialInvariants(t *testing.T) {
	if got := crc64Bare(0, nil); got != 0 {
		t.Errorf("empty data with seed 0: got 0x%X, want 0", got)
	}
	if got := crc64Bare(0xDEADBEEFDEADBEEF, nil); got != 0xDEADBEEFDEADBEEF {
		t.Errorf("empty data: seed should be returned unchanged, got 0x%X", got)
	}
	// table[0] = 0 for any reflected CRC polynomial.
	if got := crc64Bare(0, []byte{0x00}); got != 0 {
		t.Errorf("single zero byte with seed 0: got 0x%X, want 0", got)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func TestParseDeltaHeader_BadMagic(t *testing.T) {
	b := buildValidEmptyDelta(4096, 8)
	binary.LittleEndian.PutUint64(b[0:8], 0xDEADBEEF) // overwrite magic
	if _, _, _, err := parseDeltaHeader(b); err == nil {
		t.Fatal("expected error for bad magic, got nil")
	}
}

func TestParseDeltaHeader_BadVersion(t *testing.T) {
	b := buildValidEmptyDelta(4096, 8)
	binary.LittleEndian.PutUint32(b[8:12], 999) // overwrite version
	if _, _, _, err := parseDeltaHeader(b); err == nil {
		t.Fatal("expected error for bad version, got nil")
	}
}

func TestParseDeltaHeader_TooSmall(t *testing.T) {
	// Smaller than 32 + 4 = 36 bytes, can't even read bitmap_len.
	tiny := make([]byte, 10)
	if _, _, _, err := parseDeltaHeader(tiny); err == nil {
		t.Fatal("expected error for truncated file, got nil")
	}
}

func TestParseDeltaHeader_BitmapCRCMismatch(t *testing.T) {
	b := buildValidEmptyDelta(4096, 8)
	// Find the bitmap_crc position: 36 (after bitmap_len) + bitmap_len bytes.
	bitmapLen := binary.LittleEndian.Uint32(b[32:36])
	crcPos := 36 + int(bitmapLen)
	binary.LittleEndian.PutUint64(b[crcPos:crcPos+8], 0xBADBADBADBADBADB)
	if _, _, _, err := parseDeltaHeader(b); err == nil {
		t.Fatal("expected error for bitmap CRC mismatch, got nil")
	}
}

func TestParseDeltaHeader_BitmapLenOverflows(t *testing.T) {
	b := buildValidEmptyDelta(4096, 8)
	// Claim a bitmap_len much larger than the file actually contains.
	binary.LittleEndian.PutUint32(b[32:36], 1<<30)
	if _, _, _, err := parseDeltaHeader(b); err == nil {
		t.Fatal("expected error for truncated bitmap section, got nil")
	}
}

// buildValidEmptyDelta returns the bytes of a well-formed empty-delta —
// used by parser error tests as a starting point to corrupt.
func buildValidEmptyDelta(blockSize uint32, totalBlocks uint64) []byte {
	bitmapWords := (totalBlocks + 63) / 64
	bitmapLen := uint32(bitmapWords * 8)
	bitmap := make([]byte, bitmapLen)
	bitmapCRC := crc64Bare(0, bitmap)

	var buf bytes.Buffer
	put64 := func(v uint64) {
		var x [8]byte
		binary.LittleEndian.PutUint64(x[:], v)
		buf.Write(x[:])
	}
	put32 := func(v uint32) {
		var x [4]byte
		binary.LittleEndian.PutUint32(x[:], v)
		buf.Write(x[:])
	}
	put64(deltaMagic)
	put32(deltaVersion)
	put32(blockSize)
	put64(totalBlocks)
	put64(0) // dirty_count
	put32(bitmapLen)
	buf.Write(bitmap)
	put64(bitmapCRC)
	put64(0) // data_crc
	return buf.Bytes()
}
