// Package templatedelta flattens a firecracker rootfs.delta into its base
// image at template-build time, so sandboxes restored from this template
// don't have to replay the delta into a per-VM overlay on every create.
package templatedelta

import (
	"encoding/binary"
	"fmt"
	"hash/crc64"
	"os"
)

// rootfs.delta binary format (matches firecracker fork's
// vmm/src/devices/virtio/block/virtio/io/delta.rs):
//
//   header (32 bytes):
//     magic        u64 LE = 0x4F564C5944454C54 ("OVLYDELT")
//     version      u32 LE = 1
//     block_size   u32 LE
//     total_blocks u64 LE
//     dirty_count  u64 LE
//   bitmap section:
//     bitmap_len   u32 LE
//     bitmap_data  [u8; bitmap_len]
//     bitmap_crc   u64 LE   (crc64 of bitmap_data, init=0)
//   data section:
//     for each dirty block in ascending index order: [u8; block_size]
//     data_crc     u64 LE   (running crc64 over all block bytes, init=0)
//
const (
	deltaMagic   uint64 = 0x4F564C5944454C54
	deltaVersion uint32 = 1
)

var crc64Tab = crc64.MakeTable(crc64.ISO)

// crc64Bare is CRC-64-ISO with no seed/result complement. Matches the Rust
// crc64 v2.0.0 crate; stdlib crc64.Update can't be used as-is because it
// complements at start and end.
func crc64Bare(seed uint64, data []byte) uint64 {
	crc := seed
	for _, b := range data {
		crc = crc64Tab[byte(crc)^b] ^ (crc >> 8)
	}
	return crc
}

// FlattenInto applies every dirty block from `deltaPath` to `basePath` and
// rewrites `deltaPath` to an empty-form delta (same header, dirty_count=0,
// all-zero bitmap, no data section). After this, sandboxes restored from
// this template start with an empty overlay — reads route to the
// now-flattened base via the trivially-clean dirty bitmap, eliminating the
// per-sandbox apply_delta write pass.
//
// Ordering: base is written and fsynced before the delta is rewritten. A
// crash between the two leaves the template functionally correct (the
// still-non-empty delta re-applies blocks that already exist in base on
// the next restore — wasteful but not corrupt).
func FlattenInto(basePath, deltaPath string) error {
	deltaBytes, err := os.ReadFile(deltaPath)
	if err != nil {
		return fmt.Errorf("read delta: %w", err)
	}

	hdr, bitmapBytes, dataStart, err := parseDeltaHeader(deltaBytes)
	if err != nil {
		return err
	}

	if err := applyDeltaToBase(basePath, deltaBytes, dataStart, bitmapBytes, hdr); err != nil {
		return err
	}

	return writeEmptyDelta(deltaPath, hdr.blockSize, hdr.totalBlocks, uint32(len(bitmapBytes)))
}

type deltaHeader struct {
	blockSize   uint32
	totalBlocks uint64
	dirtyCount  uint64
}

func parseDeltaHeader(b []byte) (deltaHeader, []byte, int, error) {
	if len(b) < 32+4 {
		return deltaHeader{}, nil, 0, fmt.Errorf("delta too small: %d bytes", len(b))
	}
	magic := binary.LittleEndian.Uint64(b[0:8])
	if magic != deltaMagic {
		return deltaHeader{}, nil, 0, fmt.Errorf("bad magic: 0x%016X (expected 0x%016X)", magic, deltaMagic)
	}
	version := binary.LittleEndian.Uint32(b[8:12])
	if version != deltaVersion {
		return deltaHeader{}, nil, 0, fmt.Errorf("unsupported delta version: %d", version)
	}
	hdr := deltaHeader{
		blockSize:   binary.LittleEndian.Uint32(b[12:16]),
		totalBlocks: binary.LittleEndian.Uint64(b[16:24]),
		dirtyCount:  binary.LittleEndian.Uint64(b[24:32]),
	}
	bitmapLen := binary.LittleEndian.Uint32(b[32:36])
	bitmapEnd := 36 + int(bitmapLen)
	if bitmapEnd+8 > len(b) {
		return deltaHeader{}, nil, 0, fmt.Errorf("delta truncated: bitmap claims %d bytes but file is %d", bitmapLen, len(b))
	}
	bitmapBytes := b[36:bitmapEnd]
	// CRC not validated: firecracker just wrote this file.
	return hdr, bitmapBytes, bitmapEnd + 8, nil
}

func applyDeltaToBase(basePath string, deltaBytes []byte, dataStart int, bitmapBytes []byte, hdr deltaHeader) (retErr error) {
	base, err := os.OpenFile(basePath, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open base: %w", err)
	}
	// Surface close errors only if nothing earlier already failed.
	defer func() {
		if cerr := base.Close(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("close base: %w", cerr)
		}
	}()

	var applied uint64
	pos := dataStart
	bs := int(hdr.blockSize)

	// bitvec (Lsb0 default) packs bit i at byte i/8, bit i%8 of that byte.
	// Iterate in ascending bit-index order to match the data section's
	// block ordering (apply_delta writes blocks in bitmap.iter_dirty()
	// order, which is ascending).
	for i := uint64(0); i < hdr.totalBlocks; i++ {
		byteIdx := int(i / 8)
		bitInByte := uint(i % 8)
		if byteIdx >= len(bitmapBytes) || bitmapBytes[byteIdx]&(1<<bitInByte) == 0 {
			continue
		}
		if pos+bs > len(deltaBytes)-8 {
			return fmt.Errorf("data section truncated at block %d", i)
		}
		block := deltaBytes[pos : pos+bs]
		pos += bs
		offset := int64(i) * int64(hdr.blockSize)
		if _, err := base.WriteAt(block, offset); err != nil {
			return fmt.Errorf("pwrite base at offset %d: %w", offset, err)
		}
		applied++
	}

	if applied != hdr.dirtyCount {
		return fmt.Errorf("applied %d blocks, header claims %d", applied, hdr.dirtyCount)
	}

	if err := base.Sync(); err != nil {
		return fmt.Errorf("fsync base: %w", err)
	}
	return nil
}

// writeEmptyDelta replaces `path` with a delta whose header is preserved
// but dirty_count is 0 and the bitmap is all zeros. tmp-file + rename so
// a crash mid-write can't leave a torn delta on disk.
func writeEmptyDelta(path string, blockSize uint32, totalBlocks uint64, bitmapLen uint32) error {
	bitmap := make([]byte, bitmapLen)
	bitmapCRC := crc64Bare(0, bitmap)

	buf := make([]byte, 0, 32+4+int(bitmapLen)+8+8)
	var u32 [4]byte
	var u64 [8]byte

	put64 := func(v uint64) {
		binary.LittleEndian.PutUint64(u64[:], v)
		buf = append(buf, u64[:]...)
	}
	put32 := func(v uint32) {
		binary.LittleEndian.PutUint32(u32[:], v)
		buf = append(buf, u32[:]...)
	}

	// Header.
	put64(deltaMagic)
	put32(deltaVersion)
	put32(blockSize)
	put64(totalBlocks)
	put64(0) // dirty_count = 0

	// Bitmap section.
	put32(bitmapLen)
	buf = append(buf, bitmap...)
	put64(bitmapCRC)

	// Data section: zero blocks, data_crc = 0.
	put64(0)

	// Atomic replace.
	tmp := path + ".flatten.tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("create tmp delta: %w", err)
	}
	if _, err := f.Write(buf); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write tmp delta: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("fsync tmp delta: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close tmp delta: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename tmp delta: %w", err)
	}
	return nil
}
