// Presence side-car format. A layered diff overlay (mem.diff) pairs with a
// `<mem>.presence` file: an explicit bitmap of which pages the overlay
// provides, written by the Firecracker fork at snapshot save. The overlay's
// extent map encodes the same fact (written extent = dirty, hole = clean) but
// file transfers don't reliably preserve extents — a copy that materializes
// holes or punches holes through written zero pages silently changes what a
// restore would serve. The side-car survives any byte-preserving transfer.
//
// This file is the repo's single source of truth for the on-disk layout:
// magic, page_size (u64 LE), npages (u64 LE), bitmap words (u64 LE each),
// trailing CRC-64 over all preceding bytes. It must stay bit-compatible with
// the Firecracker fork's encoder; TestCRC64MatchesSnapshotter and the decode
// tests pin that. A 0-byte side-car is the torn-save sentinel; a 1-byte 0x55
// side-car marks a memory file whose save could not derive presence.
package presence

import (
	"encoding/binary"
	"fmt"
	"hash/crc64"
	"os"
	"path/filepath"
)

const (
	presenceMagic = "FCPRSNC1"
	// presenceHeaderLen is magic + page_size (u64 LE) + npages (u64 LE).
	presenceHeaderLen = 24
	// Underivable is the 1-byte side-car content marking a memory
	// file whose save could not derive a presence bitmap.
	Underivable byte = 0x55
)

// presenceCRCTable is the Jones polynomial (0xad93d23594c935a9) in the
// bit-reversed form stdlib's reflected implementation expects.
var presenceCRCTable = crc64.MakeTable(0x95ac9329ac4bc9b5)

// presenceCRC computes the zero-init/zero-xorout CRC-64 variant the
// snapshotting side writes. stdlib bakes in all-ones init and xorout; seeding
// Update with ^0 cancels both inversions.
func presenceCRC(data []byte) uint64 {
	return ^crc64.Update(^uint64(0), presenceCRCTable, data)
}

// SidecarPath is where Firecracker persists the overlay's
// page-presence bitmap. It pairs with the mem file: transfers must copy the
// two together and deletion must remove both — a stale bitmap next to a
// future same-size overlay passes every restore-side check and silently
// mis-layers pages.
func SidecarPath(memPath string) string { return memPath + ".presence" }

// Bitmap is a decoded presence side-car.
type Bitmap struct {
	PageSize uint64
	NPages   uint64
	Bits     []uint64
}

// IsSet reports whether page i is provided by the overlay.
func (p Bitmap) IsSet(i int) bool {
	w := i >> 6
	return w < len(p.Bits) && p.Bits[w]&(1<<(uint(i)&63)) != 0
}

// Encode serializes a presence bitmap in the on-disk layout.
func Encode(pageSize, npages uint64, bits []uint64) []byte {
	b := make([]byte, 0, presenceHeaderLen+len(bits)*8+8)
	b = append(b, presenceMagic...)
	b = binary.LittleEndian.AppendUint64(b, pageSize)
	b = binary.LittleEndian.AppendUint64(b, npages)
	for _, w := range bits {
		b = binary.LittleEndian.AppendUint64(b, w)
	}
	return binary.LittleEndian.AppendUint64(b, presenceCRC(b))
}

// Read reads and validates `<memPath>.presence`. The sentinel
// contents get distinct errors ("torn snapshot save", "un-layerable") so
// callers and operators can tell the three failure classes apart; a missing
// file surfaces as the underlying os.IsNotExist error.
func Read(memPath string) (Bitmap, error) {
	path := SidecarPath(memPath)
	b, err := os.ReadFile(path)
	if err != nil {
		return Bitmap{}, err
	}
	switch {
	case len(b) == 0:
		return Bitmap{}, fmt.Errorf("%s: empty (torn snapshot save)", path)
	case len(b) == 1 && b[0] == Underivable:
		return Bitmap{}, fmt.Errorf("%s: marked un-layerable by its save", path)
	}
	if len(b) < presenceHeaderLen+8 || string(b[:8]) != presenceMagic {
		return Bitmap{}, fmt.Errorf("%s: unrecognized header", path)
	}
	payload, trailer := b[:len(b)-8], b[len(b)-8:]
	if got, want := presenceCRC(payload), binary.LittleEndian.Uint64(trailer); got != want {
		return Bitmap{}, fmt.Errorf("%s: checksum mismatch (computed %#x, stored %#x)", path, got, want)
	}
	p := Bitmap{
		PageSize: binary.LittleEndian.Uint64(b[8:16]),
		NPages:   binary.LittleEndian.Uint64(b[16:24]),
	}
	words := (p.NPages + 63) / 64
	if uint64(len(b)) != presenceHeaderLen+words*8+8 {
		return Bitmap{}, fmt.Errorf("%s: %d bytes, want %d for %d pages",
			path, len(b), presenceHeaderLen+words*8+8, p.NPages)
	}
	p.Bits = make([]uint64, words)
	for i := range p.Bits {
		p.Bits[i] = binary.LittleEndian.Uint64(b[presenceHeaderLen+i*8:])
	}
	return p, nil
}

// writeSidecarTemp writes the encoded side-car to `<dst>.tmp`, fsynced, and
// returns the temp path. The caller renames it into place (plainly or with
// RENAME_NOREPLACE) and fsyncs the directory, removing the temp on failure.
func writeSidecarTemp(dst string, pageSize, npages uint64, bits []uint64) (tmp string, err error) {
	if uint64(len(bits)) != (npages+63)/64 {
		return "", fmt.Errorf("presence bitmap has %d words, want %d for %d pages", len(bits), (npages+63)/64, npages)
	}
	tmp = dst + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err = f.Write(Encode(pageSize, npages, bits)); err != nil {
		return "", err
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	return tmp, nil
}

// syncDir fsyncs the directory containing path, making a just-renamed dirent
// durable.
func syncDir(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// Write atomically writes `<memPath>.presence`: encode to a temp file, fsync,
// rename over the destination, fsync the directory. Unlike the
// Firecracker-side writer (whose seccomp allowlist has no rename), a torn
// write here can never leave a partial side-car — the reader sees the old
// file or the new one. Replaces an existing side-car; writers that must NOT
// replace one (the convergence sweep) use WriteIfAbsent.
func Write(memPath string, pageSize, npages uint64, bits []uint64) error {
	dst := SidecarPath(memPath)
	tmp, err := writeSidecarTemp(dst, pageSize, npages, bits)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(dst)
}
