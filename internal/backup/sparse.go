package backup

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

// ErrTruncatedSource reports a source file that ended before its recorded
// extents were fully read: a newer pause rewrote it mid-stream.
var ErrTruncatedSource = errors.New("backup source truncated during read")

// PackFingerprint identifies a specific physical packing (extent table +
// apparent size). Artifact object names embed it so an object can only
// ever dedupe against a byte-identical packing: a file whose apparent
// content is unchanged but whose extents differ (a guest allocating
// blocks with zero writes) maps to a different object, and a manifest can
// never describe an object packed with a different table.
func PackFingerprint(extents []Extent, apparent int64) string {
	h := sha256.New()
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(apparent))
	h.Write(buf[:])
	for _, e := range extents {
		binary.BigEndian.PutUint64(buf[:], uint64(e.Offset))
		h.Write(buf[:])
		binary.BigEndian.PutUint64(buf[:], uint64(e.Length))
		h.Write(buf[:])
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// Extent is one contiguous run of data bytes inside a (possibly sparse)
// file: Offset is the position in the apparent file, Length the data run.
// The extent table for a packed artifact travels in the generation manifest
// so restore can rebuild the sparse file exactly.
type Extent struct {
	Offset int64 `json:"offset"`
	Length int64 `json:"length"`
}

// PackedSize is the byte count a packed upload of these extents moves.
func PackedSize(extents []Extent) int64 {
	var total int64
	for _, e := range extents {
		total += e.Length
	}
	return total
}
