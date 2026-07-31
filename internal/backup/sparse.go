package backup

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
