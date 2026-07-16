//go:build !linux

package vm

func savedSnapshotExtentAccountingSupported() bool { return false }

// Non-Linux builds are development-only. They retain allocated-block
// accounting so unit helpers remain portable; production capability probing
// requires Linux FIEMAP semantics.
func exclusiveFileBytes(path string) (int64, error) {
	return allocatedFileBytes(path)
}
