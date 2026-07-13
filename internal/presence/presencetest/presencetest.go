// Package presencetest provides test fixtures shared by the presence format
// tests and vmd's sweep tests.
package presencetest

import (
	"os"
	"testing"
)

// WriteSparseOverlay lays out a file the way a diff dump does: written extents
// for provided pages (zeros included), holes for the rest. The final Sync
// matters: SEEK_DATA over unsynced delayed-allocation extents can misreport on
// some filesystems, which is exactly the class of flake a presence test must
// not have.
func WriteSparseOverlay(t *testing.T, path string, pageSize, npages int, dataPages map[int]byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(int64(npages * pageSize)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, pageSize)
	for pg, b := range dataPages {
		for i := range buf {
			buf[i] = b
		}
		if _, err := f.WriteAt(buf, int64(pg*pageSize)); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
}
