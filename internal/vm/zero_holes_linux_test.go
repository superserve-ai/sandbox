package vm

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// A punched block that held any data would hand every sandbox from the
// template zeros in its place.
func TestPunchZeroBlocksKeepsContentsAndPunchesOnlyWholeZeroBlocks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mem.snap")
	// Block 0 zero, block 1 one non-zero byte at its end, block 2 zero, then a
	// partial zero tail that is not a whole block.
	want := make([]byte, 3*zeroHoleBlock+4096)
	want[2*zeroHoleBlock-1] = 0x5a
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}

	punched, err := PunchZeroBlocks(path)
	if err != nil {
		t.Fatal(err)
	}
	if punched != 2*zeroHoleBlock {
		t.Fatalf("punched %d bytes, want the two zero blocks (%d)", punched, 2*zeroHoleBlock)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("punching changed the file's contents")
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	data, err := unix.Seek(int(f.Fd()), 0, unix.SEEK_DATA)
	if err != nil {
		t.Fatal(err)
	}
	if data != zeroHoleBlock {
		t.Fatalf("first data at %d, want block 0 punched and data from %d", data, zeroHoleBlock)
	}
}
