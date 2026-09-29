//go:build !linux

package vm

import (
	"fmt"
	"github.com/superserve-ai/sandbox/internal/retainedstorage"
	"os"
	"reflect"
)

func sameRetainedFileMetadata(before, after any) bool {
	return reflect.DeepEqual(before, after)
}

func retainedFileExtents(_ *os.File, _ int) ([]retainedstorage.Extent, string, error) {
	return nil, "", fmt.Errorf("physical extent inventory requires Linux")
}
