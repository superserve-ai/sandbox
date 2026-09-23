//go:build !linux

package backup

import "os"

// dropPageCache is a no-op off linux; production hosts are linux.
func dropPageCache(*os.File) error { return nil }
