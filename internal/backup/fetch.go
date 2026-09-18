package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrNoBackup reports a sandbox with no completed generation in the bucket.
var ErrNoBackup = errors.New("no completed backup generation")

// Restored locates a restored generation's bootable disk and its base.
type Restored struct {
	Disk       string
	Base       string
	Standalone bool
	Manifest   *GenerationManifest
}

// RestoredDisk reads the completion marker in dir and resolves the rootfs
// and, for an overlay, the shared base beside it.
func RestoredDisk(dir string) (Restored, error) {
	var r Restored
	raw, err := os.ReadFile(filepath.Join(dir, ManifestObject))
	if err != nil {
		return r, fmt.Errorf("not restored")
	}
	r.Manifest = &GenerationManifest{}
	if err := json.Unmarshal(raw, r.Manifest); err != nil {
		return r, fmt.Errorf("restore marker: %w", err)
	}
	for _, f := range r.Manifest.Files {
		if f.Name != "rootfs.ext4" {
			continue
		}
		r.Disk = filepath.Join(dir, f.Name)
		if _, err := os.Stat(r.Disk); err != nil {
			return r, fmt.Errorf("restored without a rootfs")
		}
		if f.BaseSHA256 == "" {
			r.Standalone = true
			return r, nil
		}
		r.Base = filepath.Join(dir, SharedBaseName(f.BaseSHA256))
		if _, err := os.Stat(r.Base); err != nil {
			return r, fmt.Errorf("restored without its base %s", f.BaseSHA256)
		}
		return r, nil
	}
	return r, fmt.Errorf("restore marker lists no rootfs")
}

// FetchNewest restores the sandbox's newest completed generation into
// destDir, which must not exist, and resolves its disk.
func FetchNewest(ctx context.Context, r BlobReader, lister BlobLister, sandboxID, destDir string, progress ProgressFunc) (Restored, error) {
	gens, err := ListGenerations(ctx, lister, sandboxID)
	if err != nil {
		return Restored{}, fmt.Errorf("list generations: %w", err)
	}
	if len(gens) == 0 {
		return Restored{}, ErrNoBackup
	}
	if _, err := RestoreGeneration(ctx, r, sandboxID, gens[0].Generation, destDir, progress); err != nil {
		return Restored{}, err
	}
	return RestoredDisk(destDir)
}
