package backup

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

// TemplateRuntime preserves the exact paths embedded in Firecracker state.
// The manifest and durable outbox carry this alongside the hashed build metadata.
type TemplateRuntime struct {
	RootfsPath   string `json:"rootfs_path"`
	SnapshotPath string `json:"snapshot_path"`
	MemPath      string `json:"mem_path"`
	BasePath     string `json:"base_path,omitempty"`
	DeltaPath    string `json:"delta_path,omitempty"`
	SizeBytes    int64  `json:"size_bytes"`
}

type PublicationFile struct {
	Name           string `json:"name"`
	RuntimePath    string `json:"runtime_path"`
	SizeBytes      int64  `json:"size_bytes"`
	AllocatedBytes int64  `json:"allocated_bytes"`
	SHA256         string `json:"sha256"`
	Object         string `json:"object,omitempty"`
}

var publicationHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Object paths may be absent following a deduplicated manifest write. In that
// case the immutable generation manifest, named by the publication, resolves
// each file name to its packing-specific object; never invent an object name.
func ValidateTemplatePublication(r TemplateRuntime, files []PublicationFile) error {
	if r.RootfsPath == "" || r.SnapshotPath == "" || r.MemPath == "" || r.SizeBytes < 0 {
		return fmt.Errorf("incomplete runtime paths")
	}
	paths := map[string]bool{}
	names := map[string]bool{}
	for _, f := range files {
		if f.Name == "" || path.Base(f.Name) != f.Name || names[f.Name] || !path.IsAbs(f.RuntimePath) || path.Clean(f.RuntimePath) != f.RuntimePath || paths[f.RuntimePath] {
			return fmt.Errorf("invalid or duplicate artifact mapping")
		}
		if f.SizeBytes < 0 || f.AllocatedBytes < -1 || !publicationHash.MatchString(f.SHA256) || f.SHA256 == strings.Repeat("0", 64) {
			return fmt.Errorf("invalid artifact integrity")
		}
		names[f.Name] = true
		paths[f.RuntimePath] = true
	}
	for _, p := range []string{r.RootfsPath, r.SnapshotPath, r.MemPath, r.BasePath, r.DeltaPath} {
		if p != "" && !paths[p] {
			return fmt.Errorf("runtime path is absent from verified manifest: %s", p)
		}
	}
	if !names["build.meta.json"] {
		return fmt.Errorf("build metadata is absent from verified manifest")
	}
	return nil
}
