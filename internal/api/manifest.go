package api

import (
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// pauseManifestFiles is the complete artifact set a pause is expected to
// hash. A manifest missing any of these is partial: usable for per-file
// verification, but not a trustworthy total for snapshot.size_bytes.
var pauseManifestFiles = []string{"vmstate.snap", "rootfs.ext4"}

// applyManifest flattens a pause's manifest entries into FinalizePause's
// array parameters, so the manifest is replaced in the same statement that
// finalizes the pause. That statement's status guard is what makes stale
// writes impossible: a finalize landing after another pause has already
// finalized matches zero rows and writes nothing, manifest included. It
// also sets SizeBytes from the manifest when the set is complete; partial
// manifests pass 0 and the query keeps the previously recorded size.
func applyManifest(p *db.FinalizePauseParams, manifest []vmdclient.ManifestEntry) {
	for _, e := range manifest {
		p.ManifestFileNames = append(p.ManifestFileNames, e.FileName)
		p.ManifestPaths = append(p.ManifestPaths, e.Path)
		p.ManifestSizes = append(p.ManifestSizes, e.SizeBytes)
		p.ManifestDigests = append(p.ManifestDigests, e.SHA256)
		p.ManifestBasePaths = append(p.ManifestBasePaths, e.BasePath)
	}
	p.SizeBytes = manifestCompleteBytes(manifest)
}

// manifestCompleteBytes sums entry sizes only when the manifest covers the
// full expected pause set. A partial manifest returns 0 so FinalizePause
// keeps the previously recorded size (its upsert ignores non-positive
// sizes) instead of publishing a partial sum as the snapshot's footprint.
func manifestCompleteBytes(manifest []vmdclient.ManifestEntry) int64 {
	var total int64
	seen := make(map[string]bool, len(manifest))
	for _, e := range manifest {
		seen[e.FileName] = true
		total += e.SizeBytes
	}
	for _, name := range pauseManifestFiles {
		if !seen[name] {
			return 0
		}
	}
	return total
}
