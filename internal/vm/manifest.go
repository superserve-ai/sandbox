package vm

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
)

// ManifestEntry describes one durable artifact file finalized by a pause:
// its identity (logical name + host path), integrity (sha256 + size), and,
// for overlay files, the base file the artifact depends on to be restorable.
type ManifestEntry struct {
	FileName  string
	Path      string
	SizeBytes int64
	SHA256    string
	BasePath  string
}

// hashFile streams path through sha256, returning the lowercase hex digest
// and the byte count hashed.
func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, bufio.NewReaderSize(f, 1<<20))
	if err != nil {
		return "", 0, fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// collectPauseManifest hashes a pause's durable artifacts: the disk state
// (what the backup tier uploads) plus vmstate.snap (small, cheap local
// integrity). Memory files are deliberately absent: they never leave the
// host, and hashing multi-GiB mem images would stretch the pause RPC for
// no durability gain. A file that fails to hash is skipped with a warning
// rather than failing the pause — the snapshot artifacts are valid either
// way, and coverage monitoring surfaces the missing entry downstream.
func collectPauseManifest(snapshotPath, diskPath, diskBasePath string, log zerolog.Logger) []ManifestEntry {
	start := time.Now()
	entries := make([]ManifestEntry, 0, 2)
	add := func(name, path, basePath string) {
		if path == "" {
			return
		}
		sum, size, err := hashFile(path)
		if err != nil {
			log.Warn().Err(err).Str("path", path).Msg("pause manifest: hash failed, entry skipped")
			return
		}
		entries = append(entries, ManifestEntry{
			FileName:  name,
			Path:      path,
			SizeBytes: size,
			SHA256:    sum,
			BasePath:  basePath,
		})
	}
	add("vmstate.snap", snapshotPath, "")
	add("rootfs.ext4", diskPath, diskBasePath)
	log.Info().
		Int("files", len(entries)).
		Int64("manifest_hash_ms", time.Since(start).Milliseconds()).
		Msg("pause manifest computed")
	return entries
}
