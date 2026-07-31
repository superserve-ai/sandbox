package vm

import (
	"context"
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

const (
	// hashSafetyMargin is reserved out of the pause RPC's remaining deadline
	// so the response always reaches the control plane even when hashing is
	// cut short: a paused VM whose pause "times out" gets retried against an
	// already-stopped unit, which is the worse failure.
	hashSafetyMargin = 3 * time.Second
	// hashBudgetCap bounds hashing when the caller has no deadline.
	hashBudgetCap = 60 * time.Second
)

// hashFile streams path through sha256, returning the lowercase hex digest
// and the byte count hashed. Cancellation is checked between reads so a
// multi-GiB image cannot pin the pause path past its budget.
func hashFile(ctx context.Context, path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 4<<20)
	var n int64
	for {
		if err := ctx.Err(); err != nil {
			return "", 0, fmt.Errorf("hash %s: %w", path, err)
		}
		r, rerr := f.Read(buf)
		if r > 0 {
			h.Write(buf[:r])
			n += int64(r)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return "", 0, fmt.Errorf("hash %s: %w", path, rerr)
		}
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// collectPauseManifest hashes a pause's durable artifacts: the disk state
// (what the backup tier uploads) plus vmstate.snap (small, cheap local
// integrity). Memory files are deliberately absent: they never leave the
// host, and hashing multi-GiB mem images would stretch the pause RPC for
// no durability gain.
//
// Hashing runs under its own budget: the caller's remaining deadline minus
// a safety margin (so the RPC response always gets out), capped when there
// is no deadline. When the deadline leaves no usable budget, hashing is
// skipped entirely rather than stretched past the RPC cap; the finalize
// clears the snapshot's previous manifest rows, so a skipped hash yields
// "no integrity data" (surfaced by coverage monitoring), never stale
// hashes. Detached from the caller's cancellation: a paused VM should get
// its integrity record even if the client gave up. A file that misses the
// budget or fails to hash is likewise skipped with a warning rather than
// failing the pause; the control plane never publishes a partial total as
// the snapshot size.
func collectPauseManifest(ctx context.Context, snapshotPath, diskPath, diskBasePath string, log zerolog.Logger) []ManifestEntry {
	budget := hashBudgetCap
	if dl, ok := ctx.Deadline(); ok {
		rem := time.Until(dl) - hashSafetyMargin
		if rem <= 0 {
			log.Warn().Msg("pause manifest: no hashing budget left before RPC deadline, skipping")
			return nil
		}
		if rem < budget {
			budget = rem
		}
	}
	hctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), budget)
	defer cancel()

	start := time.Now()
	entries := make([]ManifestEntry, 0, 2)
	add := func(name, path, basePath string) {
		if path == "" {
			return
		}
		sum, size, err := hashFile(hctx, path)
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
	// vmstate first: tiny and guaranteed inside any budget, so even a
	// budget-exhausted pause records something verifiable.
	add("vmstate.snap", snapshotPath, "")
	add("rootfs.ext4", diskPath, diskBasePath)
	log.Info().
		Int("files", len(entries)).
		Int64("manifest_hash_ms", time.Since(start).Milliseconds()).
		Dur("budget", budget).
		Msg("pause manifest computed")
	return entries
}
