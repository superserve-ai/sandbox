package vm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/sync/singleflight"

	"github.com/superserve-ai/sandbox/internal/backup"
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
	// BaseStagedPath is the staged snapshot to READ the base from when
	// staging captured one; BasePath remains the recorded identity.
	BaseStagedPath string
	// BaseSHA256 is the base file's content digest. The path alone is not
	// an identity: a base rebuilt or restored with different bytes at the
	// same path changes the effective filesystem under an unchanged
	// overlay, and only the content digest makes that a new generation.
	BaseSHA256 string
}

const (
	// hashSafetyMargin is reserved out of the pause RPC's remaining deadline
	// so the response always reaches the control plane even when hashing is
	// cut short: a paused VM whose pause "times out" gets retried against an
	// already-stopped unit, which is the worse failure.
	hashSafetyMargin = 3 * time.Second
	// hashBudgetCap bounds hashing when the caller has no deadline.
	hashBudgetCap = 60 * time.Second
	// buildHashBudget bounds hashing a finished build's artifact set. Builds
	// are not latency-critical the way pause is, so the budget is generous:
	// it exists to keep a wedged disk from pinning the build worker forever,
	// not to shave seconds off the pause RPC.
	buildHashBudget = 10 * time.Minute
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
	budget, ok := hashBudget(ctx)
	if !ok {
		log.Warn().Msg("pause manifest: no hashing budget left before RPC deadline, skipping")
		return nil
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
		var baseSum string
		if basePath != "" {
			baseSum, err = baseDigest(hctx, basePath)
			if err != nil {
				log.Warn().Err(err).Str("path", basePath).
					Msg("pause manifest: base digest failed, entry skipped")
				return
			}
		}
		entries = append(entries, ManifestEntry{
			FileName:   name,
			Path:       path,
			SizeBytes:  size,
			SHA256:     sum,
			BasePath:   basePath,
			BaseSHA256: baseSum,
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

// hashBudget derives the manifest hashing budget from the caller's
// deadline: the caller's remaining time (minus the response margin) when
// a deadline exists, whether shorter OR longer than the default, and
// hashBudgetCap only when there is none. Clamping every caller to the
// cap would make the async rehash's ten-minute budget unreachable, and a
// disk that hashes in more than the cap could then never complete.
func hashBudget(ctx context.Context) (time.Duration, bool) {
	if dl, ok := ctx.Deadline(); ok {
		rem := time.Until(dl) - hashSafetyMargin
		if rem <= 0 {
			return 0, false
		}
		return rem, true
	}
	return hashBudgetCap, true
}

// baseDigestCache memoizes content digests of overlay base images, keyed
// by path plus stat identity (device, inode, size, mtime). Bases are
// immutable template artifacts shared by many sandboxes, so a multi-GB
// base hashes once per boot instead of once per pause; any change to the
// file's identity misses the cache and rehashes.
var baseDigestCache sync.Map

// baseDigestGroup coalesces concurrent cache misses for the same base
// identity: a batch of overlay sandboxes pausing together against a cold
// base must produce one hash, not one per pause.
var baseDigestGroup singleflight.Group

// baseDigest returns the content digest of a base image, cached. The
// identity is re-checked after hashing: a base swapped mid-hash yields
// an error (and an incomplete manifest, which the retry path owns)
// rather than a digest describing bytes of two different files.
func baseDigest(ctx context.Context, path string) (string, error) {
	key, err := baseIdentity(path)
	if err != nil {
		return "", err
	}
	if v, ok := baseDigestCache.Load(key); ok {
		return v.(string), nil
	}
	// DoChan rather than Do: a joiner must honor its own hash budget. A
	// synchronous pause joining a hash started under the async rehash's
	// ten-minute budget would otherwise block far past the pause RPC
	// deadline. The in-flight hash keeps running for callers that can
	// still use it; this caller just degrades to an incomplete manifest,
	// which the retry path owns.
	ch := baseDigestGroup.DoChan(key, func() (any, error) {
		if v, ok := baseDigestCache.Load(key); ok {
			return v.(string), nil
		}
		hctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pauseRehashBudget)
		defer cancel()
		sum, _, err := hashFile(hctx, path)
		if err != nil {
			return "", err
		}
		after, err := baseIdentity(path)
		if err != nil {
			return "", err
		}
		if after != key {
			return "", fmt.Errorf("base image %s changed while hashing", path)
		}
		baseDigestCache.Store(key, sum)
		return sum, nil
	})
	select {
	case res := <-ch:
		if res.Err != nil {
			return "", res.Err
		}
		return res.Val.(string), nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func baseIdentity(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("base image %s: no stat identity", path)
	}
	// ctime is load-bearing: a timestamp-preserving in-place rewrite can
	// keep the device, inode, size, and restored mtime all identical,
	// but userspace cannot set ctime back, so any content or metadata
	// change is visible there.
	return fmt.Sprintf("%s|%d|%d|%d|%d|%d",
		path, st.Dev, st.Ino, fi.Size(), fi.ModTime().UnixNano(), st.Ctim.Nano()), nil
}

// collectBuildManifest hashes every artifact file in a completed build's
// snapshot directory except build.meta.json, which the caller rewrites with
// these digests afterwards and hashes separately, plus any extraPaths that
// live outside the directory (the overlay base image sits in the run dir
// but is required to restore the template). Detached from the caller's
// cancellation like collectPauseManifest: a build that already produced
// valid artifacts should get its integrity record even if the caller gives
// up during finalize.
//
// complete reports whether EVERY artifact hashed. A file that misses the
// budget or fails to hash is skipped with a warning and flips complete to
// false; callers building a durable generation must not publish a partial
// set (the manifest object's presence means restorable), so they treat
// !complete as "do not enqueue".
func collectBuildManifest(ctx context.Context, snapshotDir string, extraPaths []string, log zerolog.Logger) (entries []ManifestEntry, complete bool) {
	hctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), buildHashBudget)
	defer cancel()

	dirEntries, err := os.ReadDir(snapshotDir)
	if err != nil {
		log.Warn().Err(err).Str("dir", snapshotDir).Msg("build manifest: read artifact dir failed")
		return nil, false
	}
	start := time.Now()
	complete = true
	entries = make([]ManifestEntry, 0, len(dirEntries)+len(extraPaths))
	seen := make(map[string]string, len(dirEntries)+len(extraPaths))
	add := func(name, path string) {
		if prev, dup := seen[name]; dup {
			// Same path twice is the intentional dedupe (a base copied
			// into the snapshot dir); two different files sharing a
			// basename is ambiguity the artifact set must not paper
			// over, since object names are basenames.
			if prev != path {
				log.Warn().Str("name", name).Str("kept", prev).Str("dropped", path).
					Msg("build manifest: basename collision between artifacts")
				complete = false
			}
			return
		}
		seen[name] = path
		sum, size, err := hashFile(hctx, path)
		if err != nil {
			log.Warn().Err(err).Str("path", path).Msg("build manifest: hash failed")
			complete = false
			return
		}
		entries = append(entries, ManifestEntry{
			FileName:  name,
			Path:      path,
			SizeBytes: size,
			SHA256:    sum,
		})
	}
	for _, de := range dirEntries {
		if !de.Type().IsRegular() || de.Name() == buildMetaFilename {
			continue
		}
		// Crash residue and reserved names are not artifacts: a *.tmp is
		// a torn writeBuildDigests replacement that the next stamp will
		// rename away (the enqueued path would dangle), and a file named
		// like the bucket's manifest object would collide with the
		// generation's completion marker and poison the task.
		if strings.HasSuffix(de.Name(), ".tmp") || de.Name() == backup.ManifestObject {
			log.Warn().Str("name", de.Name()).
				Msg("build manifest: skipping non-artifact file")
			continue
		}
		add(de.Name(), filepath.Join(snapshotDir, de.Name()))
	}
	for _, p := range extraPaths {
		if p == "" {
			continue
		}
		add(filepath.Base(p), p)
	}
	log.Info().
		Int("files", len(entries)).
		Bool("complete", complete).
		Int64("manifest_hash_ms", time.Since(start).Milliseconds()).
		Msg("build manifest computed")
	return entries, complete
}
