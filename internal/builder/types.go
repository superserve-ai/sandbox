// Package builder produces Firecracker-bootable rootfs.ext4 files from a
// user-supplied BuildSpec. It does NOT boot Firecracker — that lives in
// internal/vm. The builder's job is:
//
//  1. Resolve an OCI image reference to a digest
//  2. Pull layers and flatten them to a scratch directory
//  3. Inject the boxd guest agent so the resulting VM runs boxd on boot
//  4. Emit rootfs.ext4 at a caller-supplied path
//
// Build steps (RUN / COPY / ENV / WORKDIR) are NOT executed here — those run
// inside a booted Firecracker VM by the VM manager (Day 7). This package only
// produces the base rootfs on top of which the build VM boots.
package builder

// BuildSpec mirrors the canonical JSON shape persisted in template.build_spec.
// Kept handler-package-independent so internal/builder can be used by both
// the HTTP handlers (for validation) and the vmd-side build pipeline.
type BuildSpec struct {
	// From is the OCI image reference to start from (e.g. "python:3.11",
	// "ghcr.io/org/image:tag"). Tag refs are resolved to digests at build
	// time and the digest is recorded for reproducibility.
	From string `json:"from"`

	// Steps are executed by the VM manager inside a booted build VM via boxd,
	// not by this package. Persisted here so the builder can hash the spec
	// for idempotent submit detection.
	Steps []BuildStep `json:"steps,omitempty"`

	// StartCmd / ReadyCmd are run by the VM manager at the end of the build,
	// also not by this package. Included for spec integrity.
	StartCmd string `json:"start_cmd,omitempty"`
	ReadyCmd string `json:"ready_cmd,omitempty"`
}

// BuildStep is a single tagged-union entry. Exactly one of the fields is
// set (enforced at spec validation time in the HTTP handler).
type BuildStep struct {
	Run     *string      `json:"run,omitempty"`
	Copy    *CopyOp      `json:"copy,omitempty"`
	Env     *EnvOp       `json:"env,omitempty"`
	Workdir *string      `json:"workdir,omitempty"`
}

type CopyOp struct {
	Src string `json:"src"` // base64-encoded tar; capped at 1 MiB
	Dst string `json:"dst"`
}

type EnvOp struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// BuildRootfsResult is the output of producing a rootfs.ext4 from a BuildSpec.
type BuildRootfsResult struct {
	// RootfsPath is the absolute path to the produced ext4 image.
	RootfsPath string

	// ResolvedDigest is the sha256 digest the base image reference resolved
	// to at build time, e.g. "sha256:abc123...". Stored on template_build for
	// reproducibility and future cache keys.
	ResolvedDigest string

	// SizeBytes is the on-disk size of the produced ext4 file.
	SizeBytes int64
}

// Config is the injectable dependency bundle used by Builder. Callers
// provide paths / limits; the builder stays stateless otherwise.
type Config struct {
	// BoxdBinaryPath is the host-side path to the boxd binary injected into
	// every template rootfs. Required.
	BoxdBinaryPath string

	// Platform restricts which OCI platforms are acceptable. Defaults to
	// linux/amd64 when zero.
	PlatformOS   string
	PlatformArch string

	// MaxUncompressedSizeBytes is a safety cap on the flattened filesystem
	// before mkfs.ext4 runs. 0 means "no cap".
	MaxUncompressedSizeBytes int64
}

// ApplyDefaults fills in zero-valued fields with sensible defaults.
func (c *Config) ApplyDefaults() {
	if c.PlatformOS == "" {
		c.PlatformOS = "linux"
	}
	if c.PlatformArch == "" {
		c.PlatformArch = "amd64"
	}
}
