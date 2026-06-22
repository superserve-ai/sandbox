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
	Run     *string `json:"run,omitempty"`
	Env     *EnvOp  `json:"env,omitempty"`
	Workdir *string `json:"workdir,omitempty"`
	User    *UserOp `json:"user,omitempty"`
}

type EnvOp struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// UserOp switches the user subsequent steps execute as, and the default
// user that sandboxes created from the template use for exec. If the user
// does not already exist inside the image, it is created with a disabled
// password. When Sudo is true, the user is granted passwordless sudo.
type UserOp struct {
	Name string `json:"name"`
	Sudo bool   `json:"sudo,omitempty"`
}

// ImageDefaults captures the base OCI image's runtime configuration — the
// information a container runtime (Docker/containerd) uses to decide what to
// run and how. We read this from the image config during pull and persist it
// so a sandbox can honor the image's own ENTRYPOINT/CMD/env/user instead of
// requiring the caller to hand-author a template start command.
//
// All fields are optional: a base image may set none of them (e.g. an image
// built purely to be a foundation for RUN steps).
type ImageDefaults struct {
	// Entrypoint is the image's ENTRYPOINT in exec form. Combined with Cmd to
	// form the default argv (see the precedence rules in package start).
	Entrypoint []string `json:"entrypoint,omitempty"`

	// Cmd is the image's CMD in exec form — default arguments appended to
	// Entrypoint, or the full command when Entrypoint is empty.
	Cmd []string `json:"cmd,omitempty"`

	// Env is the image's environment, parsed from the "KEY=VALUE" form the OCI
	// config uses into a map for easy merging with build- and sandbox-level env.
	Env map[string]string `json:"env,omitempty"`

	// WorkingDir is the image's WORKDIR; the directory the start command runs in.
	WorkingDir string `json:"working_dir,omitempty"`

	// User is the image's USER ("uid", "uid:gid", or a name). The start command
	// runs as this user unless overridden.
	User string `json:"user,omitempty"`
}

// IsZero reports whether no image defaults were captured (an image that
// specifies no entrypoint, cmd, env, workdir, or user).
func (d ImageDefaults) IsZero() bool {
	return len(d.Entrypoint) == 0 && len(d.Cmd) == 0 && len(d.Env) == 0 &&
		d.WorkingDir == "" && d.User == ""
}

// BuildRootfsResult is the output of producing a rootfs.ext4 from a BuildSpec.
type BuildRootfsResult struct {
	// RootfsPath is the absolute path to the produced ext4 image.
	RootfsPath string

	// ResolvedDigest is the sha256 digest the base image reference resolved
	// to at build time, e.g. "sha256:abc123...". Stored on template_build for
	// reproducibility and future cache keys.
	ResolvedDigest string

	// ImageDefaults is the base image's runtime configuration captured during
	// pull. Persisted on the template so sandboxes can run the image's own
	// start command without manual authoring. May be the zero value.
	ImageDefaults ImageDefaults

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

	// Path to the secretsproxy CA cert. Empty disables CA install.
	ProxyCACertPath string
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
