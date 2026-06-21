// Package start defines the resolved "start command" contract shared between
// the control plane (which resolves an image's runtime config + caller
// overrides into a concrete command) and boxd (which supervises that command
// inside the guest). It is intentionally dependency-light — boxd links it into
// the guest agent, so it must not pull in heavy packages (no OCI/registry,
// no DB). The resolution logic lives in resolve.go; the on-wire/baked types
// live here.
package start

// RestartPolicy controls whether boxd relaunches a supervised start command
// after it exits. Mirrors the subset of Docker restart policies we support.
type RestartPolicy string

const (
	// RestartNo never relaunches the command after it exits.
	RestartNo RestartPolicy = "no"
	// RestartOnFailure relaunches only on non-zero exit (with backoff).
	RestartOnFailure RestartPolicy = "on-failure"
	// RestartAlways relaunches on any exit (with backoff).
	RestartAlways RestartPolicy = "always"
)

// DefaultRestartPolicy is applied when a Spec leaves Restart empty. on-failure
// is the safe default: a clean exit (status 0) is treated as "the agent's work
// is done", while a crash is retried.
const DefaultRestartPolicy = RestartOnFailure

// Normalize returns a known RestartPolicy, falling back to DefaultRestartPolicy
// for empty or unrecognized values.
func (p RestartPolicy) Normalize() RestartPolicy {
	switch p {
	case RestartNo, RestartOnFailure, RestartAlways:
		return p
	default:
		return DefaultRestartPolicy
	}
}

// Spec is the fully-resolved start command. It is baked into a sandbox rootfs
// at StartSpecPath and read by boxd on boot, and is also accepted live via
// boxd's POST /start. It is the contract between the resolver and the
// supervisor — Resolve produces it; boxd consumes it.
type Spec struct {
	// Argv is the command + arguments to exec. Empty Argv means "nothing to
	// start" (a base template with no runnable entrypoint) — boxd idles.
	Argv []string `json:"argv,omitempty"`

	// Env is the resolved environment for the process as KEY→VALUE. boxd
	// applies these on top of the guest's base environment.
	Env map[string]string `json:"env,omitempty"`

	// User is the user to run as ("uid", "uid:gid", or a name). Empty = root.
	User string `json:"user,omitempty"`

	// WorkingDir is the directory to run in. Empty = "/".
	WorkingDir string `json:"working_dir,omitempty"`

	// Restart is the relaunch policy. Empty is treated as DefaultRestartPolicy.
	Restart RestartPolicy `json:"restart,omitempty"`

	// Ready is an optional readiness probe command/HTTP path used to gate
	// "agent is up". Empty means "consider ready once the process is spawned".
	Ready string `json:"ready,omitempty"`
}

// IsRunnable reports whether the spec has a command to run.
func (s Spec) IsRunnable() bool { return len(s.Argv) > 0 }

// StartSpecPath is the in-rootfs location boxd reads the baked start spec from
// on cold boot. Chosen under /etc so it survives snapshot/restore and is
// outside any user working directory.
const StartSpecPath = "/etc/superserve/start.json"

// Image holds the subset of an OCI image's runtime config relevant to start
// resolution. It deliberately mirrors (but does not import) the builder's
// ImageDefaults so this package stays free of registry dependencies; callers
// convert builder.ImageDefaults → start.Image at the boundary.
type Image struct {
	Entrypoint []string
	Cmd        []string
	Env        map[string]string
	WorkingDir string
	User       string
}

// Overrides are caller-supplied values that take precedence over the image's
// own config during Resolve. Zero-valued fields fall through to the image.
type Overrides struct {
	// Command, when non-empty, replaces the image's Entrypoint+Cmd entirely,
	// matching `docker run IMAGE CMD...`. Empty leaves the image command.
	Command []string

	// BuildEnv is environment contributed by template build steps; it layers
	// over the image env. SandboxEnv (request-time) layers over both.
	BuildEnv   map[string]string
	SandboxEnv map[string]string

	// User / WorkingDir override the image values when non-empty.
	User       string
	WorkingDir string

	// Restart / Ready set the supervision policy and readiness probe.
	Restart RestartPolicy
	Ready   string
}
