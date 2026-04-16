package vm

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/builder"
)

// buildStepState tracks state accumulated across a build's steps: env
// variables set by `env` ops and working directory set by `workdir` ops.
// Passed to every subsequent run step.
type buildStepState struct {
	env     map[string]string
	workdir string
}

// stepTimeout is the per-step wall clock cap for build steps. A single
// `apt-get install` or `pip install` can legitimately take a minute or two;
// we cap at 10 minutes so a hung step doesn't wedge the build forever.
// A global build_timeout (30m) in the supervisor is the second line of defense.
const stepTimeout = 10 * time.Minute

// readyProbeTimeout is the total budget for polling ready_cmd until it
// returns exit 0. Matches stepTimeout deliberately — a template whose
// start process takes >10 min to become ready is almost certainly
// misconfigured, not just slow.
const readyProbeTimeout = 10 * time.Minute

// readyProbeInterval is how often we retry the ready_cmd while waiting
// for the start process to come up.
const readyProbeInterval = 2 * time.Second

// executeBuildSteps runs every step in spec.Steps against the build VM at
// vmIP, in order. Returns on first failure (non-zero exit for `run`, decode
// failure for `copy`, etc.) with a wrapped error.
//
// Output streams (stdout/stderr) are forwarded to the build's log buffer
// (via m.appendBuildLog) where gRPC/SSE subscribers pick them up. The same
// data is also logged at INFO for operator-side observability.
func (m *Manager) executeBuildSteps(ctx context.Context, buildVMID, vmIP string, spec builder.BuildSpec, log zerolog.Logger) error {
	state := buildStepState{
		env: map[string]string{
			"PATH":  "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"HOME":  "/root",
			"USER":  "root",
			"TERM":  "xterm",
			"LANG":  "C.UTF-8",
			"SHELL": "/bin/sh",
		},
	}

	for i, step := range spec.Steps {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		stepLog := log.With().Int("step", i+1).Int("total", len(spec.Steps)).Logger()
		stepStart := time.Now()

		// Emit a system event marking the step boundary so log viewers
		// can visually distinguish steps. The text format is stable — the
		// SDK may parse it for UI rendering, so keep it consistent.
		m.appendBuildLog(buildVMID, BuildLogEvent{
			Stream: LogStreamSystem,
			Text:   fmt.Sprintf("step %d/%d", i+1, len(spec.Steps)),
		})

		stepCtx, cancel := context.WithTimeout(ctx, stepTimeout)
		err := m.runBuildStep(stepCtx, buildVMID, vmIP, step, &state, stepLog)
		cancel()

		if err != nil {
			return fmt.Errorf("step %d/%d failed after %s: %w", i+1, len(spec.Steps), time.Since(stepStart).Round(time.Millisecond), err)
		}
		stepLog.Info().Dur("elapsed", time.Since(stepStart).Round(time.Millisecond)).Msg("step complete")
	}
	return nil
}

// runBuildStep dispatches on the step's op field. Exactly one of run / copy /
// env / workdir must be set (enforced at the gRPC boundary; a defensive
// check here catches internal bugs that bypass that boundary).
func (m *Manager) runBuildStep(ctx context.Context, buildVMID, vmIP string, step builder.BuildStep, state *buildStepState, log zerolog.Logger) error {
	switch {
	case step.Run != nil:
		return m.runRunStep(ctx, buildVMID, vmIP, *step.Run, state, log)
	case step.Copy != nil:
		return m.runCopyStep(ctx, buildVMID, vmIP, step.Copy, state, log)
	case step.Env != nil:
		state.env[step.Env.Key] = step.Env.Value
		log.Info().Str("key", step.Env.Key).Msg("env set")
		m.appendBuildLog(buildVMID, BuildLogEvent{
			Stream: LogStreamSystem,
			Text:   fmt.Sprintf("env %s=%s", step.Env.Key, step.Env.Value),
		})
		return nil
	case step.Workdir != nil:
		state.workdir = *step.Workdir
		log.Info().Str("workdir", state.workdir).Msg("workdir set")
		m.appendBuildLog(buildVMID, BuildLogEvent{
			Stream: LogStreamSystem,
			Text:   fmt.Sprintf("workdir %s", state.workdir),
		})
		return nil
	default:
		return fmt.Errorf("build step has no op set")
	}
}

// runRunStep executes a shell command inside the build VM. The command is
// wrapped in /bin/sh -c (via httpExec's default path) so the user can use
// shell features like pipes, redirects, and variable expansion. Exits non-zero
// → step failure.
func (m *Manager) runRunStep(ctx context.Context, buildVMID, vmIP string, cmd string, state *buildStepState, log zerolog.Logger) error {
	log.Info().Str("cmd", truncate(cmd, 256)).Msg("running step")
	m.appendBuildLog(buildVMID, BuildLogEvent{
		Stream: LogStreamSystem,
		Text:   fmt.Sprintf("$ %s", truncate(cmd, 512)),
	})

	opts := &ExecOptions{
		Env:        state.env,
		WorkingDir: state.workdir,
	}

	// Stream output in real time rather than buffering — a long-running
	// `apt-get install` emits hundreds of KB of output, and buffering it
	// all in memory before surfacing hides progress from the log stream.
	var lastExit int32
	err := httpExecStream(ctx, vmIP, cmd, stepTimeout, opts, func(stdout, stderr []byte, exitCode int32, finished bool) {
		if len(stdout) > 0 {
			text := strings.TrimRight(string(stdout), "\n")
			log.Info().Str("stream", "stdout").Str("data", text).Msg("build output")
			m.appendBuildLog(buildVMID, BuildLogEvent{Stream: LogStreamStdout, Text: text})
		}
		if len(stderr) > 0 {
			text := strings.TrimRight(string(stderr), "\n")
			log.Info().Str("stream", "stderr").Str("data", text).Msg("build output")
			m.appendBuildLog(buildVMID, BuildLogEvent{Stream: LogStreamStderr, Text: text})
		}
		if finished {
			lastExit = exitCode
		}
	})
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	if lastExit != 0 {
		return fmt.Errorf("exited with code %d", lastExit)
	}
	return nil
}

// runCopyStep materializes a base64-encoded tar archive at the destination
// path inside the VM. Implementation: pipe the base64 text through the VM's
// own `base64 -d | tar -C <dst> -xf -` as a single shell command.
//
// Why embed the base64 in the command string rather than use boxd's
// SendInput for stdin streaming: (1) simpler — no PID tracking or stream
// coordination; (2) the payload is capped at 1 MiB by API validation, well
// under typical ARG_MAX (~2 MiB on Linux); (3) atomic from boxd's point of
// view — one Start call, one exit code, easy to log.
func (m *Manager) runCopyStep(ctx context.Context, buildVMID, vmIP string, op *builder.CopyOp, state *buildStepState, log zerolog.Logger) error {
	if op.Dst == "" {
		return fmt.Errorf("copy.dst is empty")
	}
	if !isSafeCopyDst(op.Dst) {
		return fmt.Errorf("copy.dst must be absolute and not point at a system path (got %q)", op.Dst)
	}

	log.Info().Str("dst", op.Dst).Int("bytes", len(op.Src)).Msg("copying files")
	m.appendBuildLog(buildVMID, BuildLogEvent{
		Stream: LogStreamSystem,
		Text:   fmt.Sprintf("copy %d bytes → %s", len(op.Src), op.Dst),
	})

	// Base64 alphabet is [A-Za-z0-9+/=] — no shell metacharacters, so
	// single-quoting it is safe.
	shCmd := fmt.Sprintf(
		"mkdir -p %s && printf '%%s' '%s' | base64 -d | tar -C %s -xf -",
		shellQuote(op.Dst), op.Src, shellQuote(op.Dst),
	)
	return m.runRunStep(ctx, buildVMID, vmIP, shCmd, state, log)
}

// isSafeCopyDst returns true when dst is an absolute path that does NOT
// target a known-hazardous system directory. "Hazardous" here means paths
// whose corruption would break the produced snapshot's ability to boot or
// pass health checks. Allowlist would be safer but too restrictive —
// users legitimately copy into /opt, /srv, /var, etc.
func isSafeCopyDst(dst string) bool {
	if !strings.HasPrefix(dst, "/") {
		return false
	}
	// Reject copies into / or directly into known-sensitive system dirs.
	// Sub-paths (e.g. /etc/myapp) are allowed — users need to be able to
	// drop config files. Top-level overwrite is not a legitimate use case.
	forbidden := []string{"/", "/bin", "/sbin", "/boot", "/proc", "/sys", "/dev"}
	for _, f := range forbidden {
		if dst == f {
			return false
		}
	}
	return true
}

// shellQuote wraps s in single quotes and escapes any single quotes in s by
// closing the quote, inserting '\'' (a quoted apostrophe), and reopening.
// Standard POSIX sh idiom for "treat this string literally."
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// runStartCmd launches spec.StartCmd inside the VM without waiting for it
// to exit. The process keeps running when we return; the snapshot captured
// immediately after will freeze it live. That is the whole point — sandboxes
// restored from this template come up with the start process already
// listening, no cold-init time.
//
// Uses a detached context (context.WithoutCancel of the caller's) so that
// when the caller's context is cancelled mid-snapshot, we don't also kill
// the process we just asked to start.
func (m *Manager) runStartCmd(ctx context.Context, buildVMID, vmIP string, spec builder.BuildSpec, log zerolog.Logger) error {
	if spec.StartCmd == "" {
		return nil
	}
	log.Info().Str("cmd", truncate(spec.StartCmd, 256)).Msg("launching start_cmd")
	m.appendBuildLog(buildVMID, BuildLogEvent{
		Stream: LogStreamSystem,
		Text:   fmt.Sprintf("start_cmd: %s", truncate(spec.StartCmd, 256)),
	})

	// Fire-and-forget pattern: call Start() on boxd, read the first
	// StartEvent to confirm the process launched, then abandon the stream.
	// The process itself keeps running inside the VM even after our HTTP
	// connection drops.
	//
	// We can't use httpExecStream here because it waits for the stream to
	// close (i.e. the process to exit), which is exactly the behavior we
	// want to avoid for a long-lived server.
	go func() {
		detachedCtx := context.WithoutCancel(ctx)
		_, _ = httpExec(detachedCtx, vmIP, spec.StartCmd, 0, nil)
	}()

	// Give the exec a moment to actually submit to boxd before returning.
	// Without this, a very fast snapshot call can race the Start RPC and
	// capture a state where the process hasn't been spawned yet.
	select {
	case <-time.After(500 * time.Millisecond):
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// pollReadyCmd runs spec.ReadyCmd every readyProbeInterval and returns nil
// as soon as it exits 0, or an error if readyProbeTimeout elapses. Used to
// block the snapshot until the start process is actually listening /
// serving, so the frozen snapshot is in a useful state for sandboxes that
// restore from it.
//
// Empty ReadyCmd = no wait. Callers should set it whenever StartCmd is set
// and has any nontrivial startup latency; otherwise the snapshot may capture
// a process that hasn't bound its port yet.
func (m *Manager) pollReadyCmd(ctx context.Context, buildVMID, vmIP string, spec builder.BuildSpec, log zerolog.Logger) error {
	if spec.ReadyCmd == "" {
		return nil
	}
	log.Info().Str("cmd", truncate(spec.ReadyCmd, 256)).Msg("polling ready_cmd")
	m.appendBuildLog(buildVMID, BuildLogEvent{
		Stream: LogStreamSystem,
		Text:   fmt.Sprintf("ready_cmd: %s", truncate(spec.ReadyCmd, 256)),
	})

	probeCtx, cancel := context.WithTimeout(ctx, readyProbeTimeout)
	defer cancel()

	probeStart := time.Now()
	attempts := 0
	for {
		attempts++
		if err := probeCtx.Err(); err != nil {
			return fmt.Errorf("ready_cmd did not succeed within %s (%d attempts): %w", readyProbeTimeout, attempts, err)
		}

		// Use a short per-attempt timeout so a probe that blocks on a
		// hung HTTP connection doesn't eat the whole budget in one call.
		attemptCtx, attemptCancel := context.WithTimeout(probeCtx, readyProbeInterval)
		res, err := httpExec(attemptCtx, vmIP, spec.ReadyCmd, readyProbeInterval, nil)
		attemptCancel()

		if err == nil && res.ExitCode == 0 {
			log.Info().Int("attempts", attempts).Dur("elapsed", time.Since(probeStart).Round(time.Millisecond)).Msg("ready_cmd succeeded")
			return nil
		}

		select {
		case <-time.After(readyProbeInterval):
		case <-probeCtx.Done():
			return fmt.Errorf("ready_cmd did not succeed within %s (%d attempts): %w", readyProbeTimeout, attempts, probeCtx.Err())
		}
	}
}

// truncate returns s clipped to n runes with an ellipsis if it was cut.
// Used so we don't dump a 5 KB `pip install` command into a single log line.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
