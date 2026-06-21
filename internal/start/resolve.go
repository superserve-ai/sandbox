package start

// Resolve computes the effective start command for an image plus caller
// overrides, following Docker's precedence semantics. It never mutates its
// inputs: every slice and map in the returned Spec is freshly allocated, so the
// caller's Image/Overrides are safe to reuse.
//
// Precedence (first non-empty wins):
//   - argv:    ov.Command (replaces entrypoint+cmd entirely, like
//     `docker run IMG CMD`) → else img.Entrypoint+img.Cmd concatenated.
//   - env:     img.Env, then ov.BuildEnv, then ov.SandboxEnv layered on top
//     (later wins on key collision).
//   - user:    ov.User → img.User → "" (root).
//   - workdir: ov.WorkingDir → img.WorkingDir → "" (means /).
//   - restart: ov.Restart.Normalize() (empty/unknown → DefaultRestartPolicy).
//   - ready:   ov.Ready → "".
//
// An empty resolved argv (no command and no entrypoint/cmd) is valid: it yields
// a Spec where IsRunnable() is false, i.e. a base template that boxd idles on.
func Resolve(img Image, ov Overrides) Spec {
	return Spec{
		Argv:       resolveArgv(img, ov),
		Env:        resolveEnv(img, ov),
		User:       firstNonEmpty(ov.User, img.User),
		WorkingDir: firstNonEmpty(ov.WorkingDir, img.WorkingDir),
		Restart:    ov.Restart.Normalize(),
		Ready:      ov.Ready,
	}
}

// resolveArgv applies Docker's command-vs-entrypoint precedence. When
// ov.Command is set it replaces both entrypoint and cmd (it does NOT append
// img.Cmd, mirroring `docker run IMG CMD`). Otherwise entrypoint and cmd are
// concatenated. The result is always a fresh slice (nil when empty).
func resolveArgv(img Image, ov Overrides) []string {
	if len(ov.Command) > 0 {
		return cloneSlice(ov.Command)
	}
	if len(img.Entrypoint) == 0 && len(img.Cmd) == 0 {
		return nil
	}
	argv := make([]string, 0, len(img.Entrypoint)+len(img.Cmd))
	argv = append(argv, img.Entrypoint...)
	argv = append(argv, img.Cmd...)
	return argv
}

// resolveEnv layers the environment sources lowest-to-highest precedence:
// img.Env, then ov.BuildEnv, then ov.SandboxEnv, with later sources winning on
// key collision. It returns a fresh map (nil when all sources are empty) and
// never mutates any input map.
func resolveEnv(img Image, ov Overrides) map[string]string {
	n := len(img.Env) + len(ov.BuildEnv) + len(ov.SandboxEnv)
	if n == 0 {
		return nil
	}
	env := make(map[string]string, n)
	for k, v := range img.Env {
		env[k] = v
	}
	for k, v := range ov.BuildEnv {
		env[k] = v
	}
	for k, v := range ov.SandboxEnv {
		env[k] = v
	}
	return env
}

// firstNonEmpty returns the first non-empty string, or "" if both are empty.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// cloneSlice returns a fresh copy of s so the Spec never aliases caller-owned
// backing arrays. A nil/empty input yields nil.
func cloneSlice(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	return out
}
