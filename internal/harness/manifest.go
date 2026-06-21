// Package harness implements the Harness Contract manifest (`harness.toml`):
// the small declaration a harness ships so the Actor runtime knows how to boot
// its brain, deliver a turn, stream output, and decide when it is safe to
// hibernate. This package is the loader/validator only — it parses the TOML
// into a typed Manifest and enforces the contract's invariants up front, so the
// runtime never has to defend against a malformed manifest at boot time.
//
// The authoritative manifest shape (see .context/SPEC-open-agent-infra.md §4.2
// and the "Actor ⇄ Harness Contract" transcript):
//
//	start     = "claude --headless"        # boot command for the brain (required)
//	transport = "stdin"                    # how one turn arrives: http | stdin | exec
//	port      = 8080                       # required iff transport=http
//	ready     = "GET /healthz"             # optional readiness probe
//	idle      = "signal"                   # signal | http:/<path> | timeout:<dur>
//	state     = ["/root/.claude", "/work"] # paths mapped onto /state (required)
//	level     = 1                          # durability rung: 0 | 1 | 2 (default 0)
package harness

import (
	"fmt"
	"os"
	"strings"
	"time"

	toml "github.com/pelletier/go-toml/v2"
)

// Transport is how a single turn (one inbox event) is delivered to the brain.
// The harness picks exactly one; the runtime wires the inbox accordingly.
type Transport string

const (
	// TransportHTTP delivers a turn as an HTTP request on the manifest's port
	// and streams the response back as the outbox. Used by long-lived servers
	// (e.g. Flue).
	TransportHTTP Transport = "http"
	// TransportStdin delivers a turn on the process's stdin and streams stdout
	// back as the outbox. Used by line-oriented shims (e.g. cc-actor-shim).
	TransportStdin Transport = "stdin"
	// TransportExec runs the start command once per turn (exec-per-event)
	// rather than keeping a resident process between turns.
	TransportExec Transport = "exec"
)

// valid reports whether t is one of the three contract transports.
func (t Transport) valid() bool {
	switch t {
	case TransportHTTP, TransportStdin, TransportExec:
		return true
	default:
		return false
	}
}

// Level is the durability rung the harness implements (§4.3 "durability
// ladder"). The contract never changes; a harness climbs as high as it can and
// the platform fills the rest.
//
//	0 — drop-in: a runnable process whose state lives under the state paths.
//	1 — event:   + accept one turn → stream → signal idle.
//	2 — steps:   + resumable work via $ACTOR_STEP (or a self-managed engine).
type Level int

const (
	// Level0 is the default rung: crash recovery is "restore the last VM
	// snapshot". Works with anything that keeps its state on disk.
	Level0 Level = 0
	// Level1 adds event-driven turns: one turn in, stream out, signal idle.
	Level1 Level = 1
	// Level2 adds resumable durable steps (platform- or self-managed).
	Level2 Level = 2
)

// valid reports whether l is a defined rung (0, 1, or 2).
func (l Level) valid() bool { return l >= Level0 && l <= Level2 }

// IdleKind tags how a harness signals it is safe to hibernate.
type IdleKind string

const (
	// IdleSignal: the harness raises a signal / writes the idle marker itself
	// when a turn completes (the Level-1 signalIdle() in the reference shims).
	IdleSignal IdleKind = "signal"
	// IdleHTTP: the runtime polls an HTTP path (IdlePolicy.Path) that returns
	// 200 when the harness is parked (e.g. Flue's "http:/flue/parked").
	IdleHTTP IdleKind = "http"
	// IdleTimeout: the runtime treats the Actor as idle after a fixed duration
	// of inactivity (IdlePolicy.Timeout).
	IdleTimeout IdleKind = "timeout"
)

// IdlePolicy is the parsed form of the manifest's `idle` string. Exactly one
// kind applies; Path is set only for IdleHTTP and Timeout only for IdleTimeout.
type IdlePolicy struct {
	Kind    IdleKind
	Path    string        // for IdleHTTP: the probe path, with a leading "/".
	Timeout time.Duration // for IdleTimeout: the inactivity window.
}

// String renders the policy back to its manifest spelling, so a loaded manifest
// round-trips through String() for logging/debugging.
func (p IdlePolicy) String() string {
	switch p.Kind {
	case IdleHTTP:
		return "http:" + p.Path
	case IdleTimeout:
		return "timeout:" + p.Timeout.String()
	default:
		return string(IdleSignal)
	}
}

// Manifest is the parsed, validated `harness.toml`. The raw TOML fields are
// decoded into rawManifest first; Manifest holds the typed, post-validation
// view the runtime consumes (Idle is parsed into an IdlePolicy; Transport and
// Level are typed enums).
type Manifest struct {
	// Start is the boot command for the brain, as a single shell-style string
	// (split into argv via StartArgv). Required, non-empty.
	Start string
	// Transport is how one turn arrives. Required; one of the Transport enum.
	Transport Transport
	// Port is the HTTP listen port. Required and in 1..65535 iff
	// Transport==http; must be unset (0) otherwise.
	Port int
	// Ready is an optional readiness probe (e.g. "GET /healthz"). Not parsed
	// further here — the runtime interprets it.
	Ready string
	// Idle is the parsed safe-to-hibernate policy. Defaults to {Kind: signal}
	// when the manifest omits `idle`.
	Idle IdlePolicy
	// State lists guest paths that map onto /state and must hold ALL durable
	// state. Required, non-empty, every entry an absolute path.
	State []string
	// Level is the durability rung. Defaults to Level0 when omitted.
	Level Level

	// idleErr carries an `idle`-string parse failure from Parse into Validate
	// so every manifest problem aggregates into one error. Set only by Parse.
	idleErr error
}

// rawManifest is the on-disk TOML shape: every field is optional/loosely typed
// so we can give precise, field-named errors during Validate rather than
// failing opaquely in the TOML decoder. `idle` stays a string until we parse it
// into an IdlePolicy; `port`/`level` use pointers so we can tell "omitted" from
// "set to 0".
type rawManifest struct {
	Start     string   `toml:"start"`
	Transport string   `toml:"transport"`
	Port      *int     `toml:"port"`
	Ready     string   `toml:"ready"`
	Idle      string   `toml:"idle"`
	State     []string `toml:"state"`
	Level     *int     `toml:"level"`
}

// Load reads a harness.toml from path, parses it, and validates it. It is a
// thin wrapper over Parse so callers get the same aggregated validation errors
// whether the manifest comes from disk or memory.
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("harness: read manifest %q: %w", path, err)
	}
	m, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("harness: %q: %w", path, err)
	}
	return m, nil
}

// Parse decodes a harness.toml from data into a typed Manifest and validates
// it. A successful return guarantees every contract invariant holds, so the
// runtime can consume the Manifest without re-checking. Decode errors and
// validation errors are reported distinctly.
func Parse(data []byte) (*Manifest, error) {
	var raw rawManifest
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("harness: decode manifest: %w", err)
	}

	m := &Manifest{
		Start:     strings.TrimSpace(raw.Start),
		Transport: Transport(strings.TrimSpace(raw.Transport)),
		Ready:     strings.TrimSpace(raw.Ready),
		State:     raw.State,
		Level:     Level0,
	}
	if raw.Port != nil {
		m.Port = *raw.Port
	}
	if raw.Level != nil {
		m.Level = Level(*raw.Level)
	}

	// Default idle is "signal" (the Level-1 reference behavior). A present but
	// malformed `idle` is surfaced as a validation error rather than silently
	// defaulted, so we parse here and let Validate aggregate the error.
	idleStr := strings.TrimSpace(raw.Idle)
	if idleStr == "" {
		m.Idle = IdlePolicy{Kind: IdleSignal}
	} else if pol, err := parseIdle(idleStr); err == nil {
		m.Idle = pol
	} else {
		// Leave Idle.Kind empty so Validate reports the parse error with the
		// original string for context.
		m.idleErr = err
	}

	if err := m.Validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// parseIdle turns the manifest `idle` string into an IdlePolicy.
//
//	"signal"          → {Kind: signal}
//	"http:/<path>"    → {Kind: http, Path: "/<path>"}   (path must be absolute)
//	"timeout:<dur>"   → {Kind: timeout, Timeout: <dur>} (Go duration, > 0)
//
// Any other spelling is an error, so a typo (e.g. "timout:120s") fails loudly
// at load time instead of being misread as "signal".
func parseIdle(s string) (IdlePolicy, error) {
	if s == string(IdleSignal) {
		return IdlePolicy{Kind: IdleSignal}, nil
	}
	if rest, ok := strings.CutPrefix(s, "http:"); ok {
		if !strings.HasPrefix(rest, "/") {
			return IdlePolicy{}, fmt.Errorf("idle: http path %q must start with %q", rest, "/")
		}
		return IdlePolicy{Kind: IdleHTTP, Path: rest}, nil
	}
	if rest, ok := strings.CutPrefix(s, "timeout:"); ok {
		d, err := time.ParseDuration(strings.TrimSpace(rest))
		if err != nil {
			return IdlePolicy{}, fmt.Errorf("idle: timeout %q is not a valid Go duration: %w", rest, err)
		}
		if d <= 0 {
			return IdlePolicy{}, fmt.Errorf("idle: timeout must be > 0, got %s", d)
		}
		return IdlePolicy{Kind: IdleTimeout, Timeout: d}, nil
	}
	return IdlePolicy{}, fmt.Errorf("idle: %q must be one of: signal | http:/<path> | timeout:<dur>", s)
}

// StartArgv splits Start into an argv for exec, using a minimal POSIX-style
// tokenizer: whitespace separates tokens, and single/double quotes group a
// token (so `claude -p "hello world"` → ["claude","-p","hello world"]). This
// covers the common case in the contract's examples. Complex shell syntax
// (pipes, variable expansion, globbing, escapes) is NOT supported — a harness
// that needs it should wrap the command in `sh -c "..."` explicitly. Returns
// nil when Start is empty.
func (m *Manifest) StartArgv() []string {
	return splitArgs(m.Start)
}

// splitArgs is the minimal tokenizer behind StartArgv. It honors single and
// double quotes (which group whitespace into one token and are stripped from
// the result) but performs no escape processing or expansion — intentionally
// simple and predictable.
func splitArgs(s string) []string {
	var (
		args  []string
		cur   strings.Builder
		quote rune // 0, '\'' or '"' — the open quote, if any
		inTok bool // whether cur holds a (possibly empty, if quoted) token
	)
	flush := func() {
		if inTok {
			args = append(args, cur.String())
			cur.Reset()
			inTok = false
		}
	}
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0 // close quote; token continues (may be empty)
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
			inTok = true // an opening quote starts a token even if empty
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			flush()
		default:
			cur.WriteRune(r)
			inTok = true
		}
	}
	flush()
	if len(args) == 0 {
		return nil
	}
	return args
}
