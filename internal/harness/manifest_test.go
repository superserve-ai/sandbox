package harness

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// writeFile writes content to path for the Load round-trip test.
func writeFile(t *testing.T, path, content string) error {
	t.Helper()
	return os.WriteFile(path, []byte(content), 0o600)
}

// fullManifest is a complete, valid http+Level-2 manifest mirroring the Flue
// reference adapter. Used for the happy-path round-trip.
const fullManifest = `
start     = "flue serve --store /state/flue"
transport = "http"
port      = 8080
ready     = "GET /healthz"
idle      = "http:/flue/parked"
state     = ["/state/flue", "/work"]
level     = 2
`

func TestParseFullManifestRoundTrips(t *testing.T) {
	m, err := Parse([]byte(fullManifest))
	if err != nil {
		t.Fatalf("Parse valid manifest: %v", err)
	}
	want := &Manifest{
		Start:     "flue serve --store /state/flue",
		Transport: TransportHTTP,
		Port:      8080,
		Ready:     "GET /healthz",
		Idle:      IdlePolicy{Kind: IdleHTTP, Path: "/flue/parked"},
		State:     []string{"/state/flue", "/work"},
		Level:     Level2,
	}
	if !reflect.DeepEqual(m, want) {
		t.Fatalf("Manifest =\n%#v\nwant\n%#v", m, want)
	}
	// The split boot command feeds the supervisor.
	if got := m.StartArgv(); !reflect.DeepEqual(got, []string{"flue", "serve", "--store", "/state/flue"}) {
		t.Fatalf("StartArgv = %#v", got)
	}
	// Idle policy renders back to its manifest spelling.
	if got := m.Idle.String(); got != "http:/flue/parked" {
		t.Fatalf("Idle.String() = %q", got)
	}
}

func TestParseDefaults(t *testing.T) {
	// A minimal stdin manifest: idle defaults to signal, level defaults to 0.
	const min = `
start     = "cc-actor-shim"
transport = "stdin"
state     = ["/root/.claude"]
`
	m, err := Parse([]byte(min))
	if err != nil {
		t.Fatalf("Parse minimal manifest: %v", err)
	}
	if m.Idle.Kind != IdleSignal {
		t.Errorf("Idle.Kind = %q, want signal (default)", m.Idle.Kind)
	}
	if m.Level != Level0 {
		t.Errorf("Level = %d, want 0 (default)", m.Level)
	}
	if m.Port != 0 {
		t.Errorf("Port = %d, want 0 (unset for stdin)", m.Port)
	}
}

func TestValidate(t *testing.T) {
	// base returns a known-good stdin manifest the cases mutate to trip exactly
	// one rule, so each substring assertion pins a single failure.
	base := func() *Manifest {
		return &Manifest{
			Start:     "claude --headless",
			Transport: TransportStdin,
			Idle:      IdlePolicy{Kind: IdleSignal},
			State:     []string{"/root/.claude", "/work"},
			Level:     Level1,
		}
	}

	tests := []struct {
		name    string
		mutate  func(*Manifest)
		wantSub string // substring expected in the aggregated error ("" = valid)
	}{
		{name: "valid", mutate: func(*Manifest) {}},
		{
			name:    "missing start",
			mutate:  func(m *Manifest) { m.Start = "" },
			wantSub: "start: required",
		},
		{
			name:    "bad transport",
			mutate:  func(m *Manifest) { m.Transport = "grpc" },
			wantSub: `transport: "grpc" invalid`,
		},
		{
			name: "http without port",
			mutate: func(m *Manifest) {
				m.Transport = TransportHTTP
				m.Port = 0
			},
			wantSub: "port: required when transport=http",
		},
		{
			name: "http port out of range",
			mutate: func(m *Manifest) {
				m.Transport = TransportHTTP
				m.Port = 70000
			},
			wantSub: "out of range",
		},
		{
			name:    "port set on non-http transport",
			mutate:  func(m *Manifest) { m.Port = 8080 },
			wantSub: "does not use a port",
		},
		{
			name:    "non-absolute state path",
			mutate:  func(m *Manifest) { m.State = []string{"/ok", "relative/path"} },
			wantSub: "must be an absolute path",
		},
		{
			name:    "empty state",
			mutate:  func(m *Manifest) { m.State = nil },
			wantSub: "state: required",
		},
		{
			name:    "level out of range",
			mutate:  func(m *Manifest) { m.Level = 3 },
			wantSub: "level: 3 invalid",
		},
		{
			name:    "idle kind unset (hand-built manifest)",
			mutate:  func(m *Manifest) { m.Idle = IdlePolicy{} },
			wantSub: "idle: kind",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := base()
			tt.mutate(m)
			err := m.Validate()
			if tt.wantSub == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tt.wantSub)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("Validate() = %q, want substring %q", err.Error(), tt.wantSub)
			}
		})
	}
}

// TestValidateAggregatesAllErrors confirms multiple faults surface in one error
// rather than one-at-a-time.
func TestValidateAggregatesAllErrors(t *testing.T) {
	m := &Manifest{
		Start:     "",      // fault 1
		Transport: "bogus", // fault 2
		Idle:      IdlePolicy{Kind: IdleSignal},
		State:     []string{"oops"}, // fault 3 (non-absolute)
		Level:     9,                // fault 4
	}
	err := m.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want aggregated error")
	}
	for _, sub := range []string{"start: required", "transport:", "must be an absolute path", "level: 9 invalid"} {
		if !strings.Contains(err.Error(), sub) {
			t.Errorf("aggregated error missing %q; got: %v", sub, err)
		}
	}
}

func TestParseIdle(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    IdlePolicy
		wantErr string
	}{
		{name: "signal", in: "signal", want: IdlePolicy{Kind: IdleSignal}},
		{name: "http", in: "http:/flue/parked", want: IdlePolicy{Kind: IdleHTTP, Path: "/flue/parked"}},
		{name: "http root", in: "http:/", want: IdlePolicy{Kind: IdleHTTP, Path: "/"}},
		{name: "timeout seconds", in: "timeout:120s", want: IdlePolicy{Kind: IdleTimeout, Timeout: 120 * time.Second}},
		{name: "timeout compound", in: "timeout:1m30s", want: IdlePolicy{Kind: IdleTimeout, Timeout: 90 * time.Second}},
		{name: "http missing leading slash", in: "http:flue/parked", wantErr: "must start with"},
		{name: "timeout not a duration", in: "timeout:soon", wantErr: "not a valid Go duration"},
		{name: "timeout zero", in: "timeout:0s", wantErr: "must be > 0"},
		{name: "timeout negative", in: "timeout:-5s", wantErr: "must be > 0"},
		{name: "unknown kind", in: "park", wantErr: "must be one of"},
		{name: "typo", in: "timout:120s", wantErr: "must be one of"},
		{name: "empty after prefix", in: "http:", wantErr: "must start with"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseIdle(tt.in)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("parseIdle(%q) = nil error, want %q", tt.in, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseIdle(%q) error = %q, want substring %q", tt.in, err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseIdle(%q) = %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("parseIdle(%q) = %#v, want %#v", tt.in, got, tt.want)
			}
		})
	}
}

// TestParsePropagatesIdleError confirms a malformed `idle` in the TOML fails the
// whole Parse with a field-named error.
func TestParsePropagatesIdleError(t *testing.T) {
	const bad = `
start     = "x"
transport = "stdin"
idle      = "timeout:nope"
state     = ["/s"]
`
	_, err := Parse([]byte(bad))
	if err == nil {
		t.Fatal("Parse() = nil, want idle error")
	}
	if !strings.Contains(err.Error(), "idle:") {
		t.Fatalf("Parse() error = %q, want idle context", err.Error())
	}
}

func TestStartArgv(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "empty", in: "", want: nil},
		{name: "whitespace only", in: "   \t ", want: nil},
		{name: "simple", in: "claude --headless", want: []string{"claude", "--headless"}},
		{name: "extra spaces", in: "  flue   serve  ", want: []string{"flue", "serve"}},
		{name: "tabs and newlines", in: "a\tb\nc", want: []string{"a", "b", "c"}},
		{name: "double quoted group", in: `claude -p "hello world"`, want: []string{"claude", "-p", "hello world"}},
		{name: "single quoted group", in: `sh -c 'echo hi'`, want: []string{"sh", "-c", "echo hi"}},
		{name: "quote glues adjacent", in: `--flag="a b"`, want: []string{`--flag=a b`}},
		{name: "empty quoted arg", in: `cmd ""`, want: []string{"cmd", ""}},
		{name: "store path", in: "flue serve --store /state/flue", want: []string{"flue", "serve", "--store", "/state/flue"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Manifest{Start: tt.in}
			got := m.StartArgv()
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("StartArgv(%q) = %#v, want %#v", tt.in, got, tt.want)
			}
		})
	}
}

// TestStartSpec confirms the bridge into the existing start.Spec contract.
func TestStartSpec(t *testing.T) {
	m := &Manifest{Start: "claude --headless", Ready: "GET /healthz"}
	spec := m.StartSpec()
	if !reflect.DeepEqual(spec.Argv, []string{"claude", "--headless"}) {
		t.Fatalf("StartSpec().Argv = %#v", spec.Argv)
	}
	if spec.Ready != "GET /healthz" {
		t.Fatalf("StartSpec().Ready = %q", spec.Ready)
	}
	if !spec.IsRunnable() {
		t.Fatal("StartSpec().IsRunnable() = false, want true")
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/harness.toml"
	if err := writeFile(t, path, fullManifest); err != nil {
		t.Fatal(err)
	}
	m, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if m.Transport != TransportHTTP || m.Port != 8080 {
		t.Fatalf("Load gave %#v", m)
	}

	if _, err := Load(dir + "/missing.toml"); err == nil {
		t.Fatal("Load(missing) = nil error, want read error")
	}
}
