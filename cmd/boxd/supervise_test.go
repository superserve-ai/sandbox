package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/superserve-ai/sandbox/internal/start"
)

var errLookup = errors.New("not found")

// restoreLookups reinstates the package-level lookup seams after a test stubs
// them.
func restoreLookups(u func(string) (*user.User, error), g func(string) (*user.Group, error)) {
	lookupUser = u
	lookupGroup = g
}

// These tests cover the OS-portable supervisor logic: restart-policy
// decisions, the backoff schedule, spec JSON round-trip, the "already
// supervising" guard, user-credential parsing, env layering, and reading /
// writing the baked start spec to an injectable path. They do not spawn
// processes, so they are free of build tags. NOTE: the cmd/boxd package links
// linux-only syscalls (syscall.Sethostname) and therefore only COMPILES (and
// thus only runs its tests) on linux; on darwin the package — and these tests
// — cannot build. Process-spawn tests live in supervise_linux_test.go behind a
// //go:build linux tag.

func TestSuperviseShouldRestart(t *testing.T) {
	cases := []struct {
		name     string
		policy   start.RestartPolicy
		exitCode int
		want     bool
	}{
		{"no/clean", start.RestartNo, 0, false},
		{"no/failure", start.RestartNo, 1, false},
		{"on-failure/clean", start.RestartOnFailure, 0, false},
		{"on-failure/failure", start.RestartOnFailure, 1, true},
		{"on-failure/signal", start.RestartOnFailure, 137, true},
		{"always/clean", start.RestartAlways, 0, true},
		{"always/failure", start.RestartAlways, 1, true},
		// Empty/unknown normalize to DefaultRestartPolicy (on-failure).
		{"empty/clean", start.RestartPolicy(""), 0, false},
		{"empty/failure", start.RestartPolicy(""), 1, true},
		{"garbage/failure", start.RestartPolicy("bogus"), 5, true},
		{"garbage/clean", start.RestartPolicy("bogus"), 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldRestart(tc.policy, tc.exitCode); got != tc.want {
				t.Fatalf("shouldRestart(%q, %d) = %v, want %v", tc.policy, tc.exitCode, got, tc.want)
			}
		})
	}
}

func TestSuperviseBackoffSchedule(t *testing.T) {
	// Monotonic non-decreasing and capped at backoffMax.
	var prev time.Duration = -1
	for attempt := 0; attempt < 20; attempt++ {
		d := nextBackoff(attempt)
		if d < prev {
			t.Fatalf("nextBackoff(%d)=%s decreased from %s", attempt, d, prev)
		}
		if d > backoffMax {
			t.Fatalf("nextBackoff(%d)=%s exceeds cap %s", attempt, d, backoffMax)
		}
		prev = d
	}

	// First attempt is the base; it eventually saturates at the cap.
	if got := nextBackoff(0); got != backoffBase {
		t.Fatalf("nextBackoff(0)=%s, want base %s", got, backoffBase)
	}
	if got := nextBackoff(1); got != 2*backoffBase {
		t.Fatalf("nextBackoff(1)=%s, want %s", got, 2*backoffBase)
	}
	if got := nextBackoff(100); got != backoffMax {
		t.Fatalf("nextBackoff(100)=%s, want cap %s", got, backoffMax)
	}
	// Negative attempt is clamped to 0.
	if got := nextBackoff(-5); got != backoffBase {
		t.Fatalf("nextBackoff(-5)=%s, want base %s", got, backoffBase)
	}
}

func TestSuperviseSpecJSONRoundTrip(t *testing.T) {
	orig := start.Spec{
		Argv:       []string{"python", "agent.py", "--flag"},
		Env:        map[string]string{"FOO": "bar", "BAZ": "qux"},
		User:       "1000:1000",
		WorkingDir: "/srv/app",
		Restart:    start.RestartAlways,
		Ready:      "http://localhost:8080/health",
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got start.Spec
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(orig, got) {
		t.Fatalf("round-trip mismatch:\n orig=%+v\n  got=%+v", orig, got)
	}
}

func TestSuperviseReadWriteStartSpec(t *testing.T) {
	dir := t.TempDir()
	// Nested path to exercise MkdirAll in writeStartSpec.
	path := filepath.Join(dir, "etc", "superserve", "start.json")

	// Absent file → (nil, nil), not an error.
	spec, err := readStartSpec(path)
	if err != nil {
		t.Fatalf("readStartSpec(absent) err=%v", err)
	}
	if spec != nil {
		t.Fatalf("readStartSpec(absent) = %+v, want nil", spec)
	}

	want := &start.Spec{
		Argv:       []string{"/bin/server", "-port", "80"},
		Env:        map[string]string{"ENV": "prod"},
		User:       "appuser",
		WorkingDir: "/app",
		Restart:    start.RestartOnFailure,
	}
	if err := writeStartSpec(path, want); err != nil {
		t.Fatalf("writeStartSpec: %v", err)
	}

	got, err := readStartSpec(path)
	if err != nil {
		t.Fatalf("readStartSpec: %v", err)
	}
	if got == nil || !reflect.DeepEqual(*got, *want) {
		t.Fatalf("read back = %+v, want %+v", got, want)
	}

	// Overwrite is atomic and leaves exactly one file (no .tmp residue).
	want2 := &start.Spec{Argv: []string{"echo", "hi"}, Restart: start.RestartNo}
	if err := writeStartSpec(path, want2); err != nil {
		t.Fatalf("writeStartSpec overwrite: %v", err)
	}
	got2, err := readStartSpec(path)
	if err != nil {
		t.Fatalf("readStartSpec after overwrite: %v", err)
	}
	if got2 == nil || !reflect.DeepEqual(*got2, *want2) {
		t.Fatalf("overwrite read back = %+v, want %+v", got2, want2)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" || (len(e.Name()) > 0 && e.Name()[0] == '.') {
			t.Fatalf("writeStartSpec left residue file %q", e.Name())
		}
	}
}

func TestSuperviseReadStartSpecMalformed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "start.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := readStartSpec(path); err == nil {
		t.Fatal("readStartSpec(malformed) = nil err, want decode error")
	}
}

func TestSuperviseParseUserCredential(t *testing.T) {
	// Stub the passwd/group lookups so resolution is deterministic and does
	// not depend on the test host's user database.
	defer restoreLookups(lookupUser, lookupGroup)
	lookupUser = func(name string) (*user.User, error) {
		if name == "appuser" {
			return &user.User{Uid: "1500", Gid: "1600", Username: "appuser"}, nil
		}
		return nil, errLookup
	}
	lookupGroup = func(name string) (*user.Group, error) {
		if name == "staff" {
			return &user.Group{Gid: "2000", Name: "staff"}, nil
		}
		return nil, errLookup
	}

	rootCases := []string{"", "root", "0", "0:0"}
	for _, s := range rootCases {
		cred, err := parseUserCredential(s)
		if err != nil {
			t.Fatalf("parseUserCredential(%q) err=%v", s, err)
		}
		if cred != nil {
			t.Fatalf("parseUserCredential(%q) = %+v, want nil (inherit root)", s, cred)
		}
	}

	// Numeric uid, gid defaults to uid.
	if cred, err := parseUserCredential("1000"); err != nil || cred == nil {
		t.Fatalf("parseUserCredential(1000) = %+v, %v", cred, err)
	} else if cred.Uid != 1000 || cred.Gid != 1000 {
		t.Fatalf("parseUserCredential(1000) cred=%+v, want uid=gid=1000", cred)
	}

	// Numeric uid:gid.
	if cred, err := parseUserCredential("1000:1001"); err != nil || cred == nil {
		t.Fatalf("parseUserCredential(1000:1001) = %+v, %v", cred, err)
	} else if cred.Uid != 1000 || cred.Gid != 1001 {
		t.Fatalf("parseUserCredential(1000:1001) cred=%+v, want 1000:1001", cred)
	}

	// Named user → looked-up uid/gid.
	if cred, err := parseUserCredential("appuser"); err != nil || cred == nil {
		t.Fatalf("parseUserCredential(appuser) = %+v, %v", cred, err)
	} else if cred.Uid != 1500 || cred.Gid != 1600 {
		t.Fatalf("parseUserCredential(appuser) cred=%+v, want 1500:1600", cred)
	}

	// Named user : named group → user uid, group gid.
	if cred, err := parseUserCredential("appuser:staff"); err != nil || cred == nil {
		t.Fatalf("parseUserCredential(appuser:staff) = %+v, %v", cred, err)
	} else if cred.Uid != 1500 || cred.Gid != 2000 {
		t.Fatalf("parseUserCredential(appuser:staff) cred=%+v, want 1500:2000", cred)
	}

	// Unknown user is an error (we cannot invent a uid).
	if _, err := parseUserCredential("ghost"); err == nil {
		t.Fatal("parseUserCredential(ghost) = nil err, want lookup error")
	}
	// Unknown group is an error.
	if _, err := parseUserCredential("1000:ghostgroup"); err == nil {
		t.Fatal("parseUserCredential(1000:ghostgroup) = nil err, want lookup error")
	}
}

func TestSuperviseEnvLayering(t *testing.T) {
	base := []string{"PATH=/bin", "HOME=/root", "KEEP=1"}
	out := supervisorEnv(base, map[string]string{"KEEP": "override", "NEW": "x"})

	// Base entries are present; spec entries appended (last-wins on lookup).
	if !containsEnv(out, "PATH=/bin") {
		t.Fatalf("env missing base PATH: %v", out)
	}
	if !containsEnv(out, "KEEP=override") {
		t.Fatalf("env missing spec override KEEP=override: %v", out)
	}
	if !containsEnv(out, "NEW=x") {
		t.Fatalf("env missing spec NEW=x: %v", out)
	}
	// Spec override must come AFTER the base value so last-wins resolution picks it.
	lastKeep := ""
	for _, kv := range out {
		if len(kv) >= 5 && kv[:5] == "KEEP=" {
			lastKeep = kv
		}
	}
	if lastKeep != "KEEP=override" {
		t.Fatalf("last KEEP entry = %q, want KEEP=override", lastKeep)
	}

	// A base lacking PATH gets a default PATH injected so bare argv[0] resolves.
	out2 := supervisorEnv([]string{"HOME=/root"}, nil)
	if !hasPrefixEnv(out2, "PATH=") {
		t.Fatalf("supervisorEnv injected no default PATH: %v", out2)
	}
}

// TestSuperviseEmptyArgvIsIdle verifies the no-op path without spawning a
// process: an empty/non-runnable spec leaves the supervisor idle and is not an
// error. (The "already supervising" guard with a live child is exercised in
// supervise_linux_test.go, which needs a real process.)
func TestSuperviseEmptyArgvIsIdle(t *testing.T) {
	sup := newSupervisor(os.Environ())
	if sup.IsSupervising() {
		t.Fatal("fresh supervisor reports IsSupervising=true")
	}
	if err := sup.Start(&start.Spec{}); err != nil {
		t.Fatalf("Start(empty) err=%v", err)
	}
	if err := sup.Start(nil); err != nil {
		t.Fatalf("Start(nil) err=%v", err)
	}
	if sup.IsSupervising() {
		t.Fatal("Start(empty/nil argv) should remain idle")
	}
	// Stop on an idle supervisor must be a safe no-op.
	sup.Stop()
}

// --- helpers ---

func containsEnv(env []string, want string) bool {
	for _, kv := range env {
		if kv == want {
			return true
		}
	}
	return false
}

func hasPrefixEnv(env []string, prefix string) bool {
	for _, kv := range env {
		if len(kv) >= len(prefix) && kv[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}
