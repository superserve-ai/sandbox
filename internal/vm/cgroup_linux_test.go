package vm

import (
	"encoding/json"
	"github.com/rs/zerolog"
	"strings"
	"testing"
)

func TestParseCgroupPopulated(t *testing.T) {
	for body, want := range map[string]bool{
		"populated 1\nfrozen 0\n": true,
		"populated 0\nfrozen 0\n": false,
		"frozen 0\n":              false,
		"":                        false,
		"populated 1":             true,
	} {
		if got := parseCgroupPopulated(body); got != want {
			t.Errorf("parseCgroupPopulated(%q) = %v, want %v", body, got, want)
		}
	}
}

func TestParseMemTotalKB(t *testing.T) {
	kb, ok := parseMemTotalKB("MemTotal:       528234424 kB")
	if !ok || kb != 528234424 {
		t.Fatalf("got %d/%v", kb, ok)
	}
	if _, ok := parseMemTotalKB("MemFree:  123 kB"); ok {
		t.Fatal("MemFree must not parse as MemTotal")
	}
}

// The environment allowlist IS the sandbox-boundary contract: nothing from
// vmd's environ (secrets, flags) may reach the Firecracker chain.
func TestDirectSpawnEnvAllowlist(t *testing.T) {
	env := directSpawnEnv()
	if len(env) != 2 {
		t.Fatalf("allowlist grew to %d entries — additions are a security review: %v", len(env), env)
	}
	for _, kv := range env {
		k := strings.SplitN(kv, "=", 2)[0]
		if k != "PATH" && k != "RUN_DIR" {
			t.Errorf("unexpected env var %q in direct-spawn allowlist", k)
		}
	}
}

func TestDirectSpawnScriptPinsNofile(t *testing.T) {
	script, err := directSpawnScript("ns-7", "/run/vmd/launcher.mntns",
		"mount --make-rprivate / && mount -t tmpfs tmpfs /d && ln -s /a /b",
		"/usr/local/bin/firecracker", "/run/x/firecracker.sock", "vm-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(script, "#!/bin/sh\nexec prlimit --nofile=1024:524288 nsenter ") {
		t.Fatalf("prlimit hop missing or misplaced:\n%s", script)
	}
	// The wrapped body must be the unit path's script verbatim.
	base := fcStartScript("ns-7", "/run/vmd/launcher.mntns",
		"mount --make-rprivate / && mount -t tmpfs tmpfs /d && ln -s /a /b",
		"/usr/local/bin/firecracker", "/run/x/firecracker.sock", "vm-1")
	if strings.Replace(script, "prlimit --nofile=1024:524288 ", "", 1) != base {
		t.Fatal("direct-spawn script diverged from the unit script beyond the prlimit hop")
	}
}

// Supervision must survive record round-trips: losing it on a rewrite is
// the likeliest way a cgroup VM silently reverts to unit-mode in the store,
// after which every unit oracle reads it as dead.
func TestSupervisionRoundTrip(t *testing.T) {
	inst := &VMInstance{ID: "vm-1", Supervision: SupervisionCgroup}
	rec := toRecord(inst)
	if rec.Supervision != SupervisionCgroup {
		t.Fatal("toRecord dropped Supervision")
	}
	back := toInstance(rec)
	if back.Supervision != SupervisionCgroup {
		t.Fatal("toInstance dropped Supervision")
	}

	// Legacy record (predates the field) must read as unit-supervised, and
	// unit-mode must serialize WITHOUT the key (rollback binaries read it).
	var legacy VMRecord
	if err := json.Unmarshal([]byte(`{"id":"old"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if cgroupSupervised(legacy.Supervision) || legacy.Supervision != SupervisionUnit {
		t.Fatal("legacy record must be unit-supervised")
	}
	out, err := json.Marshal(toRecord(&VMInstance{ID: "u", Supervision: SupervisionUnit}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "supervision") {
		t.Fatalf("unit-mode record must omit the supervision key, got %s", out)
	}
}

// A capped console must bound total bytes written and drop the rest,
// reporting success so the guest never blocks — the DoS bound.
func TestCappedConsole(t *testing.T) {
	var sink bytesBuffer
	c := newCappedConsole(&sink, 10, "vm-1", zerolog.Nop())

	n, err := c.Write([]byte("hello"))
	if n != 5 || err != nil {
		t.Fatalf("first write n=%d err=%v", n, err)
	}
	// Second write straddles the cap: 5 already written, cap 10, this is 8.
	n, err = c.Write([]byte("world!!!"))
	if n != 8 || err != nil { // reports full length consumed
		t.Fatalf("straddle write n=%d err=%v", n, err)
	}
	// Third write is entirely past the cap: dropped, still reports success.
	n, err = c.Write([]byte("more"))
	if n != 4 || err != nil {
		t.Fatalf("post-cap write n=%d err=%v", n, err)
	}
	if got := sink.String(); got != "helloworld" { // exactly the cap
		t.Fatalf("sink = %q, want the first 10 bytes only", got)
	}
}

// bytesBuffer is a tiny io.Writer sink (avoids importing bytes just for this).
type bytesBuffer struct{ b []byte }

func (w *bytesBuffer) Write(p []byte) (int, error) { w.b = append(w.b, p...); return len(p), nil }
func (w *bytesBuffer) String() string              { return string(w.b) }
