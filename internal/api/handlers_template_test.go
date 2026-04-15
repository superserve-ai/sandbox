package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// These tests cover the purely-functional helpers in handlers_template.go
// (validation, spec hashing, shell-quoting). HTTP handler coverage goes
// through integration tests in handlers_test.go.

func TestValidateBuildSpec_Minimal(t *testing.T) {
	spec := &buildSpec{From: "python:3.11"}
	if err := validateBuildSpec(spec); err != nil {
		t.Fatalf("minimal spec should be valid: %v", err)
	}
}

func TestValidateBuildSpec_RejectsNil(t *testing.T) {
	if err := validateBuildSpec(nil); err == nil {
		t.Fatalf("nil spec must be rejected")
	}
}

func TestValidateBuildSpec_RequiresFrom(t *testing.T) {
	if err := validateBuildSpec(&buildSpec{From: ""}); err == nil {
		t.Fatalf("empty from must be rejected")
	}
	if err := validateBuildSpec(&buildSpec{From: "   "}); err == nil {
		t.Fatalf("whitespace-only from must be rejected")
	}
}

func TestValidateBuildSpec_RejectsAlpine(t *testing.T) {
	cases := []string{
		"alpine",
		"alpine:3.21",
		"docker.io/library/alpine:latest",
		"python:3.11-alpine3.21",
	}
	for _, from := range cases {
		t.Run(from, func(t *testing.T) {
			err := validateBuildSpec(&buildSpec{From: from})
			if err == nil || !strings.Contains(err.Error(), "alpine") {
				t.Fatalf("expected alpine rejection for %q, got: %v", from, err)
			}
		})
	}
}

func TestValidateBuildSpec_RejectsDistroless(t *testing.T) {
	err := validateBuildSpec(&buildSpec{From: "gcr.io/distroless/base"})
	if err == nil || !strings.Contains(err.Error(), "distroless") {
		t.Fatalf("expected distroless rejection, got: %v", err)
	}
}

func TestValidateBuildSpec_RequiresExactlyOneOp(t *testing.T) {
	run := "echo hi"
	workdir := "/app"

	// Two ops set → reject.
	err := validateBuildSpec(&buildSpec{
		From: "python:3.11",
		Steps: []buildStep{
			{Run: &run, Workdir: &workdir},
		},
	})
	if err == nil {
		t.Fatalf("step with two ops must be rejected")
	}

	// Zero ops → reject.
	err = validateBuildSpec(&buildSpec{
		From:  "python:3.11",
		Steps: []buildStep{{}},
	})
	if err == nil {
		t.Fatalf("empty step must be rejected")
	}

	// Exactly one → accept.
	err = validateBuildSpec(&buildSpec{
		From:  "python:3.11",
		Steps: []buildStep{{Run: &run}},
	})
	if err != nil {
		t.Fatalf("valid single-op step rejected: %v", err)
	}
}

func TestValidateBuildSpec_CopySizeCap(t *testing.T) {
	bigPayload := strings.Repeat("A", maxCopySrcBytes+1)
	err := validateBuildSpec(&buildSpec{
		From: "python:3.11",
		Steps: []buildStep{
			{Copy: &buildCopyOp{Src: bigPayload, Dst: "/app"}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("copy over cap must be rejected, got: %v", err)
	}
}

func TestValidateBuildSpec_CopyRequiresDst(t *testing.T) {
	err := validateBuildSpec(&buildSpec{
		From: "python:3.11",
		Steps: []buildStep{
			{Copy: &buildCopyOp{Src: "YWJj", Dst: ""}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "dst") {
		t.Fatalf("copy without dst must be rejected, got: %v", err)
	}
}

func TestValidateBuildSpec_EnvRequiresKey(t *testing.T) {
	err := validateBuildSpec(&buildSpec{
		From: "python:3.11",
		Steps: []buildStep{
			{Env: &buildEnvOp{Key: "", Value: "x"}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "key") {
		t.Fatalf("env without key must be rejected, got: %v", err)
	}
}

// canonicalSpecHash must produce the same hash for equivalent specs
// regardless of JSON field ordering. Go's encoding/json writes map keys
// in sorted order, but struct fields follow declaration order — we rely
// on that, so test it explicitly so a future struct reorder breaks loudly.
func TestCanonicalSpecHash_StableAcrossFieldReorder(t *testing.T) {
	run := "pip install requests"
	a := &buildSpec{
		From: "python:3.11",
		Steps: []buildStep{
			{Run: &run},
		},
		StartCmd: "python server.py",
	}
	h1, err := canonicalSpecHash(a)
	if err != nil {
		t.Fatalf("hash a: %v", err)
	}

	// Re-marshal via an intermediate JSON → struct roundtrip. This mimics
	// what happens when a spec is persisted to jsonb and then unmarshaled
	// on dispatch.
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal a: %v", err)
	}
	var b buildSpec
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal a: %v", err)
	}
	h2, err := canonicalSpecHash(&b)
	if err != nil {
		t.Fatalf("hash b: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("hash drifted across roundtrip:\nh1=%s\nh2=%s", h1, h2)
	}
}

// canonicalSpecHash must differ when a meaningful field changes, so the
// idempotency key doesn't collide across distinct specs.
func TestCanonicalSpecHash_DistinctForDifferentSpecs(t *testing.T) {
	a := &buildSpec{From: "python:3.11"}
	b := &buildSpec{From: "python:3.12"}
	ha, _ := canonicalSpecHash(a)
	hb, _ := canonicalSpecHash(b)
	if ha == hb {
		t.Fatalf("different specs produced same hash: %s", ha)
	}
}

// shellQuote + isSafeCopyDst live in internal/vm (build_exec.go); their
// tests belong there. See internal/vm/build_exec_test.go.
