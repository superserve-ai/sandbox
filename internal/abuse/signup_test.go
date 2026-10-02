package abuse

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestSignupSharedConfigAndModes(t *testing.T) {
	trustedTeam := uuid.New()
	restrictedTeam := uuid.New()
	for _, step := range []struct {
		mode ComputeMode
		want string
	}{
		{ModeOff, "allowed"}, {ModeObserve, "would_deny"}, {ModeEnforce, "blocked"},
	} {
		s := NewConfigComputeSource("unused", nil, nil)
		reads := 0
		s.readFile = func(string) ([]byte, error) {
			reads++
			return []byte(fmt.Sprintf(`{"mode":%q,"trusted_teams":[%q],"restrictions":[{"subject_type":"team","subject_id":%q,"actions":["create"]},{"subject_type":"team","subject_id":%q,"actions":["create"]},{"subject_type":"fingerprint","subject_value":"Case-Sensitive","actions":["signup"]}]}`, step.mode, trustedTeam, trustedTeam, restrictedTeam)), nil
		}
		s.Refresh(context.Background())
		if reads != 1 {
			t.Fatalf("mode %s: refresh read file %d times, want 1", step.mode, reads)
		}
		e := &SignupEvaluator{Source: s}
		if d := e.Evaluate([]SignupSubject{{Type: "fingerprint", Value: "Case-Sensitive"}}); d.Decision != step.want || d.Mode != step.mode {
			t.Fatalf("mode %s: %+v", step.mode, d)
		}
		if d := e.Evaluate([]SignupSubject{{Type: "fingerprint", Value: "case-sensitive"}}); d.Decision != "allowed" {
			t.Fatalf("case-insensitive match: %+v", d)
		}
		compute := &ComputeEvaluator{Source: s}
		if d := compute.Evaluate(trustedTeam, ActionCreate); d.Outcome != "allowed" {
			t.Fatalf("trusted compute team changed: %+v", d)
		}
		if d := compute.Evaluate(restrictedTeam, ActionCreate); d.Outcome != step.want {
			t.Fatalf("mode %s: restricted compute team: %+v", step.mode, d)
		}
		if d := compute.Evaluate(uuid.New(), ActionResume); d.Outcome != "allowed" {
			t.Fatalf("fingerprint affected compute: %+v", d)
		}
		if reads != 1 {
			t.Fatalf("mode %s: evaluation read config file %d additional times", step.mode, reads-1)
		}
	}
}

func TestSignupConfigRejectsInvalidSubjects(t *testing.T) {
	id := uuid.New()
	for _, entry := range []string{
		`{"subject_type":"fingerprint","subject_id":"` + id.String() + `","actions":["signup"]}`,
		`{"subject_type":"fingerprint","subject_value":"","actions":["signup"]}`,
		`{"subject_type":"fingerprint","subject_value":"` + strings.Repeat("x", MaxFingerprintBytes+1) + `","actions":["signup"]}`,
		`{"subject_type":"fingerprint","subject_value":"v","actions":["create"]}`,
		`{"subject_type":"fingerprint","subject_value":"v","actions":["signup","resume"]}`,
		`{"subject_type":"team","subject_id":"` + id.String() + `","subject_value":"v","actions":["create"]}`,
		`{"subject_type":"user","subject_value":"v","actions":["create"]}`,
		`{"subject_type":"team","subject_id":"` + id.String() + `","actions":["signup"]}`,
		`{"subject_type":"fingerprint","subject_value":null,"actions":["signup"]}`,
		`{"subject_type":"fingerprint","subject_value":"v","actions":["signup"],"other":true}`,
	} {
		if _, err := parseComputeConfig([]byte(`{"restrictions":[` + entry + `]}`)); err == nil {
			t.Fatalf("accepted %s", entry)
		}
	}
}

func TestSignupRefreshFailureAndRecovery(t *testing.T) {
	s := NewConfigComputeSource("unused", nil, nil)
	data := []byte(`{"mode":"enforce","restrictions":[{"subject_type":"fingerprint","subject_value":"visitor","actions":["signup"]}]}`)
	var readErr error
	s.readFile = func(string) ([]byte, error) { return data, readErr }
	e := &SignupEvaluator{Source: s}
	match := []SignupSubject{{Type: "fingerprint", Value: "visitor"}}
	s.Refresh(context.Background())
	if e.Evaluate(match).Decision != "blocked" {
		t.Fatal("valid restriction did not publish")
	}
	previous := s.Snapshot()
	data = []byte(`{"mode":"enforce","restrictions":[{"subject_type":"fingerprint","subject_value":"visitor","actions":["create"]}]}`)
	s.Refresh(context.Background())
	if s.Snapshot() != previous {
		t.Fatal("invalid readable content replaced snapshot")
	}
	readErr = os.ErrPermission
	s.Refresh(context.Background())
	if d := e.Evaluate(match); d.Mode != ModeOff || d.Decision != "allowed" {
		t.Fatalf("read failure did not clear: %+v", d)
	}
	readErr = nil
	s.Refresh(context.Background())
	if e.Evaluate(match).Decision != "allowed" {
		t.Fatal("invalid content resurrected restriction")
	}
	data = []byte(`{"mode":"observe","restrictions":[{"subject_type":"fingerprint","subject_value":"visitor","actions":["signup"]}]}`)
	s.Refresh(context.Background())
	if e.Evaluate(match).Decision != "would_deny" {
		t.Fatal("valid content did not recover")
	}
	data = []byte(`{"mode":"enforce","restrictions":[{"subject_type":"fingerprint","subject_value":"new-visitor","actions":["signup"]}]}`)
	s.Refresh(context.Background())
	if d := e.Evaluate(match); d.Decision != "allowed" {
		t.Fatalf("replaced restriction still matched: %+v", d)
	}
	if d := e.Evaluate([]SignupSubject{{Type: "fingerprint", Value: "new-visitor"}}); d.Decision != "blocked" {
		t.Fatalf("new restriction did not match: %+v", d)
	}
}
