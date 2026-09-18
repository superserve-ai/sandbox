package abuse

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestComputePolicy(t *testing.T) {
	team, owner, other := uuid.New(), uuid.New(), uuid.New()
	for _, subject := range []string{"team", "user"} {
		for _, mode := range []string{"", "off", "observe", "enforce"} {
			for _, trusted := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/trust=%v", subject, mode, trusted), func(t *testing.T) {
					id := team
					if subject == "user" {
						id = owner
					}
					trust := "[]"
					if trusted {
						trust = fmt.Sprintf(`["%s"]`, team)
					}
					data := []byte(fmt.Sprintf(`{"mode":%q,"trusted_teams":%s,"restrictions":[{"subject_type":%q,"subject_id":%q,"actions":["create"]}]}`, mode, trust, subject, id))
					s := NewConfigComputeSource("unused", func(context.Context) (map[uuid.UUID][]uuid.UUID, error) {
						return map[uuid.UUID][]uuid.UUID{team: {other, owner}}, nil
					}, nil)
					s.readFile = func(string) ([]byte, error) { return data, nil }
					s.Refresh(context.Background())
					e := &ComputeEvaluator{Source: s}
					want := "allowed"
					if !trusted && mode == "observe" {
						want = "would_deny"
					}
					if !trusted && mode == "enforce" {
						want = "blocked"
					}
					if d := e.Evaluate(team, ActionCreate); d.Outcome != want {
						t.Fatalf("got %+v, want %s", d, want)
					}
					if d := e.Evaluate(team, ActionResume); d.Outcome != "allowed" {
						t.Fatal(d)
					}
					if d := e.Evaluate(other, ActionCreate); d.Outcome != "allowed" {
						t.Fatal(d)
					}
				})
			}
		}
	}
}

func TestComputeRefreshFailuresAndRecovery(t *testing.T) {
	team := uuid.New()
	valid := []byte(fmt.Sprintf(`{"mode":"enforce","restrictions":[{"subject_type":"team","subject_id":%q,"actions":["create","resume"]}]}`, team))
	for _, readErr := range []error{os.ErrNotExist, os.ErrPermission, fmt.Errorf("read failure")} {
		s := NewConfigComputeSource("unused", nil, nil)
		e := &ComputeEvaluator{Source: s}
		data := []byte(`{`)
		var err error
		s.readFile = func(string) ([]byte, error) { return data, err }
		s.Refresh(context.Background())
		if e.Evaluate(team, ActionCreate).Outcome != "allowed" {
			t.Fatal("invalid initial content denied")
		}
		data = valid
		s.Refresh(context.Background())
		original := s.Snapshot()
		data = []byte(`{"mode":"enforce","unknown":true}`)
		s.Refresh(context.Background())
		if s.Snapshot() != original {
			t.Fatal("invalid content replaced snapshot")
		}
		err = readErr
		s.Refresh(context.Background())
		if e.Evaluate(team, ActionCreate).Outcome != "allowed" {
			t.Fatal("read failure retained deny")
		}
		err = nil
		s.Refresh(context.Background())
		if e.Evaluate(team, ActionCreate).Outcome != "allowed" {
			t.Fatal("invalid content resurrected deny")
		}
		data = valid
		s.Refresh(context.Background())
		if e.Evaluate(team, ActionResume).Outcome != "blocked" {
			t.Fatal("valid recovery failed")
		}
		data = []byte(`{"mode":"observe","restrictions":[]}`)
		s.Refresh(context.Background())
		if e.Evaluate(team, ActionCreate).Mode != ModeObserve {
			t.Fatal("mode not refreshed")
		}
	}
}

func TestComputeConfigRejectsInvalidAndPromotionInputs(t *testing.T) {
	for _, data := range []string{`null`, `{}`, `{"mode":"invalid"}`, `{} {}`, `{"promotion_ineligible":true}`, `{"fingerprint":"reused"}`, `{"restrictions":[{"subject_type":"user","subject_id":"00000000-0000-0000-0000-000000000000","actions":["create"]}]}`, `{"restrictions":[{"subject_type":"domain","subject_id":"407643e1-09e9-4cdf-9ab6-85e2c2c645cd","actions":["create"]}]}`, `{"restrictions":[{"subject_type":"user","subject_id":"407643e1-09e9-4cdf-9ab6-85e2c2c645cd","actions":["signup"]}]}`} {
		cfg, err := parseComputeConfig([]byte(data))
		if data == `{}` {
			if err != nil || cfg.Mode != ModeOff {
				t.Fatal("omitted mode must be off")
			}
			continue
		}
		if err == nil {
			t.Fatalf("accepted %s", data)
		}
	}
}

func TestComputeConfigNullRetainsLastKnownGood(t *testing.T) {
	team := uuid.New()
	valid := []byte(fmt.Sprintf(`{"mode":"enforce","restrictions":[{"subject_type":"team","subject_id":%q,"actions":["create","resume"]}]}`, team))
	for _, data := range []string{
		`null`,
		`{"mode":null}`,
		`{"trusted_teams":null}`,
		`{"restrictions":null}`,
		`{"trusted_teams":[null]}`,
		`{"restrictions":[null]}`,
		fmt.Sprintf(`{"restrictions":[{"subject_type":null,"subject_id":%q,"actions":["create"]}]}`, team),
		`{"restrictions":[{"subject_type":"team","subject_id":null,"actions":["create"]}]}`,
		fmt.Sprintf(`{"restrictions":[{"subject_type":"team","subject_id":%q,"actions":null}]}`, team),
		fmt.Sprintf(`{"restrictions":[{"subject_type":"team","subject_id":%q,"actions":[null]}]}`, team),
		`{"mode":"enforce","mode":null}`,
		`{"mode":null,"mode":"enforce"}`,
	} {
		t.Run(data, func(t *testing.T) {
			if _, err := parseComputeConfig([]byte(data)); err == nil {
				t.Fatal("accepted null config value")
			}
			var results []string
			s := NewConfigComputeSource("unused", nil, func(_ context.Context, result string) {
				results = append(results, result)
			})
			content := []byte(data)
			s.readFile = func(string) ([]byte, error) { return content, nil }
			e := &ComputeEvaluator{Source: s}
			s.Refresh(context.Background())
			if e.Evaluate(team, ActionCreate).Outcome != "allowed" {
				t.Fatal("invalid initial content denied")
			}
			content = valid
			s.Refresh(context.Background())
			original := s.Snapshot()
			content = []byte(data)
			s.Refresh(context.Background())
			if s.Snapshot() != original {
				t.Fatal("null config value replaced last-known-good snapshot")
			}
			for _, action := range []Action{ActionCreate, ActionResume} {
				if e.Evaluate(team, action).Outcome != "blocked" {
					t.Fatalf("null config value cleared %s restriction", action)
				}
			}
			if fmt.Sprint(results) != "[invalid_content success invalid_content]" {
				t.Fatalf("unexpected refresh results: %v", results)
			}
		})
	}
}

func TestComputeConfigOmittedAndEmptyLists(t *testing.T) {
	for _, data := range []string{`{}`, `{"trusted_teams":[]}`, `{"restrictions":[]}`, `{"trusted_teams":[],"restrictions":[]}`} {
		cfg, err := parseComputeConfig([]byte(data))
		if err != nil || cfg.Mode != ModeOff || len(cfg.TrustedTeams) != 0 || len(cfg.Restrictions) != 0 {
			t.Fatalf("omitted mode and empty lists must remain valid: %s: %+v, %v", data, cfg, err)
		}
	}
}

func TestComputeOwnerFailureFailsOpenWithoutLosingTeamRestrictions(t *testing.T) {
	team, owner := uuid.New(), uuid.New()
	fail := false
	s := NewConfigComputeSource("unused", func(context.Context) (map[uuid.UUID][]uuid.UUID, error) {
		if fail {
			return nil, os.ErrPermission
		}
		return map[uuid.UUID][]uuid.UUID{team: {owner}}, nil
	}, nil)
	s.readFile = func(string) ([]byte, error) {
		return []byte(fmt.Sprintf(`{"mode":"enforce","restrictions":[{"subject_type":"user","subject_id":%q,"actions":["create"]},{"subject_type":"team","subject_id":%q,"actions":["resume"]}]}`, owner, team)), nil
	}
	e := &ComputeEvaluator{Source: s}
	s.Refresh(context.Background())
	if e.Evaluate(team, ActionCreate).Outcome != "blocked" {
		t.Fatal("owner not matched")
	}
	fail = true
	s.Refresh(context.Background())
	if e.Evaluate(team, ActionCreate).Outcome != "allowed" || e.Evaluate(team, ActionResume).Outcome != "blocked" {
		t.Fatal("owner failure must clear only user matching")
	}
}

func TestComputeConcurrentPublication(t *testing.T) {
	team := uuid.New()
	s := NewConfigComputeSource("unused", nil, nil)
	e := &ComputeEvaluator{Source: s}
	s.readFile = func(string) ([]byte, error) {
		return []byte(fmt.Sprintf(`{"mode":"enforce","trusted_teams":[%q],"restrictions":[{"subject_type":"team","subject_id":%q,"actions":["create"]}]}`, team, team)), nil
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			s.Refresh(context.Background())
		}
	}()
	for i := 0; i < 1000; i++ {
		if e.Evaluate(team, ActionCreate).Outcome != "allowed" {
			t.Fatal("partial snapshot")
		}
	}
	wg.Wait()
}

func TestComputeBackgroundReloadAndShutdown(t *testing.T) {
	team := uuid.New()
	s := NewConfigComputeSource("unused", nil, nil)
	var mu sync.Mutex
	mode := ModeEnforce
	s.readFile = func(string) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		return []byte(fmt.Sprintf(`{"mode":%q,"restrictions":[{"subject_type":"team","subject_id":%q,"actions":["create"]}]}`, mode, team)), nil
	}
	published := make(chan ComputeMode, 1)
	s.report = func(_ context.Context, result string) {
		if result == "success" {
			select {
			case published <- s.Snapshot().mode:
			default:
			}
		}
	}
	waitForPublication := func(want ComputeMode) {
		t.Helper()
		timer := time.NewTimer(time.Second)
		defer timer.Stop()
		for {
			select {
			case got := <-published:
				if got == want {
					return
				}
			case <-timer.C:
				t.Fatalf("background refresh did not publish mode %s", want)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); s.run(ctx, time.Millisecond) }()
	e := &ComputeEvaluator{Source: s}
	for _, step := range []struct {
		mode    ComputeMode
		outcome string
	}{
		{ModeEnforce, "blocked"},
		{ModeObserve, "would_deny"},
		{ModeOff, "allowed"},
	} {
		mu.Lock()
		mode = step.mode
		mu.Unlock()
		waitForPublication(step.mode)
		if d := e.Evaluate(team, ActionCreate); d.Mode != step.mode || d.Outcome != step.outcome {
			t.Fatalf("background mode edit: got %+v, want mode %s outcome %s", d, step.mode, step.outcome)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("refresh did not stop")
	}
}

func TestComputeOwnerChangesAndTrustedTeams(t *testing.T) {
	pilot, example, owner := uuid.New(), uuid.New(), uuid.New()
	owners := map[uuid.UUID][]uuid.UUID{pilot: {owner}, example: {owner}}
	s := NewConfigComputeSource("unused", func(context.Context) (map[uuid.UUID][]uuid.UUID, error) { return owners, nil }, nil)
	trust := fmt.Sprintf(`[%q,%q]`, pilot, example)
	s.readFile = func(string) ([]byte, error) {
		return []byte(fmt.Sprintf(`{"mode":"enforce","trusted_teams":%s,"restrictions":[{"subject_type":"user","subject_id":%q,"actions":["create","resume"]},{"subject_type":"team","subject_id":%q,"actions":["resume"]}]}`, trust, owner, pilot)), nil
	}
	e := &ComputeEvaluator{Source: s}
	s.Refresh(context.Background())
	for _, team := range []uuid.UUID{pilot, example} {
		for _, action := range []Action{ActionCreate, ActionResume} {
			if e.Evaluate(team, action).Outcome != "allowed" {
				t.Fatal("trusted team denied")
			}
		}
	}
	trust = "[]"
	s.Refresh(context.Background())
	if e.Evaluate(example, ActionCreate).Outcome != "blocked" {
		t.Fatal("trust removal not effective")
	}
	owners = nil
	s.Refresh(context.Background())
	if e.Evaluate(example, ActionCreate).Outcome != "allowed" {
		t.Fatal("removed owner still matched")
	}
	if e.Evaluate(pilot, ActionResume).Outcome != "blocked" {
		t.Fatal("team restriction lost")
	}
}
