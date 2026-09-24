package abuse

import "github.com/google/uuid"

type ComputeMode string

const (
	ModeOff     ComputeMode = "off"
	ModeObserve ComputeMode = "observe"
	ModeEnforce ComputeMode = "enforce"
)

// ComputeSnapshot is immutable after publication. User matches are joined to
// canonical team owners in the background, keeping evaluation constant-time.
type ComputeSnapshot struct {
	mode    ComputeMode
	trusted map[uuid.UUID]bool
	teams   map[uuid.UUID]bool
	users   map[uuid.UUID]bool
}

type ComputeSource interface{ Snapshot() *ComputeSnapshot }
type ComputeEvaluator struct{ Source ComputeSource }
type ComputeDecision struct {
	Mode                 ComputeMode
	Outcome, SubjectType string
	Reason               string
}

// Mode returns the mode published with this immutable policy.
func (s *ComputeSnapshot) Mode() ComputeMode {
	if s == nil {
		return ModeOff
	}
	return s.mode
}

// RestrictedTeams returns the teams represented in this published snapshot.
// The result is a copy so callers cannot mutate the shared policy.
func (s *ComputeSnapshot) RestrictedTeams() []uuid.UUID {
	if s == nil || s.mode == ModeOff {
		return nil
	}
	teams := make([]uuid.UUID, 0, len(s.teams)+len(s.users))
	for id := range s.teams {
		if !s.trusted[id] {
			teams = append(teams, id)
		}
	}
	for id := range s.users {
		if !s.trusted[id] && !s.teams[id] {
			teams = append(teams, id)
		}
	}
	return teams
}

func (e *ComputeEvaluator) Evaluate(team uuid.UUID, _ Action) ComputeDecision {
	d := ComputeDecision{Mode: ModeOff, Outcome: "allowed", SubjectType: "none", Reason: "off"}
	if e == nil || e.Source == nil {
		return d
	}
	s := e.Source.Snapshot()
	if s == nil {
		return d
	}
	d.Mode = s.mode
	if s.mode == ModeOff {
		return d
	}
	if s.trusted[team] {
		d.Reason = "trusted"
		return d
	}
	d.Reason = "unrestricted"
	if s.teams[team] {
		d.SubjectType = "team"
	} else if s.users[team] {
		d.SubjectType = "user"
	} else {
		return d
	}
	if s.mode == ModeObserve {
		d.Outcome = "would_deny"
	} else if s.mode == ModeEnforce {
		d.Outcome = "blocked"
	}
	d.Reason = "restricted"
	return d
}
