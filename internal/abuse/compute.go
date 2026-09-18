package abuse

import "github.com/google/uuid"

type ComputeMode string

const (
	ModeOff     ComputeMode = "off"
	ModeObserve ComputeMode = "observe"
	ModeEnforce ComputeMode = "enforce"
)

type computeKey struct {
	team   uuid.UUID
	action Action
}

// ComputeSnapshot is immutable after publication. User matches are joined to
// canonical team owners in the background, keeping evaluation constant-time.
type ComputeSnapshot struct {
	mode    ComputeMode
	trusted map[uuid.UUID]bool
	teams   map[computeKey]bool
	users   map[computeKey]bool
}

type ComputeSource interface{ Snapshot() *ComputeSnapshot }
type ComputeEvaluator struct{ Source ComputeSource }
type ComputeDecision struct {
	Mode                 ComputeMode
	Outcome, SubjectType string
}

func (e *ComputeEvaluator) Evaluate(team uuid.UUID, action Action) ComputeDecision {
	d := ComputeDecision{Mode: ModeOff, Outcome: "allowed", SubjectType: "none"}
	if e == nil || e.Source == nil {
		return d
	}
	s := e.Source.Snapshot()
	if s == nil {
		return d
	}
	d.Mode = s.mode
	if s.mode == ModeOff || s.trusted[team] {
		return d
	}
	k := computeKey{team, action}
	if s.teams[k] {
		d.SubjectType = "team"
	} else if s.users[k] {
		d.SubjectType = "user"
	} else {
		return d
	}
	if s.mode == ModeObserve {
		d.Outcome = "would_deny"
	} else if s.mode == ModeEnforce {
		d.Outcome = "blocked"
	}
	return d
}
