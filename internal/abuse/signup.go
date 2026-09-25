package abuse

// MaxFingerprintBytes bounds opaque visitor IDs in both config and requests.
const MaxFingerprintBytes = 256

func ValidFingerprint(value string) bool {
	return len(value) > 0 && len(value) <= MaxFingerprintBytes
}

type SignupSubject struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type SignupDecision struct {
	Mode               ComputeMode `json:"mode"`
	Decision           string      `json:"decision"`
	MatchedSubjectType string      `json:"matched_subject_type"`
}

type SignupEvaluator struct{ Source ComputeSource }

// Evaluate reads one immutable snapshot and performs only exact in-memory matches.
func (e *SignupEvaluator) Evaluate(subjects []SignupSubject) SignupDecision {
	d := SignupDecision{Mode: ModeOff, Decision: "allowed", MatchedSubjectType: "none"}
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
	for _, subject := range subjects {
		if subject.Type == "fingerprint" && s.fingerprints[subject.Value] {
			d.MatchedSubjectType = "fingerprint"
			if s.mode == ModeObserve {
				d.Decision = "would_deny"
			} else if s.mode == ModeEnforce {
				d.Decision = "blocked"
			}
			break
		}
	}
	return d
}
