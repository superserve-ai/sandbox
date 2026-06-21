package step

import "encoding/json"

// EnvVar is the environment variable the platform sets in the guest to the unix
// socket address of the step server. A harness connects here to record/recall
// durable steps. Mirrors $ACTOR_STEP in the Harness Contract (SPEC §2, §7).
const EnvVar = "ACTOR_STEP"

// Op is a protocol operation.
type Op string

const (
	// OpRecall asks for a previously-recorded step result. Response.Found tells
	// whether the harness should skip the work (replay) or run it.
	OpRecall Op = "recall"
	// OpRecord durably memoizes a step result (idempotent on Step name).
	OpRecord Op = "record"
)

// Request is one newline-delimited JSON message from harness → step server.
type Request struct {
	Op    Op              `json:"op"`
	Step  string          `json:"step"`
	Value json.RawMessage `json:"value,omitempty"` // for OpRecord
}

// Response is the reply. For OpRecall, Found indicates a memoized result is
// present in Value. For OpRecord, Found is always true and Value echoes the
// committed value (the existing one if the step was already recorded).
type Response struct {
	Found bool            `json:"found"`
	Value json.RawMessage `json:"value,omitempty"`
	Error string          `json:"error,omitempty"`
}
