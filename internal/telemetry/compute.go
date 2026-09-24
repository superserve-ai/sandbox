package telemetry

import (
	"context"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// ComputeRecorder is an optional extension to Recorder for compute policy
// decisions. Labels contain only policy enums, never subject identifiers.
type ComputeRecorder interface {
	RecordComputeDecision(context.Context, string, string, string, string)
	RecordComputeRefresh(context.Context, string)
}

// ComputeReconcileRecorder records bounded outcomes from background sweeps.
type ComputeReconcileRecorder interface {
	RecordComputeReconciliation(context.Context, string)
}

func (r *OTelRecorder) RecordComputeReconciliation(ctx context.Context, outcome string) {
	outcome = computeLabel(outcome, "run", "matched", "attempted", "completed", "pending", "failure", "would_pause", "no_op_trusted", "no_op_off", "no_op_unrestricted", "no_op_state", "deferred_transition")
	r.computeReconciles.Add(ctx, 1, metric.WithAttributes(attribute.String("source", "config"), attribute.String("outcome", outcome)))
}

type SignupRecorder interface {
	RecordSignupDecision(context.Context, string, string, string)
}

func (r *OTelRecorder) RecordSignupDecision(ctx context.Context, mode, decision, subject string) {
	mode = computeLabel(mode, "off", "observe", "enforce")
	decision = computeLabel(decision, "allowed", "would_deny", "blocked")
	subject = computeLabel(subject, "none", "fingerprint")
	r.signupDecisions.Add(ctx, 1, metric.WithAttributes(attribute.String("source", "config"), attribute.String("mode", mode), attribute.String("decision", decision), attribute.String("subject_type", subject)))
}

func (r *OTelRecorder) RecordComputeDecision(ctx context.Context, action, mode, outcome, subject string) {
	action = computeLabel(action, "create", "resume")
	mode = computeLabel(mode, "off", "observe", "enforce")
	outcome = computeLabel(outcome, "allowed", "would_deny", "blocked")
	subject = computeLabel(subject, "none", "team", "user")
	r.computeDecisions.Add(ctx, 1, metric.WithAttributes(attribute.String("source", "config"), attribute.String("action", action), attribute.String("mode", mode), attribute.String("outcome", outcome), attribute.String("subject_type", subject)))
}
func (r *OTelRecorder) RecordComputeRefresh(ctx context.Context, result string) {
	result = computeLabel(result, "success", "read_error", "invalid_content", "owners_error")
	r.computeRefreshes.Add(ctx, 1, metric.WithAttributes(attribute.String("source", "config"), attribute.String("result", result)))
}

func computeLabel(value string, allowed ...string) string {
	for _, candidate := range allowed {
		if value == candidate {
			return value
		}
	}
	return "unknown"
}
