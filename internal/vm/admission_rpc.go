package vm

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/admission"
	"github.com/superserve-ai/sandbox/proto/vmdpb"
)

// intentFromProto translates the wire enum into the gate's own.
//
// The two are separate types on purpose: the gate is the daemon's
// capacity model and must not depend on generated protobuf code, and an
// unrecognized wire value maps to unspecified rather than to a guess, so a
// future sender cannot smuggle a meaning this daemon does not implement.
func intentFromProto(i vmdpb.AdmissionIntent) admission.Intent {
	switch i {
	case vmdpb.AdmissionIntent_ADMISSION_INTENT_CREATE:
		return admission.IntentCreate
	case vmdpb.AdmissionIntent_ADMISSION_INTENT_RESUME:
		return admission.IntentResume
	default:
		return admission.IntentUnspecified
	}
}

// admissionError converts a gate refusal into the status code its caller
// should act on. Nil passes through, so call sites read as one line.
//
// The codes are the contract, not decoration:
//
//   - ResourceExhausted says the host is full and the sandbox is placeable
//     elsewhere. It is the only refusal a caller should answer by choosing
//     another host, which is why it must not share a code with anything a
//     retry to the SAME host could fix.
//   - Unavailable says this host is not taking new sandboxes right now —
//     still reconstructing, or draining. Retryable against another host,
//     and against this one later.
//   - FailedPrecondition says the caller did not declare its intent. Not
//     retryable: the same request will fail identically until the caller is
//     upgraded. Loud on purpose — the alternative is guessing, and both
//     guesses are silently wrong in the case that matters.
func admissionError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, admission.ErrHostAtCapacity):
		return status.Error(codes.ResourceExhausted, err.Error())
	case errors.Is(err, admission.ErrNotReady):
		return status.Error(codes.Unavailable, err.Error())
	case errors.Is(err, admission.ErrIntentRequired):
		return status.Error(codes.FailedPrecondition, err.Error())
	default:
		return err
	}
}
