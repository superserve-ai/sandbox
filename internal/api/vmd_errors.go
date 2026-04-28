package api

import (
	"context"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/db"
)

// ErrSandboxGone is returned when a handler detects that the underlying VM
// is gone (VMD returned NotFound and the sandbox should be marked failed).
// Maps to HTTP 410 Gone — the resource existed but is permanently lost.
var ErrSandboxGone = &AppError{
	Code:       "gone",
	Message:    "Sandbox VM is no longer available and has been marked failed",
	HTTPStatus: 410,
}

// ErrHostStateMissing maps to HTTP 503. Returned when vmd reports a
// file-missing FailedPrecondition while restoring from a template snapshot
// — the DB says ready but the host doesn't have the files. Recovery is an
// ops action (re-run `make seed-templates --force-rebuild`), not something
// the user can fix. 503 signals "service currently unable to handle the
// request" which is the closest fit semantically.
var ErrHostStateMissing = &AppError{
	Code:       "host_state_missing",
	Message:    "Template files are missing on the host; ops action required. Please retry in a few minutes or contact support if the issue persists.",
	HTTPStatus: 503,
}

// isVMDNotFound returns true when VMD reports that the VM is gone
// (gRPC NotFound). This covers two cases:
//   - VMD never had the VM in its map (lost BoltDB entry)
//   - VMD had the VM but detected the process is dead, cleaned up,
//     and returned NotFound
//
// In both cases the sandbox should be marked failed and the client
// gets 410 Gone.
func isVMDNotFound(err error) bool {
	if err == nil {
		return false
	}
	return status.Code(err) == codes.NotFound
}

// isVMDFileMissing returns true when vmd returned a FailedPrecondition
// indicating a snapshot/mem file is missing on disk. The caller maps
// this to a 503 with `host_state_missing` rather than a generic 500 so
// users understand it's a service-side issue not a bad request.
func isVMDFileMissing(err error) bool {
	if err == nil {
		return false
	}
	return status.Code(err) == codes.FailedPrecondition
}

// isVMDInvalidArgument returns true when vmd returned InvalidArgument —
// typically from boxd rejecting a user-supplied command (e.g. bare
// command name that doesn't resolve against the child PATH). The caller
// maps this to 400 with the vmd-supplied message so the user sees why
// their input was rejected instead of a generic 500.
func isVMDInvalidArgument(err error) bool {
	if err == nil {
		return false
	}
	return status.Code(err) == codes.InvalidArgument
}

// vmdErrorMessage returns the gRPC message from a vmd error, stripping
// gRPC/transport framing so the string is safe to surface to API callers.
func vmdErrorMessage(err error) string {
	if s, ok := status.FromError(err); ok {
		return s.Message()
	}
	return err.Error()
}

// markSandboxFailedAsync writes status=failed in a detached goroutine.
// Used when a handler discovers (via VMD NotFound) that the VM is gone.
// Detaches cancellation so the state transition survives client disconnect,
// but keeps the request's trace context so the write appears in the same span.
func (h *Handlers) markSandboxFailedAsync(reqCtx context.Context, sandboxID, teamID uuid.UUID) {
	asyncCtx := context.WithoutCancel(reqCtx)
	go func() {
		ctx, cancel := context.WithTimeout(asyncCtx, asyncTimeout)
		defer cancel()
		if err := h.DB.UpdateSandboxStatus(ctx, db.UpdateSandboxStatusParams{
			ID:     sandboxID,
			Status: db.SandboxStatusFailed,
			TeamID: teamID,
		}); err != nil {
			log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("async mark-failed write failed")
		}
	}()
}
