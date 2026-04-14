package api

import (
	"context"
	"os"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/db"
)

// snapshotFileExists returns true when the snapshot path refers to a
// readable local file. Used to guard the stateless fallback path so we
// don't tell VMD to restore from a file it can't actually read.
func snapshotFileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

// ErrSandboxGone is returned when a handler detects that the underlying VM
// is gone (VMD returned NotFound and the sandbox should be marked failed).
// Maps to HTTP 410 Gone — the resource existed but is permanently lost.
var ErrSandboxGone = &AppError{
	Code:       "gone",
	Message:    "Sandbox VM is no longer available and has been marked failed",
	HTTPStatus: 410,
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
