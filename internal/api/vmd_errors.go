package api

import (
	"context"
	"os"
	"strings"

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

// isVMDNotFound returns true when VMD reports that the VM doesn't exist
// in its in-memory map (gRPC NotFound). This happens when VMD was
// restarted and the BoltDB entry was lost.
func isVMDNotFound(err error) bool {
	if err == nil {
		return false
	}
	return status.Code(err) == codes.NotFound
}

// isVMDVMUnavailable returns true when the error indicates the sandbox
// VM is gone — either VMD doesn't know about it (NotFound), or VMD
// knows about it but the Firecracker process is dead (connection
// refused, no route to host, socket errors). In both cases the sandbox
// should be marked failed and the client gets 410 Gone.
func isVMDVMUnavailable(err error) bool {
	if err == nil {
		return false
	}
	if isVMDNotFound(err) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no route to host") ||
		strings.Contains(msg, "connect: connection reset") ||
		strings.Contains(msg, "socket") && strings.Contains(msg, "connect:")
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
