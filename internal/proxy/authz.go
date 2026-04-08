package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/superserve-ai/sandbox/internal/auth"
)

// authzFailure is a structured rejection from authorizeSandboxRequest. It
// carries the HTTP status and message the caller should return, and — for
// the handful of failure modes the proxy logs at warn level — a key/value
// pair to include in the log line. Keeping this as a value type (not an
// error) lets callers decide whether to log, write, or both, without
// prescribing a specific logging or error-wrapping style.
type authzFailure struct {
	Status  int
	Message string

	// LogMsg is what to emit if the caller chooses to log this failure.
	// Empty string means "nothing useful to log beyond the response".
	LogMsg string
	// LogKV is an optional structured field to attach to the log line.
	LogKV [2]string // {key, value}; empty key => no field
}

// write emits the failure as a plain HTTP error response. Handlers that
// have not yet committed to a streaming response should call this.
func (f *authzFailure) write(w http.ResponseWriter) {
	http.Error(w, f.Message, f.Status)
}

// authorizeSandboxRequest runs the authorization pipeline shared by every
// data-plane endpoint on the edge proxy that is gated by a signed token.
//
// It is deliberately extracted from both the /terminal WebSocket bridge and
// the /files HTTP reverse proxy because both need the exact same chain:
//
//  1. Verify the token's signature, expiry, and requested scope.
//  2. Enforce single-use semantics via the nonce cache.
//  3. Bind the token to the sandbox the request is addressing (defends
//     against a token minted for sandbox A being replayed against sandbox B
//     even though both belong to the same team).
//  4. Resolve the sandbox to a VM IP via the resolver.
//  5. Require the sandbox to be "running" — the data plane never
//     auto-wakes. Paused or idle sandboxes must be resumed via the control
//     plane before they can receive data-plane traffic, so this check is
//     a fail-fast rather than a trigger.
//
// Any failure short-circuits the entire chain and the caller writes the
// returned authzFailure back as the HTTP response. On success the verified
// Payload (carrying SandboxID/TeamID for audit logging) and the resolved
// InstanceInfo (carrying VMIP for the forwarder) are returned.
//
// Panics if WithAuth was not called at startup — an endpoint that wants
// token-gated traffic but was mounted without a verifier is a hard
// configuration bug, not a runtime condition we should degrade on.
func (h *Handler) authorizeSandboxRequest(
	ctx context.Context,
	token string,
	expectedScope auth.Scope,
	requestSandboxID string,
	now time.Time,
) (*auth.Payload, InstanceInfo, *authzFailure) {
	if h.verifier == nil || h.nonces == nil {
		panic("proxy: authorizeSandboxRequest called before WithAuth / WithTerminal / WithFiles")
	}

	payload, err := h.verifier.Verify(token, now, expectedScope)
	if err != nil {
		// Map fine-grained auth errors onto specific HTTP statuses so
		// the frontend can show useful messages ("expired" → re-mint,
		// "invalid" → something is fundamentally wrong).
		switch {
		case errors.Is(err, auth.ErrExpired), errors.Is(err, auth.ErrNotYetValid):
			return nil, InstanceInfo{}, &authzFailure{
				Status:  http.StatusUnauthorized,
				Message: "token expired",
				LogMsg:  "token expired",
			}
		case errors.Is(err, auth.ErrBadSignature),
			errors.Is(err, auth.ErrScopeMismatch):
			return nil, InstanceInfo{}, &authzFailure{
				Status:  http.StatusUnauthorized,
				Message: "invalid token",
				LogMsg:  "token verify failed",
			}
		default:
			return nil, InstanceInfo{}, &authzFailure{
				Status:  http.StatusBadRequest,
				Message: "bad token",
				LogMsg:  "token malformed",
			}
		}
	}

	// Namespace the dedupe key with the sandbox ID so a noisy tenant
	// burning nonces against their own sandbox cannot LRU-evict an
	// unrelated sandbox's nonces and enable replay against it. The
	// signature already binds (sandboxID, nonce) so this is a structural
	// reflection of the token's contents, not a new trust assumption.
	dedupeKey := payload.SandboxID + ":" + payload.Nonce
	if !h.nonces.CheckAndStore(dedupeKey, now) {
		return nil, InstanceInfo{}, &authzFailure{
			Status:  http.StatusUnauthorized,
			Message: "token already used",
			LogMsg:  "token replay rejected",
			LogKV:   [2]string{"sandbox_id", payload.SandboxID},
		}
	}

	if err := auth.SameSandbox(payload, requestSandboxID); err != nil {
		// Token was minted for a different sandbox than the one being
		// addressed. Could be a misconfigured frontend or an active
		// attempt to swap sandboxes with a valid token.
		return nil, InstanceInfo{}, &authzFailure{
			Status:  http.StatusForbidden,
			Message: "token does not match sandbox",
			LogMsg:  "sandbox mismatch",
			LogKV:   [2]string{"token_sandbox", payload.SandboxID},
		}
	}

	info, err := h.resolver.Lookup(ctx, requestSandboxID)
	if err != nil {
		if errors.Is(err, ErrInstanceNotFound) {
			return nil, InstanceInfo{}, &authzFailure{
				Status:  http.StatusNotFound,
				Message: "sandbox not found",
			}
		}
		return nil, InstanceInfo{}, &authzFailure{
			Status:  http.StatusServiceUnavailable,
			Message: "sandbox unavailable",
			LogMsg:  "resolver error",
		}
	}
	if info.Status != "running" {
		return nil, InstanceInfo{}, &authzFailure{
			Status:  http.StatusServiceUnavailable,
			Message: fmt.Sprintf("sandbox is %s", info.Status),
		}
	}

	return payload, info, nil
}
