package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/superserve-ai/sandbox/internal/auth"
)

// authzFailure is a structured rejection from authorizeSandboxRequest.
type authzFailure struct {
	Status  int
	Message string
}

func (f *authzFailure) write(w http.ResponseWriter) {
	http.Error(w, f.Message, f.Status)
}

// authorizeSandboxRequest verifies the per-sandbox HMAC access token
// and resolves the sandbox to a running VM. Shared by /terminal and
// /files on the boxd host label.
func (h *Handler) authorizeSandboxRequest(
	ctx context.Context,
	token string,
	requestSandboxID string,
) (InstanceInfo, *authzFailure) {
	if h.seedKey == nil {
		panic("proxy: authorizeSandboxRequest called without WithAuth")
	}

	if !auth.VerifyAccessToken(h.seedKey, requestSandboxID, token) {
		return InstanceInfo{}, &authzFailure{
			Status:  http.StatusUnauthorized,
			Message: "invalid access token",
		}
	}

	info, err := h.resolver.Lookup(ctx, requestSandboxID)
	if err != nil {
		if errors.Is(err, ErrInstanceNotFound) {
			return InstanceInfo{}, &authzFailure{
				Status:  http.StatusNotFound,
				Message: "sandbox not found",
			}
		}
		return InstanceInfo{}, &authzFailure{
			Status:  http.StatusServiceUnavailable,
			Message: "sandbox unavailable",
		}
	}
	if info.Status != "running" {
		return InstanceInfo{}, &authzFailure{
			Status:  http.StatusServiceUnavailable,
			Message: fmt.Sprintf("sandbox is %s", info.Status),
		}
	}

	return info, nil
}

// Routing must authenticate before consulting shared ownership. Keep token
// carriers intact so the destination performs its normal authorization too.
func (h *Handler) canRouteBoxdRequest(r *http.Request, sandboxID string) bool {
	if r.Method == http.MethodOptions {
		return false
	}
	token := r.Header.Get(accessTokenHeader)
	switch r.URL.Path {
	case filesPath:
		if !h.filesEnabled {
			return false
		}
	case execPath, execStreamPath:
		if !h.execEnabled {
			return false
		}
	case terminalPath:
		if h.terminal == nil {
			return false
		}
		token = extractTerminalToken(r)
	case execConnectPath:
		if !h.execEnabled {
			return false
		}
		token = extractTerminalToken(r)
	default:
		return false
	}
	return h.seedKey != nil && auth.VerifyAccessToken(h.seedKey, sandboxID, token)
}
