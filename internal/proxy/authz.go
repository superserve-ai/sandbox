package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/superserve-ai/sandbox/internal/auth"
)

// authzFailure is a structured rejection from authorizeSandboxRequest.
type authzFailure struct {
	Status  int
	Message string
	Code    string
}

func (f *authzFailure) write(w http.ResponseWriter) {
	if f.Code != "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.Status)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": f.Code, "message": f.Message}})
		return
	}
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
		logSandboxAuth(ctx, "invalid", "")
		return InstanceInfo{}, &authzFailure{
			Status:  http.StatusUnauthorized,
			Message: "invalid access token",
		}
	}

	logSandboxAuth(ctx, "authenticated", "")
	info, err := h.resolver.Lookup(ctx, requestSandboxID)
	if err != nil {
		if errors.Is(err, ErrInstanceNotFound) {
			return InstanceInfo{}, &authzFailure{
				Status:  http.StatusNotFound,
				Message: "sandbox not found",
				Code:    "sandbox_route_stale",
			}
		}
		return InstanceInfo{}, &authzFailure{
			Status:  http.StatusServiceUnavailable,
			Message: "sandbox unavailable",
			Code:    "sandbox_unavailable",
		}
	}
	logSandboxAuth(ctx, "authenticated", info.TeamID)
	if info.Status != "running" {
		return InstanceInfo{}, &authzFailure{
			Status:  http.StatusServiceUnavailable,
			Message: fmt.Sprintf("sandbox is %s", info.Status),
			Code:    "sandbox_unavailable",
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
	case desktopScreenshotPath,
		desktopStreamPath,
		desktopSendPointerPath,
		desktopSendKeyPath,
		desktopScrollPath,
		desktopResizePath,
		desktopSendActionsPath,
		desktopStepPath:
		if !h.desktopEnabled {
			return false
		}
	default:
		return false
	}
	valid := h.seedKey != nil && auth.VerifyAccessToken(h.seedKey, sandboxID, token)
	if valid {
		logSandboxAuth(r.Context(), "authenticated", "")
	}
	return valid
}
