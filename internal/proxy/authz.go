package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

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

	if strings.HasPrefix(token, "mcap.") {
		if h.machineAuthority == nil {
			return InstanceInfo{}, &authzFailure{Status: http.StatusServiceUnavailable, Message: "machine authority unavailable"}
		}
		capability, err := auth.VerifyMachineCapabilityWithAuthority(ctx, token, h.seedKey, time.Now(), h.machineAuthority)
		if err != nil || capability.SandboxID.String() != requestSandboxID || capability.Audience != "sandbox-proxy" {
			return InstanceInfo{}, &authzFailure{Status: http.StatusUnauthorized, Message: "invalid machine capability"}
		}
	} else if !auth.VerifyAccessToken(h.seedKey, requestSandboxID, token) {
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
				Code:    "sandbox_route_stale",
			}
		}
		return InstanceInfo{}, &authzFailure{
			Status:  http.StatusServiceUnavailable,
			Message: "sandbox unavailable",
			Code:    "sandbox_unavailable",
		}
	}
	if info.MachineOwned && !strings.HasPrefix(token, "mcap.") {
		return InstanceInfo{}, &authzFailure{Status: http.StatusUnauthorized, Message: "machine sandbox requires a machine capability"}
	}
	if info.Status != "running" {
		return InstanceInfo{}, &authzFailure{
			Status:  http.StatusServiceUnavailable,
			Message: fmt.Sprintf("sandbox is %s", info.Status),
			Code:    "sandbox_unavailable",
		}
	}

	return info, nil
}

// VerifyMachineOperation is shared by command/file/terminal entry points
// after token authentication. Legacy sandbox tokens intentionally return
// false because they carry no operation scope or lineage.
func VerifyMachineOperation(token string, signingKey []byte, sandboxID string, operation auth.MachineOperation, now time.Time) bool {
	if !strings.HasPrefix(token, "mcap.") {
		return false
	}
	capability, err := auth.VerifyMachineCapability(token, signingKey, now)
	return err == nil && capability.Audience == "sandbox-proxy" && capability.SandboxID.String() == sandboxID && capability.Allows(operation)
}

func machineOperationForProxyPath(method, path string) (auth.MachineOperation, bool) {
	switch {
	case path == "/terminal":
		return auth.MachineOperationCommandRun, true
	case path == "/exec" && method == http.MethodPost:
		return auth.MachineOperationCommandRun, true
	case path == "/exec/stream":
		return auth.MachineOperationCommandRead, true
	case path == "/exec/connect":
		return auth.MachineOperationCommandWrite, true
	case path == "/files" && method == http.MethodGet:
		return auth.MachineOperationFileRead, true
	case path == "/files" && (method == http.MethodPost || method == http.MethodPut):
		return auth.MachineOperationFileWrite, true
	default:
		return "", false
	}
}

func verifyMachineProxyOperation(token string, signingKey []byte, sandboxID, method, path string) bool {
	if !strings.HasPrefix(token, "mcap.") {
		return true
	}
	operation, ok := machineOperationForProxyPath(method, path)
	return ok && VerifyMachineOperation(token, signingKey, sandboxID, operation, time.Now())
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
		desktopSendActionsPath:
		if !h.desktopEnabled {
			return false
		}
	default:
		return false
	}
	if h.seedKey == nil {
		return false
	}
	if strings.HasPrefix(token, "mcap.") {
		capability, err := auth.VerifyMachineCapability(token, h.seedKey, time.Now())
		return err == nil && capability.SandboxID.String() == sandboxID && capability.Audience == "sandbox-proxy"
	}
	return auth.VerifyAccessToken(h.seedKey, sandboxID, token)
}
