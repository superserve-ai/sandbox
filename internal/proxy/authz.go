package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/auth"
)

// authzFailure is a structured rejection from authorizeSandboxRequest.
type authzFailure struct {
	Status  int
	Message string
	Code    string
}

type machineCapabilityContextKey struct{}

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

	var verifiedCapability *auth.MachineCapability
	if strings.HasPrefix(token, "mcap.") {
		if h.machineAuthority == nil {
			return InstanceInfo{}, &authzFailure{Status: http.StatusServiceUnavailable, Message: "machine authority unavailable"}
		}
		capability, err := auth.VerifyMachineCapabilityWithAuthority(ctx, token, h.seedKey, time.Now(), h.machineAuthority)
		if err != nil || capability.SandboxID.String() != requestSandboxID || capability.Audience != "sandbox-proxy" {
			return InstanceInfo{}, &authzFailure{Status: http.StatusUnauthorized, Message: "invalid machine capability"}
		}
		verifiedCapability = &capability
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
	if verifiedCapability != nil {
		// A signed capability is not sufficient on its own: the resolver's
		// server-side attestation must bind the target sandbox to the same
		// machine principal and team. Missing attestation fails closed rather
		// than falling back to the human owner or public headers.
		capabilityTeam := verifiedCapability.TeamID.String()
		if !info.MachineOwned || info.TeamID == "" || capabilityTeam != info.TeamID || info.MachineOwnerPrincipalID == "" || info.MachineOwnerPrincipalID != verifiedCapability.PrincipalID.String() {
			return InstanceInfo{}, &authzFailure{Status: http.StatusForbidden, Message: "machine sandbox ownership could not be verified"}
		}
		info.MachineCaller = &auth.CallerContext{
			PrincipalID: verifiedCapability.PrincipalID, CredentialID: verifiedCapability.CredentialID,
			LineageID: verifiedCapability.LineageID, TeamID: verifiedCapability.TeamID,
			Permissions: append([]auth.MachineOperation(nil), verifiedCapability.Operations...),
			Policy:      auth.NewMachinePolicy(verifiedCapability.Operations...), Audience: verifiedCapability.Audience,
			ExpiresAt: verifiedCapability.ExpiresAt, RevocationGeneration: verifiedCapability.RevocationGeneration,
		}
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
		// Both exec transports create a process from caller input. Read/write
		// are effects of an already-authorized command, not admission to start
		// one.
		return auth.MachineOperationCommandRun, true
	case path == "/exec/connect":
		return auth.MachineOperationCommandRun, true
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

// machineSessionContext binds a verified capability to the lifetime of a
// stream. Durable revocation invalidates the registry entry and cancels this
// context; callers defer cleanup on every normal or failed exit. Ordinary
// sandbox tokens do not create registrations.
func (h *Handler) machineSessionContext(parent context.Context, token string) (context.Context, func(), bool) {
	if !strings.HasPrefix(token, "mcap.") {
		return parent, func() {}, true
	}
	if h.machineAuthority == nil || h.sessions == nil {
		return parent, func() {}, false
	}
	capability, err := auth.VerifyMachineCapabilityWithAuthority(parent, token, h.seedKey, time.Now(), h.machineAuthority)
	if err != nil {
		return parent, func() {}, false
	}
	ctx, cancel := context.WithCancel(parent)
	id := uuid.NewString()
	state := auth.RevocationState{
		PrincipalID: capability.PrincipalID, CredentialID: capability.CredentialID,
		LineageID: capability.LineageID, RevocationGeneration: capability.RevocationGeneration,
		ExpiresAt: capability.ExpiresAt,
	}
	if err := h.sessions.RegisterWithCancel(id, state, cancel); err != nil {
		cancel()
		return parent, func() {}, false
	}
	// Expiry is enforced for established streams as well as reconnects. The
	// timer is bounded by the registry's session cap and exits as soon as the
	// request or an explicit revocation cancels the stream.
	go func() {
		timer := time.NewTimer(time.Until(capability.ExpiresAt))
		defer timer.Stop()
		select {
		case <-timer.C:
			h.sessions.Expire(id)
		case <-ctx.Done():
		}
	}()
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			h.sessions.Unregister(id)
			cancel()
		})
	}
	return ctx, cleanup, true
}

func (h *Handler) bindMachineRequest(r *http.Request, token string) (*http.Request, func(), bool) {
	ctx, cleanup, ok := h.machineSessionContext(r.Context(), token)
	if !ok {
		return r, cleanup, false
	}
	return r.WithContext(withMachineCapability(ctx, token, h.seedKey)), cleanup, true
}

func withMachineCapability(ctx context.Context, token string, signingKey []byte) context.Context {
	if !strings.HasPrefix(token, "mcap.") {
		return ctx
	}
	capability, err := auth.VerifyMachineCapability(token, signingKey, time.Now())
	if err != nil {
		return ctx
	}
	return context.WithValue(ctx, machineCapabilityContextKey{}, capability)
}

func machineOperationAllowed(ctx context.Context, operation auth.MachineOperation) bool {
	capability, machine := ctx.Value(machineCapabilityContextKey{}).(auth.MachineCapability)
	return !machine || capability.Allows(operation)
}

// RevokeMachineCredential is the serving-instance hook used by the durable
// lifecycle/revocation transport. It only touches bounded local registrations;
// the caller remains responsible for committing durable revocation first and
// broadcasting this notification to every proxy instance.
func (h *Handler) RevokeMachineCredential(credentialID uuid.UUID, generation uint64) int {
	if h == nil || h.sessions == nil {
		return 0
	}
	if h.machineAuthorityInvalidator != nil {
		h.machineAuthorityInvalidator.InvalidateCredential(credentialID)
	}
	return h.sessions.RevokeCredential(credentialID, generation)
}

// RevokeMachinePrincipal closes all active streams derived from a disabled
// principal on this serving instance.
func (h *Handler) RevokeMachinePrincipal(principalID uuid.UUID, generation uint64) int {
	if h == nil || h.sessions == nil {
		return 0
	}
	if h.machineAuthorityInvalidator != nil {
		h.machineAuthorityInvalidator.InvalidatePrincipal(principalID)
	}
	return h.sessions.RevokePrincipal(principalID, generation)
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
