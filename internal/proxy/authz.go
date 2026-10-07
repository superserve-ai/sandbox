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
	Caller  *auth.CallerContext
}

type machineCapabilityContextKey struct{}
type verifiedCallerContextKey struct{}

func VerifiedCallerFromContext(ctx context.Context) (auth.CallerContext, bool) {
	caller, ok := ctx.Value(verifiedCallerContextKey{}).(auth.CallerContext)
	return caller, ok
}

func retainVerifiedCaller(r *http.Request, caller *auth.CallerContext) {
	if caller != nil {
		*r = *r.WithContext(context.WithValue(r.Context(), verifiedCallerContextKey{}, *caller))
	}
}

func (f *authzFailure) write(w http.ResponseWriter) {
	if f.Code != "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.Status)
		errBody := map[string]any{"code": f.Code, "message": f.Message}
		if f.Caller != nil {
			errBody["caller"] = safeCallerReferences(*f.Caller)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"error": errBody})
		return
	}
	http.Error(w, f.Message, f.Status)
}

func safeCallerReferences(caller auth.CallerContext) map[string]string {
	refs := map[string]string{
		"principal_id":  caller.PrincipalID.String(),
		"credential_id": caller.CredentialID.String(),
		"lineage_id":    caller.LineageID.String(),
		"team_id":       caller.TeamID.String(),
	}
	if caller.CallerKind != "" {
		refs["caller_kind"] = caller.CallerKind
	}
	if caller.ActorID != uuid.Nil {
		refs["actor_id"] = caller.ActorID.String()
	}
	return refs
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
		var authorityErr error
		capability, err := auth.VerifyMachineCapability(token, h.seedKey, time.Now())
		if err == nil && !capability.IsTeamCapability() {
			if h.machineAuthority == nil {
				logSandboxAuth(ctx, "error", "")
				return InstanceInfo{}, &authzFailure{Status: http.StatusServiceUnavailable, Message: "machine authority unavailable"}
			}
			capability, err = auth.VerifyMachineCapabilityWithAuthority(ctx, token, h.seedKey, time.Now(), func(ctx context.Context, principal, credential uuid.UUID) (uint64, error) {
				generation, lookupErr := h.machineAuthority(ctx, principal, credential)
				authorityErr = lookupErr
				return generation, lookupErr
			})
		}
		if err != nil || capability.Audience != "sandbox-proxy" {
			outcome := "invalid"
			if authorityErr != nil {
				// The authority currently has no typed denial/error distinction.
				// Do not infer invalid credentials from a failed authority lookup.
				outcome = "error"
			}
			logSandboxAuth(ctx, outcome, "")
			return InstanceInfo{}, &authzFailure{Status: http.StatusUnauthorized, Message: "invalid machine capability"}
		}
		logVerifiedCaller(ctx, *callerContextFromCapability(capability))
		if capability.SandboxID.String() != requestSandboxID {
			return InstanceInfo{}, &authzFailure{Status: http.StatusUnauthorized, Message: "invalid machine capability"}
		}
		verifiedCapability = &capability
	} else if !auth.VerifyAccessToken(h.seedKey, requestSandboxID, token) {
		logSandboxAuth(ctx, "invalid", "")
		return InstanceInfo{}, &authzFailure{
			Status:  http.StatusUnauthorized,
			Message: "invalid access token",
		}
	}

	var verifiedCaller *auth.CallerContext
	if verifiedCapability != nil {
		verifiedCaller = callerContextFromCapability(*verifiedCapability)
	}
	if verifiedCapability == nil {
		logSandboxAuth(ctx, "authenticated", "")
	}
	info, err := h.resolver.Lookup(ctx, requestSandboxID)
	if err != nil {
		if errors.Is(err, ErrInstanceNotFound) {
			return InstanceInfo{}, &authzFailure{
				Status:  http.StatusNotFound,
				Message: "sandbox not found",
				Code:    "sandbox_route_stale",
				Caller:  verifiedCaller,
			}
		}
		return InstanceInfo{}, &authzFailure{
			Status:  http.StatusServiceUnavailable,
			Message: "sandbox unavailable",
			Code:    "sandbox_unavailable",
			Caller:  verifiedCaller,
		}
	}
	logResourceTeam(ctx, info.TeamID)
	ownershipState := info.OwnershipState
	if ownershipState == "" {
		if info.MachineOwned && info.MachineOwnerPrincipalID != "" {
			ownershipState = auth.OwnershipMachine
		} else {
			// Direct in-process resolvers predating the attestation field are
			// retained for ordinary sandboxes. The HTTP VMD contract emits an
			// explicit "unknown" state for records that lack proof.
			ownershipState = auth.OwnershipOrdinary
		}
	}
	if ownershipState != auth.OwnershipOrdinary && !strings.HasPrefix(token, "mcap.") {
		return InstanceInfo{}, &authzFailure{Status: http.StatusUnauthorized, Message: "machine sandbox requires a machine capability"}
	}
	if verifiedCapability != nil {
		// A signed capability is not sufficient on its own: the resolver's
		// server-side attestation must bind the target sandbox to the same
		// machine principal and team. Missing attestation fails closed rather
		// than falling back to the human owner or public headers.
		capabilityTeam := verifiedCapability.TeamID.String()
		if verifiedCapability.IsTeamCapability() {
			if info.TeamID == "" || capabilityTeam != info.TeamID || ownershipState == auth.OwnershipUnknown {
				return InstanceInfo{}, &authzFailure{Status: http.StatusForbidden, Message: "sandbox ownership could not be verified", Code: "sandbox_ownership_denied", Caller: callerContextFromCapability(*verifiedCapability)}
			}
		} else if ownershipState != auth.OwnershipMachine || info.TeamID == "" || capabilityTeam != info.TeamID || info.MachineOwnerPrincipalID == "" || info.MachineOwnerPrincipalID != verifiedCapability.PrincipalID.String() {
			return InstanceInfo{}, &authzFailure{Status: http.StatusForbidden, Message: "machine sandbox ownership could not be verified", Code: "sandbox_ownership_denied", Caller: callerContextFromCapability(*verifiedCapability)}
		}
		credentialID := verifiedCapability.CredentialID
		if verifiedCapability.IsTeamCapability() {
			credentialID = verifiedCapability.ParentCredentialID
		}
		info.MachineCaller = &auth.CallerContext{
			PrincipalID: verifiedCapability.PrincipalID, CredentialID: credentialID,
			LineageID: verifiedCapability.LineageID, TeamID: verifiedCapability.TeamID,
			Permissions: append([]auth.MachineOperation(nil), verifiedCapability.Operations...),
			Policy:      auth.NewMachinePolicy(verifiedCapability.Operations...), Audience: verifiedCapability.Audience,
			ExpiresAt: verifiedCapability.ExpiresAt, RevocationGeneration: verifiedCapability.RevocationGeneration,
			CallerKind: verifiedCapability.CallerKind, ActorID: verifiedCapability.ActorID,
		}
	}
	if info.Status != "running" {
		return InstanceInfo{}, &authzFailure{
			Status:  http.StatusServiceUnavailable,
			Message: fmt.Sprintf("sandbox is %s", info.Status),
			Code:    "sandbox_unavailable",
			Caller:  verifiedCaller,
		}
	}

	return info, nil
}

func callerContextFromCapability(capability auth.MachineCapability) *auth.CallerContext {
	credentialID := capability.CredentialID
	if capability.IsTeamCapability() {
		credentialID = capability.ParentCredentialID
	}
	return &auth.CallerContext{
		PrincipalID: capability.PrincipalID, CredentialID: credentialID,
		LineageID: capability.LineageID, TeamID: capability.TeamID,
		Permissions: append([]auth.MachineOperation(nil), capability.Operations...),
		Policy:      auth.NewMachinePolicy(capability.Operations...), Audience: capability.Audience,
		ExpiresAt: capability.ExpiresAt, RevocationGeneration: capability.RevocationGeneration,
		CallerKind: capability.CallerKind, ActorID: capability.ActorID,
	}
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
	if !ok && method == http.MethodPost {
		switch path {
		case desktopScreenshotPath, desktopStreamPath:
			operation, ok = auth.TeamOperationDesktopRead, true
		case desktopSendPointerPath, desktopSendKeyPath, desktopScrollPath, desktopResizePath, desktopSendActionsPath, desktopStepPath:
			operation, ok = auth.TeamOperationDesktopWrite, true
		}
	}
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
	capability, err := auth.VerifyMachineCapability(token, h.seedKey, time.Now())
	if err != nil {
		return parent, func() {}, false
	}
	if capability.IsTeamCapability() {
		// Human child claims are bounded by their typed capability expiry and
		// carry no machine credential lineage to register in the machine fence.
		ctx, cancel := context.WithDeadline(parent, capability.ExpiresAt)
		return ctx, cancel, true
	}
	if h.machineAuthority == nil || h.sessions == nil {
		return parent, func() {}, false
	}
	registrationEpoch := h.sessions.CurrentEpoch()
	freshUntil := time.Now().Add(5 * time.Second)
	generation, observedUntil, err := h.lookupMachineAuthority(parent, capability)
	if err != nil || generation != capability.RevocationGeneration {
		return parent, func() {}, false
	}
	if observedUntil.Before(freshUntil) {
		freshUntil = observedUntil
	}
	if capability.ExpiresAt.Before(freshUntil) {
		freshUntil = capability.ExpiresAt
	}
	ctx, cancel := context.WithCancel(parent)
	id := uuid.NewString()
	state := auth.RevocationState{
		PrincipalID: capability.PrincipalID, CredentialID: capability.CredentialID,
		LineageID: capability.LineageID, RevocationGeneration: capability.RevocationGeneration,
		ExpiresAt: capability.ExpiresAt,
	}
	if err := h.sessions.RegisterWithCancelEpoch(id, state, cancel, registrationEpoch); err != nil {
		cancel()
		return parent, func() {}, false
	}
	// Expiry and continuing authority freshness are enforced for established
	// streams as well as reconnects. A refresh failure closes at the absolute
	// freshness deadline; it never extends access and does not depend on frame
	// activity or a notification producer.
	go func() {
		for {
			deadline := freshUntil
			if capability.ExpiresAt.Before(deadline) {
				deadline = capability.ExpiresAt
			}
			remaining := time.Until(deadline)
			if remaining <= 0 {
				h.sessions.Expire(id)
				return
			}
			wait := remaining / 2
			if wait > time.Second {
				wait = time.Second
			}
			if wait < time.Millisecond {
				wait = time.Millisecond
			}
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
				// A refresh is only useful if it completes before the old
				// snapshot's deadline. Bound the lookup independently of the
				// stream context so a hung store cannot keep the stream alive.
				type refreshResult struct {
					generation uint64
					until      time.Time
					err        error
				}
				resultCh := make(chan refreshResult, 1)
				refreshCtx, refreshCancel := context.WithTimeout(ctx, time.Second)
				go func() {
					generation, nextUntil, refreshErr := h.refreshMachineAuthority(refreshCtx, capability)
					resultCh <- refreshResult{generation: generation, until: nextUntil, err: refreshErr}
				}()
				hardDeadline := time.NewTimer(time.Until(deadline))
				var result refreshResult
				select {
				case result = <-resultCh:
					hardDeadline.Stop()
				case <-hardDeadline.C:
					refreshCancel()
					h.sessions.Expire(id)
					return
				case <-ctx.Done():
					hardDeadline.Stop()
					refreshCancel()
					return
				}
				refreshCancel()
				generation, nextUntil, refreshErr := result.generation, result.until, result.err
				if refreshErr != nil || generation != capability.RevocationGeneration || !time.Now().Before(deadline) {
					h.sessions.Expire(id)
					return
				}
				freshUntil = nextUntil
				if capability.ExpiresAt.Before(freshUntil) {
					freshUntil = capability.ExpiresAt
				}
			case <-ctx.Done():
				timer.Stop()
				return
			}
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

func (h *Handler) lookupMachineAuthority(ctx context.Context, capability auth.MachineCapability) (uint64, time.Time, error) {
	if h.machineAuthoritySnapshotter != nil {
		return h.machineAuthoritySnapshotter.LookupSnapshot(ctx, capability.PrincipalID, capability.CredentialID)
	}
	generation, err := h.machineAuthority(ctx, capability.PrincipalID, capability.CredentialID)
	return generation, time.Now().Add(5 * time.Second), err
}

type proactiveAuthoritySnapshotter interface {
	RefreshSnapshot(context.Context, uuid.UUID, uuid.UUID) (uint64, time.Time, error)
}

func (h *Handler) refreshMachineAuthority(ctx context.Context, capability auth.MachineCapability) (uint64, time.Time, error) {
	if refresher, ok := h.machineAuthoritySnapshotter.(proactiveAuthoritySnapshotter); ok {
		return refresher.RefreshSnapshot(ctx, capability.PrincipalID, capability.CredentialID)
	}
	return h.lookupMachineAuthority(ctx, capability)
}

func (h *Handler) bindMachineRequest(w http.ResponseWriter, r *http.Request, token string) (*http.Request, func(), bool) {
	ctx, cleanup, ok := h.machineSessionContext(r.Context(), token)
	if !ok {
		return r, cleanup, false
	}
	if !strings.HasPrefix(token, "mcap.") {
		return r.WithContext(ctx), cleanup, true
	}
	// Canceling the upstream request does not interrupt a blocked downstream
	// Write or request-body Read. Deadline the actual client transport too.
	controller := http.NewResponseController(w)
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(finished)
		_ = controller.SetReadDeadline(time.Now())
		_ = controller.SetWriteDeadline(time.Now())
	})
	var once sync.Once
	finish := func() {
		once.Do(func() {
			// Join cancellation before this writer can belong to a later
			// keepalive request. Normal completion must stop the callback
			// before cleanup cancels the session context.
			if !stop() {
				<-finished
			}
			cleanup()
		})
	}
	return r.WithContext(withMachineCapability(ctx, token, h.seedKey)), finish, true
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
		desktopSendActionsPath,
		desktopStepPath:
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
	valid := auth.VerifyAccessToken(h.seedKey, sandboxID, token)
	if valid {
		logSandboxAuth(r.Context(), "authenticated", "")
	}
	return valid
}
