package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
	sentrygin "github.com/getsentry/sentry-go/gin"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/db"
)

const machineAdministrationBodyLimit = 4096

type machineAdministrationAuthority interface {
	EnsurePrincipal(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string) (auth.MachinePrincipal, error)
	ReadPrincipal(context.Context, uuid.UUID) (auth.MachinePrincipal, error)
	IssueCredentialFenced(context.Context, uuid.UUID, string, int64, uuid.UUID) (auth.MachineCredential, error)
	RotateCredentialFenced(context.Context, uuid.UUID, uuid.UUID, string, int64, uuid.UUID) (auth.MachineCredential, error)
	RestorePrincipalFenced(context.Context, uuid.UUID, string, int64, uuid.UUID) (auth.MachineCredential, error)
	RevokeCredential(context.Context, uuid.UUID, string) error
	DisablePrincipalFenced(context.Context, uuid.UUID, int64, uuid.UUID) error
}

var _ machineAdministrationAuthority = (*DBMachineAuthority)(nil)

func (a *DBMachineAuthority) ReadPrincipal(ctx context.Context, id uuid.UUID) (auth.MachinePrincipal, error) {
	if !authorizedControlPlane(ctx) {
		return auth.MachinePrincipal{}, auth.ErrMachineCapabilityDenied
	}
	if a == nil || a.Queries == nil {
		return auth.MachinePrincipal{}, ErrMachineAuthorityUnavailable
	}
	row, err := a.Queries.GetMachinePrincipal(ctx, id)
	if err != nil {
		return auth.MachinePrincipal{}, err
	}
	return machinePrincipalFromRow(row), nil
}

// Bound socket reads even on rejected requests: net/http can drain an unread
// request body after authentication returns. A context deadline cannot stop it.
func machineAdministrationReadDeadline() gin.HandlerFunc {
	return func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/internal/machine-identity/") {
			if err := http.NewResponseController(c.Writer).SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
				respondErrorMsg(c, "service_unavailable", "Machine authority transport is unavailable.", http.StatusServiceUnavailable)
				c.Abort()
				return
			}
		}
		c.Next()
	}
}

// Request capture and panic values can contain operator-supplied credentials.
func machineAdministrationPrivacy() gin.HandlerFunc {
	return func(c *gin.Context) {
		admin := strings.HasPrefix(c.Request.URL.Path, "/internal/machine-identity/")
		runtime := false
		for name := range c.Request.Header {
			if strings.EqualFold(name, "X-QM-Machine-Credential") {
				runtime = true
				break
			}
		}
		if !admin && !runtime {
			c.Next()
			return
		}
		if hub := sentrygin.GetHubFromContext(c); hub != nil {
			hub.Scope().SetRequestBody(nil)
			hub.Scope().AddEventProcessor(func(event *sentry.Event, _ *sentry.EventHint) *sentry.Event {
				event.Request = nil
				return event
			})
		}
		if admin {
			defer func() {
				if recover() != nil {
					panic("machine administration handler panicked")
				}
			}()
		}
		c.Next()
	}
}

// This middleware belongs only after OperatorAuth. An infrastructure token or
// a runtime credential must never confer authority to administer credentials.
func machineAdministrationAuthorization() gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, present := c.Request.Header[http.CanonicalHeaderKey("X-QM-Machine-Credential")]; present {
			respondError(c, ErrForbidden)
			c.Abort()
			return
		}
		c.Header("Cache-Control", "no-store")
		ctx, cancel := context.WithTimeout(WithControlPlaneAuthorization(c.Request.Context()), 10*time.Second)
		defer cancel()
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

func (h *Handlers) machineAdministrator(c *gin.Context) (machineAdministrationAuthority, bool) {
	if !authorizedControlPlane(c.Request.Context()) {
		respondError(c, ErrForbidden)
		return nil, false
	}
	a, ok := h.MachineCredentials.(machineAdministrationAuthority)
	if concrete, isDB := a.(*DBMachineAuthority); isDB && (concrete == nil || concrete.Queries == nil) {
		ok = false
	}
	if !ok || a == nil {
		respondErrorMsg(c, "service_unavailable", "Machine authority is not configured.", http.StatusServiceUnavailable)
		return nil, false
	}
	return a, true
}

func decodeMachineAdministration(c *gin.Context, out any) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, machineAdministrationBodyLimit)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		respondErrorMsg(c, "invalid_request", "Invalid machine administration request.", http.StatusBadRequest)
		return false
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		respondErrorMsg(c, "invalid_request", "Invalid machine administration request.", http.StatusBadRequest)
		return false
	}
	return true
}

func machineAdministrationID(c *gin.Context, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param(name))
	if err != nil || id == uuid.Nil {
		respondErrorMsg(c, "invalid_request", "A valid resource ID is required.", http.StatusBadRequest)
		return uuid.Nil, false
	}
	return id, true
}

func machineAdministrationError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, auth.ErrMachineCapabilityDenied):
		respondError(c, ErrForbidden)
	case errors.Is(err, pgx.ErrNoRows), errors.Is(err, db.ErrMachineLifecycleConflict):
		respondErrorMsg(c, "conflict", "Machine authority state does not permit this operation.", http.StatusConflict)
	default:
		// Database errors can contain credential input or query details.
		respondErrorMsg(c, "service_unavailable", "Machine authority operation could not be completed.", http.StatusServiceUnavailable)
	}
}

func machinePrincipalResponse(p auth.MachinePrincipal) gin.H {
	return gin.H{"principal_id": p.PrincipalID, "team_id": p.TeamID, "hosted_tenant_id": p.HostedTenantID, "status": p.Status, "generation": p.Generation, "approved_template_id": p.ApprovedTemplateID}
}

func (h *Handlers) EnsureMachinePrincipal(c *gin.Context) {
	a, ok := h.machineAdministrator(c)
	if !ok {
		return
	}
	var request struct {
		TeamID             uuid.UUID `json:"team_id"`
		HostedTenantID     uuid.UUID `json:"hosted_tenant_id"`
		ApprovedTemplateID uuid.UUID `json:"approved_template_id"`
	}
	if !decodeMachineAdministration(c, &request) {
		return
	}
	if request.TeamID == uuid.Nil || request.HostedTenantID == uuid.Nil || request.ApprovedTemplateID == uuid.Nil {
		respondErrorMsg(c, "invalid_request", "Team, tenant and approved template IDs are required.", http.StatusBadRequest)
		return
	}
	principal, err := a.EnsurePrincipal(c.Request.Context(), request.TeamID, request.HostedTenantID, request.ApprovedTemplateID, "")
	if err != nil {
		machineAdministrationError(c, err)
		return
	}
	c.JSON(http.StatusOK, machinePrincipalResponse(principal))
}

func (h *Handlers) GetMachinePrincipal(c *gin.Context) {
	a, ok := h.machineAdministrator(c)
	if !ok {
		return
	}
	id, ok := machineAdministrationID(c, "principal_id")
	if !ok {
		return
	}
	principal, err := a.ReadPrincipal(c.Request.Context(), id)
	if err != nil {
		machineAdministrationError(c, err)
		return
	}
	c.JSON(http.StatusOK, machinePrincipalResponse(principal))
}

type machineCredentialRequest struct {
	OperationID             uuid.UUID `json:"operation_id"`
	ExpectedGeneration      int64     `json:"expected_generation"`
	CredentialMaterial      string    `json:"credential_material"`
	ReplacementCredentialID uuid.UUID `json:"replacement_credential_id,omitempty"`
}

func (h *Handlers) MutateMachineCredential(c *gin.Context) {
	a, ok := h.machineAdministrator(c)
	if !ok {
		return
	}
	id, ok := machineAdministrationID(c, "principal_id")
	if !ok {
		return
	}
	var request machineCredentialRequest
	if !decodeMachineAdministration(c, &request) {
		return
	}
	material, err := base64.RawURLEncoding.Strict().DecodeString(request.CredentialMaterial)
	action := c.Param("action")
	if err != nil || len(material) != 32 || base64.RawURLEncoding.EncodeToString(material) != request.CredentialMaterial || request.OperationID == uuid.Nil || request.ExpectedGeneration <= 0 || (action == "rotate") != (request.ReplacementCredentialID != uuid.Nil) {
		respondErrorMsg(c, "invalid_request", "A valid operation, generation and 32-byte base64url credential are required; rotation also requires the replaced credential ID.", http.StatusBadRequest)
		return
	}
	var credential auth.MachineCredential
	switch action {
	case "issue":
		credential, err = a.IssueCredentialFenced(c.Request.Context(), id, request.CredentialMaterial, request.ExpectedGeneration, request.OperationID)
	case "rotate":
		credential, err = a.RotateCredentialFenced(c.Request.Context(), id, request.ReplacementCredentialID, request.CredentialMaterial, request.ExpectedGeneration, request.OperationID)
	case "restore":
		credential, err = a.RestorePrincipalFenced(c.Request.Context(), id, request.CredentialMaterial, request.ExpectedGeneration, request.OperationID)
	default:
		respondErrorMsg(c, "invalid_request", "Unknown machine credential operation.", http.StatusBadRequest)
		return
	}
	if err != nil {
		machineAdministrationError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"credential_id": credential.CredentialID, "principal_id": credential.PrincipalID, "lineage_id": credential.LineageID, "state": credential.State, "expires_at": credential.ExpiresAt, "revocation_generation": credential.RevocationGeneration})
}

func (h *Handlers) RevokeMachineCredential(c *gin.Context) {
	a, ok := h.machineAdministrator(c)
	if !ok {
		return
	}
	id, ok := machineAdministrationID(c, "credential_id")
	if !ok {
		return
	}
	if err := a.RevokeCredential(c.Request.Context(), id, ""); err != nil {
		machineAdministrationError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *Handlers) DisableMachinePrincipal(c *gin.Context) {
	a, ok := h.machineAdministrator(c)
	if !ok {
		return
	}
	id, ok := machineAdministrationID(c, "principal_id")
	if !ok {
		return
	}
	var request struct {
		OperationID        uuid.UUID `json:"operation_id"`
		ExpectedGeneration int64     `json:"expected_generation"`
	}
	if !decodeMachineAdministration(c, &request) {
		return
	}
	if request.OperationID == uuid.Nil || request.ExpectedGeneration <= 0 {
		respondErrorMsg(c, "invalid_request", "A valid operation ID and positive expected generation are required.", http.StatusBadRequest)
		return
	}
	if err := a.DisablePrincipalFenced(c.Request.Context(), id, request.ExpectedGeneration, request.OperationID); err != nil {
		machineAdministrationError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
