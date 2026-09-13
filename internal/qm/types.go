package qm

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/superserve-ai/sandbox/internal/qm/tenantstore"
)

// TenantResponse is the public tenant shape. Resource internals (database,
// bucket, service account, sandbox key) stay server-side.
type TenantResponse struct {
	ID            string    `json:"id"`
	TeamID        string    `json:"teamId"`
	Slug          string    `json:"slug"`
	OrgName       string    `json:"orgName"`
	AdminEmail    string    `json:"adminEmail"`
	SignIn        string    `json:"signIn"`
	ModelProvider string    `json:"modelProvider"`
	Harness       string    `json:"harness"`
	Status        string    `json:"status"`
	PublicURL     *string   `json:"publicUrl"`
	ImageTag      *string   `json:"imageTag"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

// EventResponse is one provisioning event.
type EventResponse struct {
	ID      string          `json:"id"`
	Step    string          `json:"step"`
	Status  string          `json:"status"`
	Message *string         `json:"message"`
	Detail  json.RawMessage `json:"detail"`
	At      time.Time       `json:"at"`
}

// AdminLinkResponse is a freshly minted portal sign-in link.
type AdminLinkResponse struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// SlugAvailabilityResponse answers GET /v1/qm/slugs/{slug}/availability.
type SlugAvailabilityResponse struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

func toTenantResponse(t tenantstore.Tenant) TenantResponse {
	return TenantResponse{
		ID:            t.ID.String(),
		TeamID:        t.TeamID.String(),
		Slug:          t.Slug,
		OrgName:       t.OrgName,
		AdminEmail:    t.AdminEmail,
		SignIn:        t.SignIn,
		ModelProvider: t.ModelProvider,
		Harness:       t.Harness,
		Status:        t.Status,
		PublicURL:     t.PublicUrl,
		ImageTag:      t.ImageTag,
		CreatedAt:     t.CreatedAt,
		UpdatedAt:     t.UpdatedAt,
	}
}

func toEventResponse(e tenantstore.Event) EventResponse {
	out := EventResponse{ID: e.ID.String(), Step: e.Step, Status: e.Status, Message: e.Message, At: e.At}
	if len(e.Detail) > 0 {
		out.Detail = json.RawMessage(e.Detail)
	}
	return out
}

func toEventResponses(events []tenantstore.Event) []EventResponse {
	out := make([]EventResponse, 0, len(events))
	for _, e := range events {
		out = append(out, toEventResponse(e))
	}
	return out
}

func toTenantResponses(tenants []tenantstore.Tenant) []TenantResponse {
	out := make([]TenantResponse, 0, len(tenants))
	for _, t := range tenants {
		out = append(out, toTenantResponse(t))
	}
	return out
}

// respondError writes { "error": message }.
func respondError(c *gin.Context, status int, message string) {
	c.JSON(status, gin.H{"error": message})
}

// respondFieldErrors writes { "error": ..., "fields": { name: message } }.
func respondFieldErrors(c *gin.Context, fields map[string]string) {
	c.JSON(http.StatusBadRequest, gin.H{"error": "Some fields are invalid.", "fields": fields})
}
