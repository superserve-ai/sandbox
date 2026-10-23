package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/authz"
)

type renewalChoiceClaims struct {
	jwt.RegisteredClaims
	Operation  string `json:"operation"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	BodySHA256 string `json:"body_sha256"`
}

// The console attests the current customer session and exact request. Team
// permission is checked again locally; this audience grants no staff authority.
func YCRenewalAuth(operation string) gin.HandlerFunc {
	key, err := base64.StdEncoding.DecodeString(os.Getenv("PROMOTION_ACCOUNT_PUBLIC_KEY"))
	configured := err == nil && len(key) == ed25519.PublicKeySize
	return func(c *gin.Context) {
		raw := c.GetHeader("X-YC-Renewal-Assertion")
		c.Request.Header.Del("X-YC-Renewal-Assertion")
		c.Request.Header.Del("X-Actor-User-Id")
		deny := func() {
			respondErrorMsg(c, "forbidden", "Verified customer session required.", http.StatusForbidden)
			c.Abort()
		}
		if !configured || raw == "" || len(raw) > promotionRequestLimit {
			deny()
			return
		}
		claims := new(renewalChoiceClaims)
		_, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) { return ed25519.PublicKey(key), nil }, jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer("promotion-auth-adapter"), jwt.WithAudience("yc-renewal"), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
		actor, actorErr := uuid.Parse(claims.Subject)
		if err != nil || actorErr != nil || actor == uuid.Nil || claims.IssuedAt == nil || claims.ExpiresAt == nil || !claims.ExpiresAt.After(claims.IssuedAt.Time) || claims.ExpiresAt.Sub(claims.IssuedAt.Time) > time.Minute || len(claims.Audience) != 1 || claims.Audience[0] != "yc-renewal" || claims.Operation != operation || claims.Method != c.Request.Method || claims.Path != c.Request.URL.RequestURI() || c.Request.Body == nil {
			deny()
			return
		}
		body, err := io.ReadAll(io.LimitReader(c.Request.Body, promotionRequestLimit+1))
		if err != nil || len(body) > promotionRequestLimit {
			deny()
			return
		}
		digest := sha256.Sum256(body)
		if claims.BodySHA256 != hex.EncodeToString(digest[:]) {
			deny()
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(body))
		c.Set("actor_id", actor)
		c.Set("yc_renewal_verified", true)
		c.Next()
	}
}

func renewalChoiceHTTPError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, authz.ErrPermissionDenied), errors.Is(err, authz.ErrSessionNotEligible):
		respondErrorMsg(c, "forbidden", "Renewal access denied.", http.StatusForbidden)
	case errors.Is(err, errRenewalConflict), errors.Is(err, errRenewalPending):
		respondErrorMsg(c, "renewal_conflict", "Reload the current renewal choice before trying again.", http.StatusConflict)
	default:
		respondErrorMsg(c, "renewal_unavailable", "Renewal choices are unavailable.", http.StatusServiceUnavailable)
	}
}

func (h *Handlers) renewalChoiceActor(c *gin.Context, team uuid.UUID, permission string) (uuid.UUID, bool) {
	actor := actorIDFromContext(c)
	if !c.GetBool("yc_renewal_verified") || actor == nil {
		renewalChoiceHTTPError(c, authz.ErrPermissionDenied)
		return uuid.Nil, false
	}
	if h.Pool == nil || h.RenewalChoices.available() != nil {
		renewalChoiceHTTPError(c, errRenewalDisabled)
		return uuid.Nil, false
	}
	ctx, cancel := promotionContext(c)
	defer cancel()
	// Never use the positive permission cache for a financial instruction.
	allowed, err := authz.New(h.Pool).CanTeam(ctx, *actor, team, permission)
	if err != nil {
		renewalChoiceHTTPError(c, err)
		return uuid.Nil, false
	}
	if !allowed {
		renewalChoiceHTTPError(c, authz.ErrPermissionDenied)
		return uuid.Nil, false
	}
	return *actor, true
}

func (h *Handlers) RenewalChoiceStatus(c *gin.Context) {
	var body struct {
		Team       uuid.UUID `json:"team_id"`
		Assignment uuid.UUID `json:"assignment_id"`
	}
	if !decodePromotionRequest(c, &body) {
		return
	}
	if body.Team == uuid.Nil || body.Assignment == uuid.Nil {
		respondErrorMsg(c, "invalid_request", "Team and assignment are required.", http.StatusBadRequest)
		return
	}
	actor, ok := h.renewalChoiceActor(c, body.Team, "billing:read")
	if !ok {
		return
	}
	ctx, cancel := promotionContext(c)
	defer cancel()
	view, err := h.RenewalChoices.currentView(ctx, body.Team, body.Assignment, actor)
	if err != nil {
		renewalChoiceHTTPError(c, err)
		return
	}
	c.JSON(http.StatusOK, view)
}

func (h *Handlers) SubmitRenewalChoice(c *gin.Context) {
	var body struct {
		renewalChoiceKey
		renewalChoiceRequest
	}
	if !decodePromotionRequest(c, &body) {
		return
	}
	if !validRenewalKey(body.renewalChoiceKey) || body.ID == uuid.Nil || body.Acceptance == uuid.Nil || body.ApprovalRevision < 0 || body.ChoiceRevision < 0 || (body.Choice != "annual" && body.Choice != "monthly" && body.Choice != "free") {
		respondErrorMsg(c, "invalid_request", "Invalid renewal choice.", http.StatusBadRequest)
		return
	}
	actor, ok := h.renewalChoiceActor(c, body.Team, "billing:write")
	if !ok {
		return
	}
	ctx, cancel := promotionContext(c)
	defer cancel()
	if _, err := h.RenewalChoices.submit(ctx, body.renewalChoiceKey, actor, body.renewalChoiceRequest); err != nil {
		renewalChoiceHTTPError(c, err)
		return
	}
	view, err := h.RenewalChoices.view(ctx, body.renewalChoiceKey, actor)
	if err != nil {
		renewalChoiceHTTPError(c, err)
		return
	}
	c.JSON(http.StatusOK, view)
}
