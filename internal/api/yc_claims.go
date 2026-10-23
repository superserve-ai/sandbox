package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/superserve-ai/sandbox/internal/ycclaims"
)

// Capture cannot bind accounts; Console cannot attest YC provider evidence.
func YCClaimAuth(env string) gin.HandlerFunc {
	return func(c *gin.Context) {
		want := os.Getenv(env)
		header := c.GetHeader("Authorization")
		got := strings.TrimPrefix(header, "Bearer ")
		other := "YC_CLAIM_CONSOLE_TOKEN"
		if env == other {
			other = "YC_CLAIM_CAPTURE_TOKEN"
		}
		if !strings.HasPrefix(header, "Bearer ") || len(want) < 32 || want == os.Getenv(other) || want == os.Getenv("INTERNAL_API_TOKEN") || want == os.Getenv("OPERATOR_API_TOKEN") || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			respondErrorMsg(c, "unauthorized", "claim service unavailable", http.StatusUnauthorized)
			c.Abort()
			return
		}
		c.Next()
	}
}

func (h *Handlers) ycClaimRPC(ctx context.Context, op string, p any) (json.RawMessage, error) {
	if h.PromotionAuthPool == nil {
		return nil, errors.New("shared claim authority unavailable")
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	var out json.RawMessage
	err = h.PromotionAuthPool.QueryRow(ctx, "SELECT public.yc_claim_rpc($1,$2::jsonb)", op, b).Scan(&out)
	return out, err
}

func ycClaimError(c *gin.Context, err error) {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch pg.Code {
		case "22023", "23505":
			respondErrorMsg(c, "claim_review_required", "This claim requires operator review.", http.StatusConflict)
			return
		case "P0002":
			respondErrorMsg(c, "claim_missing", "Claim unavailable.", http.StatusNotFound)
			return
		}
	}
	respondErrorMsg(c, "claim_unavailable", "Claim service unavailable. Please retry.", http.StatusServiceUnavailable)
}

func (h *Handlers) SubmitYCClaim(c *gin.Context) {
	var in struct {
		Email string `json:"email"`
		Link  string `json:"link"`
	}
	if !decodePromotionRequest(c, &in) {
		return
	}
	email, err := ycclaims.Email(in.Email)
	if err != nil {
		respondErrorMsg(c, "invalid_email", "Enter a valid email address.", 400)
		return
	}
	if _, err = ycclaims.VerificationURL(in.Link); err != nil {
		respondErrorMsg(c, "invalid_link", "Enter a YC founder verification link.", 400)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 12*time.Second)
	defer cancel()
	budget, err := h.ycClaimRPC(ctx, "budget", gin.H{"email_hash": ycclaims.Hash(email)})
	if err != nil {
		ycClaimError(c, err)
		return
	}
	var rate struct {
		Allowed bool `json:"allowed"`
	}
	if json.Unmarshal(budget, &rate) != nil || !rate.Allowed {
		respondErrorMsg(c, "rate_limited", "Please try again later.", 429)
		return
	}
	e, ref, err := ycclaims.NewVerifier().Verify(ctx, in.Link)
	if err != nil {
		status := 400
		if errors.Is(err, ycclaims.ErrUnavailable) {
			status = 503
		}
		respondErrorMsg(c, "verification_failed", "YC verification could not be completed. Please check the link and retry.", status)
		return
	}
	state, reason := "manual_review", "email_mismatch"
	company := e.AutomaticCompany()
	if e.Email == "" {
		reason = "founder_email_missing"
	} else if company == "" {
		reason = "company_review_required"
	} else if email == e.Email {
		state, reason = "awaiting_confirmation", "email_match"
	}
	p := gin.H{"submitted_email": email, "founder_email": e.Email, "evidence": e, "verification_reference": ref, "company_identity": company, "state": state, "reason": reason}
	if state == "awaiting_confirmation" {
		b := make([]byte, 32)
		if _, err = rand.Read(b); err != nil {
			ycClaimError(c, err)
			return
		}
		token := base64.RawURLEncoding.EncodeToString(b)
		p["confirmation_token"] = token
		p["token_hash"] = ycclaims.Hash(token)
	}
	out, err := h.ycClaimRPC(ctx, "submit", p)
	if err != nil {
		ycClaimError(c, err)
		return
	}
	c.Data(http.StatusOK, "application/json", out)
}

type ycClaimRequest struct {
	ID     uuid.UUID `json:"id"`
	UserID uuid.UUID `json:"user_id"`
	TeamID uuid.UUID `json:"team_id"`
	Token  string    `json:"token"`
}

func validYCToken(v string) bool {
	b, e := base64.RawURLEncoding.DecodeString(v)
	return e == nil && len(b) == 32 && len(v) == 43
}

func (h *Handlers) ConfirmYCClaim(c *gin.Context) {
	var in ycClaimRequest
	if !decodePromotionRequest(c, &in) {
		return
	}
	if in.ID == uuid.Nil || !validYCToken(in.Token) || in.UserID != uuid.Nil || in.TeamID != uuid.Nil {
		respondErrorMsg(c, "invalid_confirmation", "Invalid confirmation link.", 400)
		return
	}
	ctx, cancel := promotionContext(c)
	defer cancel()
	out, err := h.ycClaimRPC(ctx, "confirm", gin.H{"id": in.ID, "token_hash": ycclaims.Hash(in.Token)})
	if err != nil {
		ycClaimError(c, err)
		return
	}
	c.Data(200, "application/json", out)
}

func (h *Handlers) ListYCClaims(c *gin.Context) {
	var in ycClaimRequest
	if !decodePromotionRequest(c, &in) {
		return
	}
	if in.UserID == uuid.Nil || in.ID != uuid.Nil || in.TeamID != uuid.Nil || in.Token != "" {
		respondErrorMsg(c, "invalid_request", "Invalid account request.", 400)
		return
	}
	ctx, cancel := promotionContext(c)
	defer cancel()
	out, err := h.ycPreferredRPC(ctx, "lookup", gin.H{"user_id": in.UserID})
	if err != nil {
		ycClaimError(c, err)
		return
	}
	c.Data(200, "application/json", out)
}

func (h *Handlers) ycClaimTeam(ctx context.Context, user, team uuid.UUID) (string, error) {
	if h.Pool == nil || user == uuid.Nil || team == uuid.Nil {
		return "", errors.New("team unavailable")
	}
	if err := h.authzService().RequireTeamPermission(ctx, user, team, "billing:write"); err != nil {
		return "", err
	}
	var home string
	err := h.Pool.QueryRow(ctx, "SELECT home_region FROM public.team WHERE id=$1", team).Scan(&home)
	region := ycClaimRegion()
	if err != nil || home != region {
		return "", errors.New("team home is not this region")
	}
	return home, nil
}

func (h *Handlers) BindYCClaim(c *gin.Context) {
	var in ycClaimRequest
	if !decodePromotionRequest(c, &in) {
		return
	}
	if in.ID == uuid.Nil || !validYCToken(in.Token) {
		respondErrorMsg(c, "invalid_confirmation", "Email confirmation required.", 400)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	region, err := h.ycClaimTeam(ctx, in.UserID, in.TeamID)
	if err != nil {
		respondErrorMsg(c, "forbidden", "An authorized team owner or administrator must complete this claim.", 403)
		return
	}
	out, err := h.ycBindWithIntent(ctx, "bind", gin.H{"id": in.ID, "user_id": in.UserID, "team_id": in.TeamID, "home_region": region, "token_hash": ycclaims.Hash(in.Token)})
	if err != nil {
		ycClaimError(c, err)
		return
	}
	c.Data(200, "application/json", out)
}

func (h *Handlers) DecideYCClaim(c *gin.Context) {
	var in struct {
		ID                uuid.UUID `json:"id"`
		UserID            uuid.UUID `json:"user_id"`
		TeamID            uuid.UUID `json:"team_id"`
		Decision          string    `json:"decision"`
		Reason            string    `json:"reason"`
		Evidence          string    `json:"evidence_reference"`
		Company           string    `json:"company_identity"`
		ExistingException bool      `json:"existing_customer_exception"`
	}
	if !decodePromotionRequest(c, &in) {
		return
	}
	actor, err := internalActorID(c)
	if err != nil {
		return
	}
	if actor == uuid.Nil || in.ID == uuid.Nil || (in.Decision != "approve" && in.Decision != "reject" && in.Decision != "revoke" && in.Decision != "retry-email") || strings.TrimSpace(in.Reason) == "" || len(in.Reason) > 1000 || strings.TrimSpace(in.Evidence) == "" || len(in.Evidence) > 1000 {
		respondErrorMsg(c, "invalid_decision", "An audited decision and evidence reference are required.", 400)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	p := gin.H{"id": in.ID, "actor_id": actor, "reason": in.Reason, "evidence_reference": in.Evidence}
	if in.Decision == "approve" {
		region, e := h.ycClaimTeam(ctx, in.UserID, in.TeamID)
		if e != nil {
			respondErrorMsg(c, "forbidden", "Target account must be authorized for its home team.", 403)
			return
		}
		if in.ExistingException && (in.UserID.String() != os.Getenv("YC_EXISTING_EXCEPTION_USER_ID") || in.TeamID.String() != os.Getenv("YC_EXISTING_EXCEPTION_TEAM_ID")) {
			respondErrorMsg(c, "forbidden", "Existing customer exception is not configured for this account and team.", 403)
			return
		}
		p["user_id"], p["team_id"], p["home_region"], p["existing_customer_exception"] = in.UserID, in.TeamID, region, in.ExistingException
		if in.Company != "" {
			identity := ycclaims.CompanyIdentity(in.Company)
			if identity == "" {
				respondErrorMsg(c, "invalid_company", "Canonical YC directory identity required.", 400)
				return
			}
			p["company_identity"] = identity
		}
	}
	var out json.RawMessage
	if in.Decision == "approve" {
		out, err = h.ycBindWithIntent(ctx, in.Decision, p)
	} else {
		p["home_region"] = ycClaimRegion()
		out, err = h.ycClaimRPC(ctx, in.Decision, p)
		if err == nil && (in.Decision == "reject" || in.Decision == "revoke") {
			var current struct {
				Region string    `json:"intent_region"`
				Team   uuid.UUID `json:"intent_team_id"`
			}
			err = json.Unmarshal(out, &current)
			if err == nil && current.Region != "" {
				err = h.ycReleaseClaimIntent(ctx, in.ID, current.Team)
			}
		}
	}
	if err != nil {
		ycClaimError(c, err)
		return
	}
	c.Data(200, "application/json", out)
}

func (h *Handlers) GetOperatorYCClaim(c *gin.Context) {
	id, err := uuid.Parse(c.Param("claim_id"))
	if err != nil {
		respondErrorMsg(c, "invalid_request", "Invalid claim identifier.", 400)
		return
	}
	ctx, cancel := promotionContext(c)
	defer cancel()
	out, err := h.ycClaimRPC(ctx, "operator-get", gin.H{"id": id})
	if err != nil {
		ycClaimError(c, err)
		return
	}
	c.Data(200, "application/json", out)
}

func ycClaimRegion() string {
	region := sandboxIDRegionFromEnv()
	if region == "" {
		return "use"
	}
	return region
}
