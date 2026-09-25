package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	sentrygin "github.com/getsentry/sentry-go/gin"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const promotionRequestLimit = 4096

type promotionAccountRequest struct {
	UserID    uuid.UUID `json:"user_id"`
	AttemptID uuid.UUID `json:"attempt_id"`
}

func decodePromotionRequest(c *gin.Context, dst any) bool {
	if hub := sentrygin.GetHubFromContext(c); hub != nil {
		hub.Scope().SetRequestBody(nil)
	}
	if c.Request.Body == nil {
		respondErrorMsg(c, "invalid_request", "invalid promotion request", http.StatusBadRequest)
		return false
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, promotionRequestLimit)
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		respondErrorMsg(c, "invalid_request", "invalid promotion request", http.StatusBadRequest)
		return false
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		respondErrorMsg(c, "invalid_request", "invalid promotion request", http.StatusBadRequest)
		return false
	}
	return true
}

func promotionContext(c *gin.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(c.Request.Context(), 3*time.Second)
}

func promotionSource(c *gin.Context, pool *pgxpool.Pool) bool {
	if pool == nil {
		respondErrorMsg(c, "authority_unavailable", "promotion evidence source unavailable", http.StatusServiceUnavailable)
		return false
	}
	return true
}

func promotionDBError(c *gin.Context, err error) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "22023":
			respondErrorMsg(c, "invalid_evidence", "invalid signup evidence", http.StatusBadRequest)
			return
		case "23505":
			respondErrorMsg(c, "evidence_conflict", "signup evidence already used", http.StatusConflict)
			return
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		respondErrorMsg(c, "evidence_missing", "signup evidence unavailable", http.StatusNotFound)
		return
	}
	respondErrorMsg(c, "authority_unavailable", "promotion authority unavailable", http.StatusServiceUnavailable)
}

// The capture credential authorizes creation and provider-attested verification.
func (h *Handlers) CreatePromotionSignupAttempt(c *gin.Context) {
	if !promotionSource(c, h.PromotionAuthPool) {
		return
	}
	if hub := sentrygin.GetHubFromContext(c); hub != nil {
		hub.Scope().SetRequestBody(nil)
	}
	if c.Request.Body != nil {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, promotionRequestLimit)
		if err := json.NewDecoder(c.Request.Body).Decode(new(any)); err != io.EOF {
			respondErrorMsg(c, "invalid_request", "invalid promotion request", http.StatusBadRequest)
			return
		}
	}
	ctx, cancel := promotionContext(c)
	defer cancel()
	var attempt, challenge uuid.UUID
	if err := h.PromotionAuthPool.QueryRow(ctx, "select attempt_id, challenge from public.create_signup_device_attempt()").Scan(&attempt, &challenge); err != nil {
		promotionDBError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"attempt_id": attempt, "challenge": challenge})
}

func (h *Handlers) VerifyPromotionSignupAttempt(c *gin.Context) {
	if !promotionSource(c, h.PromotionAuthPool) {
		return
	}
	var input struct {
		AttemptID   uuid.UUID `json:"attempt_id"`
		Challenge   uuid.UUID `json:"challenge"`
		EventID     string    `json:"event_id"`
		Fingerprint string    `json:"fingerprint"`
		EventAt     time.Time `json:"event_at"`
	}
	if !decodePromotionRequest(c, &input) {
		return
	}
	if input.AttemptID == uuid.Nil || input.Challenge == uuid.Nil || len(input.EventID) < 1 || len(input.EventID) > 256 || len(input.Fingerprint) < 1 || len(input.Fingerprint) > 256 || input.EventAt.IsZero() {
		respondErrorMsg(c, "invalid_request", "invalid promotion request", http.StatusBadRequest)
		return
	}
	ctx, cancel := promotionContext(c)
	defer cancel()
	var outcome string
	if err := h.PromotionAuthPool.QueryRow(ctx, "select public.verify_signup_device_attempt($1,$2,$3,$4,$5)", input.AttemptID, input.Challenge, input.EventID, input.Fingerprint, input.EventAt).Scan(&outcome); err != nil {
		promotionDBError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"outcome": outcome})
}

func promotionAccountActor(c *gin.Context, userID uuid.UUID) bool {
	actor, err := uuid.Parse(c.GetHeader("X-Actor-User-Id"))
	if err != nil || userID == uuid.Nil || actor != userID {
		respondErrorMsg(c, "forbidden", "account provenance mismatch", http.StatusForbidden)
		return false
	}
	return true
}

func (h *Handlers) BindPromotionSignupAccount(c *gin.Context) {
	if !promotionSource(c, h.PromotionAuthPool) {
		return
	}
	var input promotionAccountRequest
	if !decodePromotionRequest(c, &input) || !promotionAccountActor(c, input.UserID) {
		return
	}
	if input.AttemptID == uuid.Nil {
		respondErrorMsg(c, "invalid_request", "invalid promotion request", http.StatusBadRequest)
		return
	}
	ctx, cancel := promotionContext(c)
	defer cancel()
	var outcome string
	if err := h.PromotionAuthPool.QueryRow(ctx, "select public.bind_signup_device_account($1,$2)", input.AttemptID, input.UserID).Scan(&outcome); err != nil {
		promotionDBError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"outcome": outcome})
}

type promotionEvidence struct {
	AttemptID   uuid.UUID `json:"attempt_id"`
	EventID     string    `json:"event_id"`
	Fingerprint string    `json:"fingerprint"`
	EventAt     time.Time `json:"event_at"`
	BoundAt     time.Time `json:"bound_at"`
}

func (h *Handlers) lookupPromotionEvidence(ctx context.Context, userID uuid.UUID) (promotionEvidence, error) {
	var evidence promotionEvidence
	err := h.PromotionAuthPool.QueryRow(ctx, "select attempt_id,event_id,fingerprint,event_at,bound_at from public.get_signup_device_account_evidence($1)", userID).Scan(&evidence.AttemptID, &evidence.EventID, &evidence.Fingerprint, &evidence.EventAt, &evidence.BoundAt)
	return evidence, err
}

func (h *Handlers) GetPromotionSignupAccountEvidence(c *gin.Context) {
	if !promotionSource(c, h.PromotionAuthPool) {
		return
	}
	var input promotionAccountRequest
	if !decodePromotionRequest(c, &input) || !promotionAccountActor(c, input.UserID) {
		return
	}
	if input.AttemptID != uuid.Nil {
		respondErrorMsg(c, "invalid_request", "invalid promotion request", http.StatusBadRequest)
		return
	}
	ctx, cancel := promotionContext(c)
	defer cancel()
	evidence, err := h.lookupPromotionEvidence(ctx, input.UserID)
	if err != nil {
		promotionDBError(c, err)
		return
	}
	c.JSON(http.StatusOK, evidence)
}

func (h *Handlers) RegisterPromotionSignupDevice(c *gin.Context) {
	if !promotionSource(c, h.PromotionAuthPool) || !promotionSource(c, h.Pool) {
		return
	}
	var input promotionAccountRequest
	if !decodePromotionRequest(c, &input) || !promotionAccountActor(c, input.UserID) {
		return
	}
	if input.AttemptID != uuid.Nil {
		respondErrorMsg(c, "invalid_request", "invalid promotion request", http.StatusBadRequest)
		return
	}
	ctx, cancel := promotionContext(c)
	defer cancel()
	evidence, err := h.lookupPromotionEvidence(ctx, input.UserID)
	if err != nil {
		promotionDBError(c, err)
		return
	}
	var outcome string
	if err := h.Pool.QueryRow(ctx, "select register_promotion_signup_device($1,$2,$3,$4)", input.UserID, evidence.AttemptID, evidence.EventID, evidence.Fingerprint).Scan(&outcome); err != nil {
		promotionDBError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"outcome": outcome})
}
