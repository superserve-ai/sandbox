package api

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type qmKeyIdentity struct {
	KeyID, TeamID, OwnerID uuid.UUID
	Name                   string
}
type qmIdentityAuthority interface {
	Resolve(context.Context, string) (qmKeyIdentity, error)
	Allowed(context.Context, uuid.UUID, uuid.UUID, string) (bool, error)
}
type qmAuthority struct{ h *Handlers }

func (a qmAuthority) Resolve(ctx context.Context, key string) (qmKeyIdentity, error) {
	var out qmKeyIdentity
	var owner pgtype.UUID
	sum := sha256.Sum256([]byte(key))
	err := a.h.Pool.QueryRow(ctx, `SELECT id,team_id,created_by,name FROM api_key
 WHERE key_hash=$1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>now())`, hex.EncodeToString(sum[:])).Scan(&out.KeyID, &out.TeamID, &owner, &out.Name)
	if owner.Valid {
		out.OwnerID = uuid.UUID(owner.Bytes)
	}
	return out, err
}
func (a qmAuthority) Allowed(ctx context.Context, actor, team uuid.UUID, permission string) (bool, error) {
	if a.h.authzService() == nil {
		return false, errors.New("authorization unavailable")
	}
	return a.h.authzService().CanTeam(ctx, actor, team, permission)
}

type qmAuthorization struct {
	ActorType         string `json:"actor_type"`
	ActorID           string `json:"actor_id"`
	CredentialID      string `json:"credential_id"`
	UserID            string `json:"user_id,omitempty"`
	TeamID            string `json:"team_id"`
	OwnerID           string `json:"owner_id"`
	AuthOutcome       string `json:"auth_outcome"`
	AttributionStatus string `json:"attribution_status"`
	Allowed           bool   `json:"allowed"`
}
type qmHumanClaims struct {
	jwt.RegisteredClaims
	TeamID       string `json:"team_id"`
	CredentialID string `json:"credential_id"`
	Action       string `json:"action"`
}

// The optional console proof binds a separately authenticated human to the
// presented credential, team and action. A key creator alone proves no human.
func qmHuman(raw string, key ed25519.PublicKey, identity qmKeyIdentity, action string) (uuid.UUID, error) {
	if len(key) != ed25519.PublicKeySize || len(raw) > 8192 {
		return uuid.Nil, errors.New("invalid assertion")
	}
	claims := new(qmHumanClaims)
	_, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) { return key, nil }, jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer("console-auth-adapter"), jwt.WithAudience("qm-management"), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	subject, e := uuid.Parse(claims.Subject)
	if err != nil || e != nil || subject == uuid.Nil || claims.IssuedAt == nil || claims.ExpiresAt == nil || !claims.ExpiresAt.After(claims.IssuedAt.Time) || claims.ExpiresAt.Sub(claims.IssuedAt.Time) > time.Minute || claims.TeamID != identity.TeamID.String() || claims.CredentialID != identity.KeyID.String() || claims.Action != action {
		return uuid.Nil, errors.New("invalid assertion")
	}
	return subject, nil
}
func qmAuthorizationHandler(authority qmIdentityAuthority, serviceToken string, humanKey ed25519.PublicKey) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		defer func() {
			if recover() != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "authorization_unavailable"})
			}
		}()
		token := c.GetHeader("X-QM-Service-Token")
		key := c.GetHeader("X-API-Key")
		assertion := c.GetHeader("X-QM-Human-Assertion")
		c.Request.Header.Del("X-QM-Service-Token")
		c.Request.Header.Del("X-API-Key")
		c.Request.Header.Del("X-QM-Human-Assertion")
		// A service credential is distinct from any user's key and is never treated
		// as authorization to a team. Missing service configuration fails closed.
		if len(serviceToken) < 32 || len(token) > 4096 || subtle.ConstantTimeCompare([]byte(token), []byte(serviceToken)) != 1 {
			c.AbortWithStatusJSON(503, gin.H{"error": "service_authentication_failed"})
			return
		}
		if key == "" || len(key) > 4096 {
			c.AbortWithStatusJSON(401, gin.H{"error": "invalid_credentials"})
			return
		}
		var input struct {
			Action string `json:"action"`
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1024)
		decoder := json.NewDecoder(c.Request.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
			c.AbortWithStatusJSON(400, gin.H{"error": "invalid_request"})
			return
		}
		permission := "settings:write"
		switch input.Action {
		case "read":
			permission = "settings:read"
		case "write", "admin-link":
		default:
			c.AbortWithStatusJSON(400, gin.H{"error": "invalid_action"})
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 4*time.Second)
		defer cancel()
		identity, err := authority.Resolve(ctx, key)
		if errors.Is(err, pgx.ErrNoRows) {
			c.AbortWithStatusJSON(401, gin.H{"error": "invalid_credentials"})
			return
		}
		if err != nil {
			c.AbortWithStatusJSON(503, gin.H{"error": "authentication_unavailable"})
			return
		}
		if identity.KeyID == uuid.Nil || identity.TeamID == uuid.Nil || identity.OwnerID == uuid.Nil {
			c.AbortWithStatusJSON(503, gin.H{"error": "identity_unavailable"})
			return
		}
		decision := qmAuthorization{ActorType: "api_key", ActorID: identity.KeyID.String(), CredentialID: identity.KeyID.String(), TeamID: identity.TeamID.String(), OwnerID: identity.OwnerID.String(), AuthOutcome: "authenticated", AttributionStatus: "identified"}
		actor := identity.OwnerID
		if assertion != "" {
			human, e := qmHuman(assertion, humanKey, identity, input.Action)
			if e != nil {
				c.AbortWithStatusJSON(401, gin.H{"error": "invalid_human_assertion"})
				return
			}
			decision.ActorType = "human"
			decision.ActorID = human.String()
			decision.UserID = human.String()
			actor = human
		}
		// Preserve the existing prohibition on ordinary RBAC use of impersonation keys.
		if identity.Name != consoleImpersonationKeyName {
			decision.Allowed, err = authority.Allowed(ctx, identity.OwnerID, identity.TeamID, permission)
			if err == nil && decision.Allowed && actor != identity.OwnerID {
				decision.Allowed, err = authority.Allowed(ctx, actor, identity.TeamID, permission)
			}
		}
		if err != nil {
			c.AbortWithStatusJSON(503, gin.H{"error": "authorization_unavailable"})
			return
		}
		// Denials return the same verified identity; Allowed is the authorization result.
		c.JSON(http.StatusOK, decision)
	}
}
func (h *Handlers) QMAuthHandler() gin.HandlerFunc {
	key, _ := base64.StdEncoding.DecodeString(os.Getenv("QM_HUMAN_ASSERTION_PUBLIC_KEY"))
	return qmAuthorizationHandler(qmAuthority{h}, os.Getenv("QM_AUTH_SERVICE_TOKEN"), ed25519.PublicKey(key))
}
