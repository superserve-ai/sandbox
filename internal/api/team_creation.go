package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const teamCreationBodyLimit = 16 << 10
const teamCreationAssertionLimit = 8 << 10

type teamCreationInput struct {
	RequestID string `json:"request_id"`
	Name      string `json:"name"`
	Region    string `json:"region"`
}

type teamCreationPolicy struct {
	Version          int    `json:"version"`
	Mode             string `json:"mode"`
	Session          string `json:"session"`
	Captcha          string `json:"captcha"`
	Preauth          string `json:"preauth"`
	GoogleOnboarding string `json:"google_onboarding"`
	AdditionalTeam   string `json:"additional_team"`
}

type teamCreationIdentity struct {
	Email         *string `json:"email"`
	EmailVerified bool    `json:"email_verified"`
}

type teamCreationClaims struct {
	Version       int                   `json:"v"`
	Issuer        string                `json:"iss"`
	Audience      string                `json:"aud"`
	Purpose       string                `json:"purpose"`
	Subject       string                `json:"sub"`
	IssuedAt      int64                 `json:"iat"`
	ExpiresAt     int64                 `json:"exp"`
	RequestID     string                `json:"request_id"`
	Name          string                `json:"name"`
	Region        string                `json:"region"`
	Authorization string                `json:"authorization"`
	Policy        *teamCreationPolicy   `json:"policy,omitempty"`
	Identity      *teamCreationIdentity `json:"identity,omitempty"`
}

var errInvalidTeamAssertion = errors.New("invalid team creation assertion")
var errExpiredTeamAssertion = errors.New("expired team creation assertion")
var errTeamPolicy = errors.New("team creation policy not satisfied")

// Strict decoding rejects duplicate keys at every depth, including proof metadata.
func decodeUniqueJSON(data []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := checkUniqueJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errInvalidTeamAssertion
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errInvalidTeamAssertion
	}
	return nil
}

func checkUniqueJSONValue(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	start, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch start {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			keyToken, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return errInvalidTeamAssertion
			}
			seen[key] = true
			if err := checkUniqueJSONValue(d); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := checkUniqueJSONValue(d); err != nil {
				return err
			}
		}
	default:
		return errInvalidTeamAssertion
	}
	_, err = d.Token()
	return err
}

func validTeamCreationRequestID(raw string, actor uuid.UUID, region string) bool {
	if id, err := uuid.Parse(raw); err == nil && id.Version() == 4 && raw == id.String() {
		return true
	}
	return raw == "onboarding-v1:"+actor.String()+":"+region
}

func trimECMAScript(raw string) string {
	return strings.TrimFunc(raw, func(r rune) bool {
		return r == '\t' || r == '\n' || r == '\v' || r == '\f' || r == '\r' ||
			r == ' ' || r == '\u00a0' || r == '\u1680' ||
			(r >= '\u2000' && r <= '\u200a') || r == '\u2028' || r == '\u2029' ||
			r == '\u202f' || r == '\u205f' || r == '\u3000' || r == '\uFEFF'
	})
}

func hasJSONFields(data []byte, fields ...string) bool {
	var values map[string]json.RawMessage
	if json.Unmarshal(data, &values) != nil {
		return false
	}
	for _, field := range fields {
		if _, ok := values[field]; !ok {
			return false
		}
	}
	return true
}

func validTeamCreationPolicy(policy *teamCreationPolicy) bool {
	if policy == nil || policy.Version != 1 || policy.Session != "passed" {
		return false
	}
	if policy.Mode == "first_team" {
		return policy.Captcha == "passed" && policy.Preauth == "passed" &&
			(policy.GoogleOnboarding == "passed" || policy.GoogleOnboarding == "not_applicable") &&
			policy.AdditionalTeam == "not_applicable"
	}
	return policy.Mode == "additional_team" && policy.AdditionalTeam == "passed" &&
		policy.Captcha == "not_applicable" && policy.Preauth == "not_applicable" &&
		policy.GoogleOnboarding == "not_applicable"
}

func verifyTeamCreationAssertion(raw string, keys map[string]ed25519.PublicKey, now time.Time) (teamCreationClaims, error) {
	var claims teamCreationClaims
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || len(raw) > teamCreationAssertionLimit {
		return claims, errInvalidTeamAssertion
	}
	decode := base64.RawURLEncoding.Strict().DecodeString
	headerData, err := decode(parts[0])
	if err != nil {
		return claims, errInvalidTeamAssertion
	}
	var header struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
		KeyID     string `json:"kid"`
	}
	if decodeUniqueJSON(headerData, &header) != nil || !hasJSONFields(headerData, "alg", "typ", "kid") || header.Algorithm != "EdDSA" || header.Type != "team-creation+jwt" || header.KeyID == "" {
		return claims, errInvalidTeamAssertion
	}
	key := keys[header.KeyID]
	if len(key) != ed25519.PublicKeySize {
		return claims, errInvalidTeamAssertion
	}
	sig, err := decode(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return claims, errInvalidTeamAssertion
	}
	payload, err := decode(parts[1])
	if err != nil || decodeUniqueJSON(payload, &claims) != nil || !hasJSONFields(payload, "v", "iss", "aud", "purpose", "sub", "iat", "exp", "request_id", "name", "region", "authorization") {
		return claims, errInvalidTeamAssertion
	}
	if claims.Version != 1 || claims.Issuer != "superserve-console" || claims.Audience != "superserve-team-creation" || claims.Purpose != "team-creation" ||
		claims.Subject == "" || claims.RequestID == "" || claims.Name == "" || claims.Region == "" {
		return claims, errInvalidTeamAssertion
	}
	if _, err := uuid.Parse(claims.Subject); err != nil {
		return claims, errInvalidTeamAssertion
	}
	if claims.ExpiresAt <= claims.IssuedAt || claims.ExpiresAt-claims.IssuedAt > 120 || claims.IssuedAt > now.Unix()+30 {
		return claims, errInvalidTeamAssertion
	}
	if claims.ExpiresAt < now.Unix()-30 {
		return claims, errExpiredTeamAssertion
	}
	switch claims.Authorization {
	case "create":
		var objects map[string]json.RawMessage
		_ = json.Unmarshal(payload, &objects)
		if !hasJSONFields(objects["policy"], "version", "mode", "session", "captcha", "preauth", "google_onboarding", "additional_team") ||
			!hasJSONFields(objects["identity"], "email", "email_verified") || !validTeamCreationPolicy(claims.Policy) || claims.Identity == nil ||
			(claims.Identity.EmailVerified && claims.Identity.Email == nil) {
			return claims, errTeamPolicy
		}
	case "recover":
		var objects map[string]json.RawMessage
		_ = json.Unmarshal(payload, &objects)
		_, hasPolicy := objects["policy"]
		_, hasIdentity := objects["identity"]
		if hasPolicy || hasIdentity {
			return claims, errInvalidTeamAssertion
		}
	default:
		return claims, errInvalidTeamAssertion
	}
	return claims, nil
}

// TeamCreationInternalAuth uses the existing internal credential but maps its
// failure to this endpoint's stable error contract.
func TeamCreationInternalAuth() gin.HandlerFunc {
	token := os.Getenv("INTERNAL_API_TOKEN")
	return func(c *gin.Context) {
		provided := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if token == "" || provided == "" || provided == c.GetHeader("Authorization") || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			respondErrorMsg(c, "invalid_assertion", "Authentication required", http.StatusUnauthorized)
			c.Abort()
			return
		}
		c.Next()
	}
}

// CreateInternalTeam verifies transport and proof before any persistence access.
// Creation remains closed until the promotion authority accepts a canonical identity.
func (h *Handlers) CreateInternalTeam(c *gin.Context) {
	if h.Config == nil || (h.Config.TeamCreationRegion != "use" && h.Config.TeamCreationRegion != "usw") || len(h.Config.TeamCreationKeys) == 0 {
		respondErrorMsg(c, "provisioning_unavailable", "Team provisioning is unavailable", http.StatusServiceUnavailable)
		return
	}
	if c.Request.ContentLength > teamCreationBodyLimit || len(c.GetHeader("X-Team-Creation-Assertion")) > teamCreationAssertionLimit {
		respondErrorMsg(c, "request_too_large", "Request is too large", http.StatusRequestEntityTooLarge)
		return
	}
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, teamCreationBodyLimit+1))
	if err != nil {
		respondErrorMsg(c, "invalid_request", "Invalid request", http.StatusBadRequest)
		return
	}
	if len(body) > teamCreationBodyLimit {
		respondErrorMsg(c, "request_too_large", "Request is too large", http.StatusRequestEntityTooLarge)
		return
	}
	var input teamCreationInput
	if decodeUniqueJSON(body, &input) != nil || !hasJSONFields(body, "request_id", "name", "region") || input.Name == "" || input.Name != trimECMAScript(input.Name) ||
		(input.Region != "use" && input.Region != "usw") {
		respondErrorMsg(c, "invalid_request", "Invalid request", http.StatusBadRequest)
		return
	}
	claims, err := verifyTeamCreationAssertion(c.GetHeader("X-Team-Creation-Assertion"), h.Config.TeamCreationKeys, time.Now())
	if err != nil {
		switch err {
		case errExpiredTeamAssertion:
			respondErrorMsg(c, "assertion_expired", "Assertion expired", http.StatusUnauthorized)
		case errTeamPolicy:
			respondErrorMsg(c, "policy_not_satisfied", "Creation policy not satisfied", http.StatusForbidden)
		default:
			respondErrorMsg(c, "invalid_assertion", "Invalid assertion", http.StatusUnauthorized)
		}
		return
	}
	actor, _ := uuid.Parse(claims.Subject)
	if !validTeamCreationRequestID(input.RequestID, actor, input.Region) {
		respondErrorMsg(c, "invalid_request", "Invalid request", http.StatusBadRequest)
		return
	}
	if claims.RequestID != input.RequestID || claims.Name != input.Name || claims.Region != input.Region {
		respondErrorMsg(c, "invalid_assertion", "Invalid assertion", http.StatusUnauthorized)
		return
	}
	if input.Region != h.Config.TeamCreationRegion {
		respondErrorMsg(c, "wrong_region", "Wrong receiving region", http.StatusConflict)
		return
	}
	respondErrorMsg(c, "provisioning_unavailable", "Team provisioning is unavailable", http.StatusServiceUnavailable)
}
