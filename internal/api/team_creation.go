package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/getsentry/sentry-go"
	sentrygin "github.com/getsentry/sentry-go/gin"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/rs/zerolog/log"
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
	AuthUpdatedAt string  `json:"auth_updated_at"`
	ObservedAt    string  `json:"observed_at"`
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
	if !utf8.Valid(data) || exactJSONShape(data, reflect.TypeOf(out).Elem()) != nil {
		return errInvalidTeamAssertion
	}
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

// encoding/json accepts case-insensitive field names and null scalar values.
// Check the exact wire schema before allowing its struct decoder to run.
func exactJSONShape(data []byte, kind reflect.Type) error {
	data = bytes.TrimSpace(data)
	if kind.Kind() == reflect.Pointer {
		if kind.Elem().Kind() == reflect.String && bytes.Equal(data, []byte("null")) {
			return nil
		}
		kind = kind.Elem()
	}
	if bytes.Equal(data, []byte("null")) {
		return errInvalidTeamAssertion
	}
	if kind.Kind() == reflect.String && !validTeamCreationJSONString(data) {
		return errInvalidTeamAssertion
	}
	if kind.Kind() != reflect.Struct {
		return nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil {
		return errInvalidTeamAssertion
	}
	for i := 0; i < kind.NumField(); i++ {
		field := kind.Field(i)
		tag := strings.Split(field.Tag.Get("json"), ",")
		value, present := fields[tag[0]]
		if !present {
			if len(tag) == 2 && tag[1] == "omitempty" {
				continue
			}
			return errInvalidTeamAssertion
		}
		if exactJSONShape(value, field.Type) != nil {
			return errInvalidTeamAssertion
		}
		delete(fields, tag[0])
	}
	if len(fields) != 0 {
		return errInvalidTeamAssertion
	}
	return nil
}

// Reject unpaired UTF-16 escapes instead of encoding/json's replacement rune.
func validTeamCreationJSONString(data []byte) bool {
	if len(data) < 2 || data[0] != '"' {
		return false
	}
	for i := 1; i < len(data)-1; i++ {
		if data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data)-1 {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		value, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if value >= 0xDC00 && value <= 0xDFFF {
			return false
		}
		if value >= 0xD800 && value <= 0xDBFF {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if err != nil || low < 0xDC00 || low > 0xDFFF {
				return false
			}
			i += 6
		}
	}
	return true
}

// Fixed microsecond precision preserves Auth revisions exactly in PostgreSQL.
const teamCreationIdentityTimeLayout = "2006-01-02T15:04:05.000000Z"

func parseTeamCreationIdentityTime(raw string) (time.Time, error) {
	value, err := time.Parse(teamCreationIdentityTimeLayout, raw)
	if err != nil || value.Year() < 1970 || value.Format(teamCreationIdentityTimeLayout) != raw {
		return time.Time{}, errInvalidTeamAssertion
	}
	return value, nil
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
	if decodeUniqueJSON(headerData, &header) != nil || header.Algorithm != "EdDSA" || header.Type != "team-creation+jwt" || header.KeyID == "" {
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
	if err != nil || decodeUniqueJSON(payload, &claims) != nil {
		return claims, errInvalidTeamAssertion
	}
	if claims.Version != 1 || claims.Issuer != "superserve-console" || claims.Audience != "superserve-team-creation" || claims.Purpose != "team-creation" ||
		claims.Subject == "" || claims.RequestID == "" || claims.Name == "" || claims.Region == "" {
		return claims, errInvalidTeamAssertion
	}
	if actor, err := uuid.Parse(claims.Subject); err != nil || actor == uuid.Nil || actor.String() != claims.Subject {
		return claims, errInvalidTeamAssertion
	}
	if claims.IssuedAt < 0 || claims.ExpiresAt > 253402300799 || claims.ExpiresAt <= claims.IssuedAt || claims.ExpiresAt-claims.IssuedAt > 120 || claims.IssuedAt > now.Unix()+30 {
		return claims, errInvalidTeamAssertion
	}
	if claims.ExpiresAt < now.Unix()-30 {
		return claims, errExpiredTeamAssertion
	}
	switch claims.Authorization {
	case "create":
		if !validTeamCreationPolicy(claims.Policy) || claims.Identity == nil ||
			(claims.Identity.EmailVerified && claims.Identity.Email == nil) {
			return claims, errTeamPolicy
		}
		if _, err := parseTeamCreationIdentityTime(claims.Identity.AuthUpdatedAt); err != nil {
			return claims, errInvalidTeamAssertion
		}
		if _, err := parseTeamCreationIdentityTime(claims.Identity.ObservedAt); err != nil {
			return claims, errInvalidTeamAssertion
		}
	case "recover":
		if claims.Policy != nil || claims.Identity != nil {
			return claims, errInvalidTeamAssertion
		}
	default:
		return claims, errInvalidTeamAssertion
	}
	return claims, nil
}

// net/http may drain an unread body after even an authentication/rate rejection.
func TeamCreationReadDeadline() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodPost && c.Request.URL.Path == "/internal/teams" {
			err := http.NewResponseController(c.Writer).SetReadDeadline(time.Now().Add(5 * time.Second))
			if err != nil && !errors.Is(err, http.ErrNotSupported) {
				teamCreationError(c, "provisioning_unavailable", "Team provisioning is unavailable", http.StatusServiceUnavailable)
				c.Abort()
				return
			}
		}
		c.Next()
	}
}

// Suppress request capture and panic payloads: both can contain signed identity.
func TeamCreationPrivacy() gin.HandlerFunc {
	return func(c *gin.Context) {
		if hub := sentrygin.GetHubFromContext(c); hub != nil {
			hub.Scope().SetRequestBody(nil)
			hub.Scope().AddEventProcessor(func(event *sentry.Event, _ *sentry.EventHint) *sentry.Event {
				event.Request = nil
				return event
			})
		}
		defer func() {
			if recover() != nil {
				panic("team creation handler panicked")
			}
		}()
		c.Next()
	}
}

func teamCreationError(c *gin.Context, code, message string, status int) {
	log.Warn().Str("code", code).Int("status", status).
		Str("request_id", c.GetString("team_creation_request_id")).Msg("team creation request rejected")
	respondErrorMsg(c, code, message, status)
}

// TeamCreationInternalAuth uses the existing internal credential but maps its
// failure to this endpoint's stable error contract.
func TeamCreationInternalAuth() gin.HandlerFunc {
	token := os.Getenv("INTERNAL_API_TOKEN")
	return func(c *gin.Context) {
		provided := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if token == "" || provided == "" || provided == c.GetHeader("Authorization") || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			teamCreationError(c, "invalid_assertion", "Authentication required", http.StatusUnauthorized)
			c.Abort()
			return
		}
		c.Next()
	}
}

func validTeamCreationVerifierConfig(region string, keys map[string]ed25519.PublicKey) bool {
	if region != "use" && region != "usw" || len(keys) == 0 {
		return false
	}
	for kid, key := range keys {
		if kid == "" || len(kid) > 128 || len(key) != ed25519.PublicKeySize {
			return false
		}
	}
	return true
}

// CreateInternalTeam verifies transport and proof before any persistence access.
func (h *Handlers) CreateInternalTeam(c *gin.Context) {
	h.createInternalTeam(c, time.Now())
}

func (h *Handlers) createInternalTeam(c *gin.Context, now time.Time) {
	if h.Config == nil || !validTeamCreationVerifierConfig(h.Config.TeamCreationRegion, h.Config.TeamCreationKeys) {
		teamCreationError(c, "provisioning_unavailable", "Team provisioning is unavailable", http.StatusServiceUnavailable)
		return
	}
	if c.Request.ContentLength > teamCreationBodyLimit || len(c.GetHeader("X-Team-Creation-Assertion")) > teamCreationAssertionLimit {
		teamCreationError(c, "request_too_large", "Request is too large", http.StatusRequestEntityTooLarge)
		return
	}
	claims, err := verifyTeamCreationAssertion(c.GetHeader("X-Team-Creation-Assertion"), h.Config.TeamCreationKeys, now)
	if err != nil {
		switch err {
		case errExpiredTeamAssertion:
			teamCreationError(c, "assertion_expired", "Assertion expired", http.StatusUnauthorized)
		case errTeamPolicy:
			teamCreationError(c, "policy_not_satisfied", "Creation policy not satisfied", http.StatusForbidden)
		default:
			teamCreationError(c, "invalid_assertion", "Invalid assertion", http.StatusUnauthorized)
		}
		return
	}
	// A context timeout alone cannot interrupt a stalled socket read.
	controller := http.NewResponseController(c.Writer)
	if err := controller.SetReadDeadline(now.Add(5 * time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		teamCreationError(c, "provisioning_unavailable", "Team provisioning is unavailable", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, teamCreationBodyLimit+1))
	if err != nil {
		teamCreationError(c, "invalid_request", "Invalid request", http.StatusBadRequest)
		return
	}
	if len(body) > teamCreationBodyLimit {
		teamCreationError(c, "request_too_large", "Request is too large", http.StatusRequestEntityTooLarge)
		return
	}
	defer controller.SetReadDeadline(time.Time{})
	var input teamCreationInput
	if decodeUniqueJSON(body, &input) != nil || input.Name == "" || input.Name != trimECMAScript(input.Name) ||
		(input.Region != "use" && input.Region != "usw") {
		teamCreationError(c, "invalid_request", "Invalid request", http.StatusBadRequest)
		return
	}

	actor, _ := uuid.Parse(claims.Subject)
	if !validTeamCreationRequestID(input.RequestID, actor, input.Region) {
		teamCreationError(c, "invalid_request", "Invalid request", http.StatusBadRequest)
		return
	}
	if claims.RequestID != input.RequestID || claims.Name != input.Name || claims.Region != input.Region {
		teamCreationError(c, "invalid_assertion", "Invalid assertion", http.StatusUnauthorized)
		return
	}
	if input.Region != h.Config.TeamCreationRegion {
		teamCreationError(c, "wrong_region", "Wrong receiving region", http.StatusConflict)
		return
	}
	c.Set("team_creation_request_id", input.RequestID)
	if h.Pool == nil {
		teamCreationError(c, "provisioning_unavailable", "Team provisioning is unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	var result teamCreationResult
	if claims.Authorization == "recover" {
		result, err = readTeamCreationResult(ctx, h.Pool, actor, input)
	} else {
		result, err = createTeamCreationResult(ctx, h.Pool, actor, input, claims.Identity)
	}
	if err != nil {
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			teamCreationError(c, "result_not_found", "No completed result exists", http.StatusNotFound)
		case errors.Is(err, errTeamCreationConflict):
			teamCreationError(c, "idempotency_conflict", "Request parameters conflict", http.StatusConflict)
		case errors.Is(err, errTeamCreationDeleted):
			teamCreationError(c, "team_deleted", "Created team was deleted", http.StatusGone)
		case errors.Is(err, errTeamCreationIdentityUnavailable):
			teamCreationError(c, "provisioning_unavailable", "Team provisioning is unavailable", http.StatusServiceUnavailable)
		default:
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) {
				log.Error().Str("db_code", pgErr.Code).Str("authorization", claims.Authorization).Msg("team creation database failure")
			} else {
				log.Error().Str("authorization", claims.Authorization).Msg("team creation database failure")
			}
			if isTransientCreateDBErr(err) || errors.Is(err, context.DeadlineExceeded) ||
				(pgErr != nil && (pgErr.Code == "55000" || pgErr.Code == "42P01" || pgErr.Code == "42883" || pgErr.Code == "P0002" || pgErr.Code == "40001" || pgErr.Code == "40P01" || pgErr.Code == "55P03")) {
				teamCreationError(c, "provisioning_unavailable", "Team provisioning is unavailable", http.StatusServiceUnavailable)
			} else {
				teamCreationError(c, "internal_error", "Team provisioning failed", http.StatusInternalServerError)
			}
		}
		return
	}
	outcome := result.Outcome
	if outcome == "" {
		outcome = "existing_result"
	}
	log.Info().Str("request_id", input.RequestID).Str("authorization", claims.Authorization).Str("outcome", outcome).Msg("team creation request completed")
	c.JSON(http.StatusOK, result)
}
