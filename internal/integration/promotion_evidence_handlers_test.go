//go:build integration

package integration

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/api"
)

func TestIntegration_PromotionEvidenceHandlers(t *testing.T) {
	auth := promotionIsolatedDatabase(t, false)
	east := promotionIsolatedDatabase(t, true)
	west := promotionIsolatedDatabase(t, true)
	config := auth.Config().Copy()
	config.ConnConfig.RuntimeParams["role"] = "promotion_evidence_proxy"
	proxy, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proxy.Close)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PROMOTION_ACCOUNT_PUBLIC_KEY", base64.StdEncoding.EncodeToString(public))
	t.Setenv("PROMOTION_CAPTURE_TOKEN", "capture-example-token")
	t.Setenv("PROMOTION_ACCOUNT_TOKEN", "account-example-token")
	t.Setenv("INTERNAL_API_TOKEN", "internal-example-token")
	newRouter := func(source, region *pgxpool.Pool) http.Handler {
		return api.SetupRouter(t.Context(), &api.Handlers{PromotionAuthPool: source, Pool: region}, region)
	}
	eastRouter, westRouter := newRouter(proxy, east), newRouter(proxy, west)
	marshal := func(value any) string {
		t.Helper()
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	request := func(t *testing.T, router http.Handler, operation, body string, user, signedAttempt uuid.UUID, status int, result string) *httptest.ResponseRecorder {
		t.Helper()
		path, token := "/internal/promotion/account/"+operation, "account-example-token"
		if operation == "attempts" || operation == "verify" {
			path, token = "/internal/promotion/signup/attempts", "capture-example-token"
			if operation == "verify" {
				path += "/verify"
			}
		}
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		if token == "account-example-token" {
			claims := jwt.MapClaims{
				"iss": "promotion-auth-adapter", "aud": "promotion-account", "sub": user.String(),
				"iat": time.Now().Add(-time.Second).Unix(), "exp": time.Now().Add(time.Minute).Unix(),
				"operation": operation,
			}
			if operation == "bind" {
				claims["attempt_id"] = signedAttempt.String()
			}
			assertion, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(private)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("X-Actor-User-Id", user.String())
			req.Header.Set("X-Promotion-Account-Assertion", assertion)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != status {
			t.Fatalf("%s: status=%d want=%d body=%s", operation, w.Code, status, w.Body.String())
		}
		var response struct {
			Outcome string `json:"outcome"`
			Error   struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if status == http.StatusOK && response.Outcome != result || status != http.StatusOK && response.Error.Code != result {
			t.Fatalf("%s: want result %q, body=%s", operation, result, w.Body.String())
		}
		return w
	}
	create := func(t *testing.T) (uuid.UUID, uuid.UUID) {
		t.Helper()
		w := request(t, eastRouter, "attempts", "", uuid.Nil, uuid.Nil, http.StatusOK, "")
		var response struct {
			Attempt   uuid.UUID `json:"attempt_id"`
			Challenge uuid.UUID `json:"challenge"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		var storedChallenge uuid.UUID
		if err := auth.QueryRow(t.Context(), `SELECT challenge FROM signup_device_attempt WHERE attempt_id=$1`, response.Attempt).Scan(&storedChallenge); err != nil || response.Attempt == uuid.Nil || response.Challenge == uuid.Nil || response.Challenge != storedChallenge {
			t.Fatalf("attempt was not persisted: response=%+v stored=%v err=%v", response, storedChallenge, err)
		}
		return response.Attempt, response.Challenge
	}
	verifyBody := func(attempt, challenge uuid.UUID, event, fingerprint string, eventAt time.Time) string {
		return marshal(map[string]any{"attempt_id": attempt, "challenge": challenge, "event_id": event, "fingerprint": fingerprint, "event_at": eventAt})
	}
	accountBody := func(user, attempt uuid.UUID) string {
		body := map[string]any{"user_id": user}
		if attempt != uuid.Nil {
			body["attempt_id"] = attempt
		}
		return marshal(body)
	}

	t.Run("durable evidence and independent regional registration", func(t *testing.T) {
		fingerprint := "Visitor-MixedCase-" + uuid.NewString()
		users := []uuid.UUID{uuid.New(), uuid.New()}
		attempts := make([]uuid.UUID, len(users))
		events := make([]string, len(users))
		for i, user := range users {
			attempt, challenge := create(t)
			attempts[i], events[i] = attempt, "Event-"+uuid.NewString()
			var eventAt time.Time
			if err := auth.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&eventAt); err != nil {
				t.Fatal(err)
			}
			body := verifyBody(attempt, challenge, events[i], fingerprint, eventAt)
			request(t, eastRouter, "verify", verifyBody(attempt, uuid.New(), events[i], fingerprint, eventAt), uuid.Nil, uuid.Nil, 400, "invalid_evidence")
			request(t, eastRouter, "verify", body, uuid.Nil, uuid.Nil, 200, "verified")
			request(t, eastRouter, "verify", body, uuid.Nil, uuid.Nil, 200, "replayed")
			request(t, eastRouter, "verify", verifyBody(attempt, challenge, events[i], "replacement", eventAt), uuid.Nil, uuid.Nil, 409, "evidence_conflict")
			request(t, eastRouter, "evidence", accountBody(user, uuid.Nil), user, uuid.Nil, 404, "evidence_missing")
			request(t, eastRouter, "bind", accountBody(user, attempt), user, attempt, 400, "invalid_evidence")
			rolloutExec(t, auth, `INSERT INTO auth.users(id,created_at) VALUES($1,clock_timestamp())`, user)
			request(t, eastRouter, "bind", accountBody(user, attempt), users[1-i], attempt, 403, "forbidden")
			request(t, eastRouter, "bind", accountBody(user, attempt), user, uuid.New(), 403, "forbidden")
			request(t, eastRouter, "bind", accountBody(user, attempt), user, attempt, 200, "bound")
			request(t, eastRouter, "bind", accountBody(user, attempt), user, attempt, 200, "replayed")
			w := request(t, westRouter, "evidence", accountBody(user, uuid.Nil), user, uuid.Nil, 200, "")
			var evidence struct {
				Attempt     uuid.UUID `json:"attempt_id"`
				Event       string    `json:"event_id"`
				Fingerprint string    `json:"fingerprint"`
				EventAt     time.Time `json:"event_at"`
				BoundAt     time.Time `json:"bound_at"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &evidence); err != nil {
				t.Fatal(err)
			}
			if evidence.Attempt != attempt || evidence.Event != events[i] || evidence.Fingerprint != fingerprint || !evidence.EventAt.Equal(eventAt) || evidence.BoundAt.IsZero() {
				t.Fatalf("retrieval changed original evidence: %+v", evidence)
			}
		}
		request(t, eastRouter, "bind", accountBody(users[1], attempts[0]), users[1], attempts[0], 409, "evidence_conflict")
		for _, region := range []struct {
			router http.Handler
			pool   *pgxpool.Pool
			first  int
		}{{eastRouter, east, 0}, {westRouter, west, 1}} {
			for _, i := range []int{region.first, 1 - region.first, region.first, 1 - region.first} {
				outcome := "owner_conflict"
				if i == region.first {
					outcome = "owner"
				}
				w := request(t, region.router, "register", accountBody(users[i], uuid.Nil), users[i], uuid.Nil, 200, outcome)
				if strings.Contains(w.Body.String(), fingerprint) || strings.Contains(w.Body.String(), users[region.first].String()) {
					t.Fatal("registration disclosed fingerprint or owner identity")
				}
				var attempt uuid.UUID
				var event, storedFingerprint string
				if err := region.pool.QueryRow(t.Context(), `SELECT source_attempt_id,source_event_id,fingerprint FROM promotion_signup_device_evidence WHERE user_id=$1`, users[i]).Scan(&attempt, &event, &storedFingerprint); err != nil || attempt != attempts[i] || event != events[i] || storedFingerprint != fingerprint {
					t.Fatalf("regional evidence differs from shared source: %v %q %q err=%v", attempt, event, storedFingerprint, err)
				}
			}
			var owner uuid.UUID
			if err := region.pool.QueryRow(t.Context(), `SELECT user_id FROM promotion_device_owner WHERE fingerprint=$1`, fingerprint).Scan(&owner); err != nil || owner != users[region.first] {
				t.Fatalf("regional owner=%v err=%v", owner, err)
			}
		}
	})

	t.Run("bounded and malformed input", func(t *testing.T) {
		user := uuid.New()
		attempt, challenge := create(t)
		var before int
		if err := auth.QueryRow(t.Context(), `SELECT count(*) FROM signup_device_attempt`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		for _, operation := range []string{"attempts", "verify", "bind", "evidence", "register"} {
			valid := accountBody(user, uuid.Nil)
			if operation == "bind" {
				valid = accountBody(user, attempt)
			} else if operation == "verify" {
				valid = verifyBody(attempt, challenge, "event", "visitor", time.Now().UTC())
			} else if operation == "attempts" {
				valid = ""
			}
			for _, tc := range []struct{ name, body string }{
				{"malformed", "{"},
				{"unknown field", `{"unexpected":true}`},
				{"trailing JSON", valid + ` {}`},
				{"oversized", valid + strings.Repeat(" ", 4097)},
			} {
				t.Run(operation+"/"+tc.name, func(t *testing.T) {
					request(t, eastRouter, operation, tc.body, user, attempt, 400, "invalid_request")
				})
			}
		}
		for _, field := range []string{"event_id", "fingerprint"} {
			for _, size := range []int{0, 257} {
				body := map[string]any{"attempt_id": attempt, "challenge": challenge, "event_id": "event", "fingerprint": "visitor", "event_at": time.Now().UTC()}
				body[field] = strings.Repeat("x", size)
				request(t, eastRouter, "verify", marshal(body), uuid.Nil, uuid.Nil, 400, "invalid_request")
			}
		}
		for _, operation := range []string{"evidence", "register"} {
			request(t, eastRouter, operation, accountBody(user, attempt), user, uuid.Nil, 400, "invalid_request")
			request(t, eastRouter, operation, marshal(map[string]any{"user_id": user, "fingerprint": "forged"}), user, uuid.Nil, 400, "invalid_request")
		}
		var after, verified, bindings, regionalEvidence int
		if err := auth.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM signup_device_attempt),
			(SELECT count(*) FROM signup_device_attempt WHERE attempt_id=$1 AND verified_at IS NOT NULL),
			(SELECT count(*) FROM signup_device_account_evidence WHERE user_id=$2)`, attempt, user).Scan(&after, &verified, &bindings); err != nil {
			t.Fatal(err)
		}
		if err := east.QueryRow(t.Context(), `SELECT count(*) FROM promotion_signup_device_evidence WHERE user_id=$1`, user).Scan(&regionalEvidence); err != nil {
			t.Fatal(err)
		}
		if before != after || verified != 0 || bindings != 0 || regionalEvidence != 0 {
			t.Fatalf("invalid input persisted state: attempts=%d->%d verified=%d bindings=%d regional=%d", before, after, verified, bindings, regionalEvidence)
		}
		body := verifyBody(attempt, challenge, strings.Repeat("E", 256), strings.Repeat("F", 256), time.Now().UTC())
		body += strings.Repeat(" ", 4096-len(body))
		request(t, eastRouter, "verify", body, uuid.Nil, uuid.Nil, 200, "verified")
	})

	t.Run("missing evidence and unavailable authority", func(t *testing.T) {
		user := uuid.New()
		proof := promotionVerifiedSignup(t, auth, user, "visitor-"+uuid.NewString())
		closed, err := pgxpool.NewWithConfig(t.Context(), proxy.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		closed.Close()
		for _, source := range []*pgxpool.Pool{nil, closed} {
			router := newRouter(source, east)
			for _, operation := range []string{"attempts", "verify", "bind", "evidence", "register"} {
				body := accountBody(user, uuid.Nil)
				if operation == "bind" {
					body = accountBody(user, proof.attempt)
				} else if operation == "verify" {
					body = verifyBody(uuid.New(), uuid.New(), "event", "visitor", time.Now().UTC())
				} else if operation == "attempts" {
					body = ""
				}
				request(t, router, operation, body, user, proof.attempt, 503, "authority_unavailable")
			}
		}
		for _, region := range []*pgxpool.Pool{nil, closed} {
			request(t, newRouter(proxy, region), "register", accountBody(user, uuid.Nil), user, uuid.Nil, 503, "authority_unavailable")
		}
		missing := uuid.New()
		for _, operation := range []string{"evidence", "register"} {
			request(t, eastRouter, operation, accountBody(missing, uuid.Nil), missing, uuid.Nil, 404, "evidence_missing")
		}
		var count int
		if err := east.QueryRow(t.Context(), `SELECT count(*) FROM promotion_signup_device_evidence WHERE user_id IN ($1,$2)`, user, missing).Scan(&count); err != nil || count != 0 {
			t.Fatalf("failed registration persisted evidence: count=%d err=%v", count, err)
		}
	})
}
