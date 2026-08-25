package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestHandleStripeWebhookLogsNotOwnedRoutingDecision(t *testing.T) {
	now := time.Date(2026, 8, 22, 18, 0, 0, 0, time.UTC)
	teamID := uuid.New()

	payload, err := json.Marshal(map[string]any{
		"id":      "evt_not_owned_log",
		"type":    "checkout.session.completed",
		"created": now.Unix(),
		"data": map[string]any{
			"object": map[string]any{
				"client_reference_id": teamID.String(),
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal webhook payload: %v", err)
	}

	var buf bytes.Buffer
	oldLogger := log.Logger
	log.Logger = zerolog.New(&buf).Level(zerolog.InfoLevel)
	t.Cleanup(func() {
		log.Logger = oldLogger
	})

	h := &Handlers{
		Config: &config.Config{StripeWebhookSecret: "whsec_snapshot"},
		Now:    func() time.Time { return now },
		Pool:   &pgxpool.Pool{},
		DB: db.New(&mockDBTX{
			queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
				if strings.Contains(sql, "FROM team WHERE id = $1") {
					return &mockRow{scanFn: func(dest ...any) error { return pgx.ErrNoRows }}
				}
				return &mockRow{scanFn: func(dest ...any) error {
					return pgx.ErrNoRows
				}}
			},
			execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
				t.Fatalf("unexpected billing mutation for not_owned webhook")
				return pgconn.CommandTag{}, nil
			},
		}),
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/stripe/webhook", h.HandleStripeWebhook)

	req := httptest.NewRequest(http.MethodPost, "/stripe/webhook", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", stripeWebhookTestSignature(payload, now, "whsec_snapshot"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"status":"ignored"`) {
		t.Fatalf("response body = %q, want ignored status", w.Body.String())
	}

	out := buf.String()
	for _, want := range []string{
		`"routing_decision":"not_owned"`,
		`"event_id":"evt_not_owned_log"`,
		`"event_type":"checkout.session.completed"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("log output %q missing %q", out, want)
		}
	}
}
