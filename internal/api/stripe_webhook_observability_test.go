package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestLogStripeWebhookProcessingFailureClassifiesWrappedErrors(t *testing.T) {
	for _, tc := range []struct {
		name, level, message string
		err                  error
		pending              bool
	}{
		{
			name: "wrapped pending", level: "warn", message: "Stripe checkout association pending",
			err: fmt.Errorf("deferred processing: %w", errStripeCheckoutAssociationPending), pending: true,
		},
		{
			name: "wrapped unrelated", level: "error", message: "process Stripe webhook failed",
			err: fmt.Errorf("processing failed: %w", errors.New("unexpected failure")),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			previousLogger := log.Logger
			log.Logger = zerolog.New(&output)
			t.Cleanup(func() { log.Logger = previousLogger })

			if pending := logStripeWebhookProcessingFailure(tc.err, "evt_example", "customer.subscription.created"); pending != tc.pending {
				t.Fatalf("pending = %t, want %t", pending, tc.pending)
			}
			var entry map[string]any
			if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &entry); err != nil {
				t.Fatalf("decode log entry: %v", err)
			}
			if entry["level"] != tc.level || entry["message"] != tc.message || entry["event_id"] != "evt_example" || entry["event_type"] != "customer.subscription.created" {
				t.Fatalf("log entry = %v", entry)
			}
		})
	}
}

func TestPersistStripeWebhookFailureClassifiesWrappedErrors(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		err        error
	}{
		{
			name: "wrapped pending",
			err:  fmt.Errorf("deferred processing: %w", errStripeCheckoutAssociationPending),
			want: db.StripeCheckoutAssociationPendingError,
		},
		{
			name: "wrapped unrelated",
			err:  fmt.Errorf("processing failed: %w", errors.New("unexpected failure")),
			want: "processing failed: unexpected failure",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			queries := db.New(&mockDBTX{queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
				called = true
				if !strings.Contains(sql, "-- name: MarkStripeWebhookEventFailed") || len(args) != 2 || args[1] != "evt_example" {
					t.Fatalf("unexpected persistence query: %q, %v", sql, args)
				}
				lastError, ok := args[0].(*string)
				if !ok || lastError == nil || *lastError != tc.want {
					t.Fatalf("persisted failure = %v, want %q", args[0], tc.want)
				}
				return &mockRow{scanFn: func(...any) error { return nil }}
			}})
			if err := (&Handlers{}).persistStripeWebhookFailure(context.Background(), queries, "evt_example", tc.err); err != nil {
				t.Fatal(err)
			}
			if !called {
				t.Fatal("failure was not persisted")
			}
		})
	}
}

func TestPersistStripeWebhookFailureVerifiesProcessedState(t *testing.T) {
	writeErr := errors.New("failure write unavailable")
	lookupErr := errors.New("processed state unavailable")
	for _, tc := range []struct {
		name              string
		writeErr, readErr error
		processed         bool
		wantErr           error
	}{
		{name: "recovered", writeErr: pgx.ErrNoRows, processed: true},
		{name: "unprocessed", writeErr: pgx.ErrNoRows, wantErr: pgx.ErrNoRows},
		{name: "missing", writeErr: pgx.ErrNoRows, readErr: pgx.ErrNoRows, wantErr: pgx.ErrNoRows},
		{name: "lookup failure", writeErr: pgx.ErrNoRows, readErr: lookupErr, wantErr: lookupErr},
		{name: "write failure", writeErr: writeErr, processed: true, wantErr: writeErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookedUp := false
			queries := db.New(&mockDBTX{queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
				switch {
				case strings.HasPrefix(sql, "-- name: MarkStripeWebhookEventFailed "):
					return &mockRow{scanFn: func(...any) error { return tc.writeErr }}
				case strings.HasPrefix(sql, "-- name: GetStripeWebhookEvent "):
					lookedUp = true
					if len(args) != 1 || args[0] != "evt_example" {
						t.Fatalf("unexpected lookup arguments: %v", args)
					}
					return &mockRow{scanFn: func(dest ...any) error {
						*(dest[4].(*pgtype.Timestamptz)) = pgtype.Timestamptz{Time: time.Now(), Valid: tc.processed}
						return tc.readErr
					}}
				default:
					t.Fatalf("unexpected query: %s", sql)
					return nil
				}
			}})
			err := (&Handlers{}).persistStripeWebhookFailure(context.Background(), queries, "evt_example", errStripeCheckoutAssociationPending)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("persistence error = %v, want %v", err, tc.wantErr)
			}
			if lookedUp != errors.Is(tc.writeErr, pgx.ErrNoRows) {
				t.Fatalf("processed state lookup = %v", lookedUp)
			}
		})
	}
}

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
