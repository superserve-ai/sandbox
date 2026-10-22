package api

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/ycclaims"
)

type validationMailSender func(context.Context, EmailMessage) error

func (s validationMailSender) SendEmail(ctx context.Context, m EmailMessage) error { return s(ctx, m) }

func TestYCValidationMailNeverFallsBack(t *testing.T) {
	// Sender configuration must not turn unsupported validation into broad mail.
	t.Setenv("YC_EMAIL_API_KEY", "test-provider-key")
	t.Setenv("YC_EMAIL_FROM", "sender@example.test")
	t.Setenv("YC_CONSOLE_URL", "https://console.example.test")
	for _, tc := range []struct {
		name  string
		state ycclaims.CaptureValidation
		claim string
	}{
		{"untagged", ycclaims.CaptureValidation{Requested: true}, uuid.NewString()},
		{"wrong target", ycclaims.CaptureValidation{Requested: true, ExpiresAt: time.Now().Add(time.Hour)}, uuid.NewString()},
		{"missing claim", ycclaims.CaptureValidation{Requested: true, Verifier: ycclaims.VerifyCapture, ExpiresAt: time.Now().Add(time.Hour)}, ""},
		{"malformed claim", ycclaims.CaptureValidation{Requested: true, Verifier: ycclaims.VerifyCapture, ExpiresAt: time.Now().Add(time.Hour)}, "not-a-uuid"},
		{"zero claim", ycclaims.CaptureValidation{Requested: true, Verifier: ycclaims.VerifyCapture, ExpiresAt: time.Now().Add(time.Hour)}, uuid.Nil.String()},
		{"expired", ycclaims.CaptureValidation{Requested: true, Verifier: ycclaims.VerifyCapture, ExpiresAt: time.Now().Add(-time.Second)}, uuid.NewString()},
		{"present empty intent", ycclaims.CaptureValidation{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("YC_STAGING_VALIDATION_CLAIM_ID", tc.claim)
			h := &Handlers{YCClaimValidation: tc.state}
			if scope, validation, err := h.ycValidationMailScope(); scope != nil || !validation || err == nil {
				t.Fatalf("invalid validation fell through: scope=%+v mode=%v err=%v", scope, validation, err)
			}
		})
	}
}

func TestYCScopedApprovalLeaseAndFinish(t *testing.T) {
	claim, message := uuid.New(), uuid.New()
	scope := &ycApprovalMailScope{claimID: claim, expires: time.Now().Add(time.Minute)}
	var lease uuid.UUID
	var calls []string
	rpc := func(ctx context.Context, op string, params any) (json.RawMessage, error) {
		calls = append(calls, op)
		p := params.(map[string]any)
		switch op {
		case "lease-for-claim":
			if p["claim_id"] != claim {
				t.Fatal("unscoped lease")
			}
			lease = p["lease_id"].(uuid.UUID)
			if lease == uuid.Nil {
				t.Fatal("missing lease identity")
			}
			return json.Marshal(ycMailJob{ClaimID: claim, MessageID: message, Email: "customer@example.test"})
		case "finish":
			if ctx.Err() != nil || p["id"] != claim || p["message_id"] != message || p["lease_id"] != lease || p["success"] != true {
				t.Fatal("lost exact finish fence", p)
			}
			return json.RawMessage(`{}`), nil
		default:
			t.Fatal("broad or unexpected operation", op)
			return nil, nil
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	sends := 0
	sender := validationMailSender(func(_ context.Context, m EmailMessage) error {
		sends++
		if m.To != "customer@example.test" || m.IdempotencyKey != "yc-approval/"+message.String() {
			t.Fatal(m)
		}
		// Expiry/cancellation after transport must not suppress acknowledgement.
		scope.expires = time.Now().Add(-time.Second)
		cancel()
		return nil
	})
	if found, err := deliverYCApprovalMail(ctx, rpc, sender, "https://console.example.test", "sender@example.test", scope); !found || err != nil {
		t.Fatal(found, err)
	}
	if sends != 1 || len(calls) != 2 {
		t.Fatal(sends, calls)
	}
	if found, err := deliverYCApprovalMail(t.Context(), rpc, sender, "https://console.example.test", "sender@example.test", scope); found || err == nil || len(calls) != 2 {
		t.Fatal("expired next lease performed work", found, err, calls)
	}
}

func TestYCScopedApprovalOldDatabaseAndWrongClaim(t *testing.T) {
	for _, oldDatabase := range []bool{true, false} {
		scope := &ycApprovalMailScope{claimID: uuid.New(), expires: time.Now().Add(time.Minute)}
		calls, sends := 0, 0
		rpc := func(_ context.Context, op string, p any) (json.RawMessage, error) {
			calls++
			if op != "lease-for-claim" {
				t.Fatal("broad fallback", op)
			}
			if oldDatabase {
				return nil, errors.New("unknown operation")
			}
			return json.Marshal(ycMailJob{ClaimID: uuid.New(), MessageID: uuid.New(), Email: "unrelated@example.test"})
		}
		sender := validationMailSender(func(context.Context, EmailMessage) error { sends++; return nil })
		found, err := deliverYCApprovalMail(t.Context(), rpc, sender, "https://console.example.test", "sender@example.test", scope)
		if found || err == nil || calls != 1 || sends != 0 {
			t.Fatal(found, err, calls, sends)
		}
	}
}

func TestYCOrdinaryApprovalLeaseUnchanged(t *testing.T) {
	calls := 0
	rpc := func(_ context.Context, op string, p any) (json.RawMessage, error) {
		calls++
		if op != "lease" || p.(map[string]any)["claim_id"] != nil {
			t.Fatal(op, p)
		}
		return json.RawMessage(`{}`), nil
	}
	if found, err := deliverYCApprovalMail(t.Context(), rpc, nil, "", "", nil); found || err != nil || calls != 1 {
		t.Fatal(found, err, calls)
	}
}
