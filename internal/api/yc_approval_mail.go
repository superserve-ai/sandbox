package api

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

func sendYCApprovalMail(ctx context.Context, sender EmailSender, origin, from string, j ycMailJob) error {
	if sender == nil || from == "" || j.Email == "" || j.ClaimID == uuid.Nil || j.MessageID == uuid.Nil {
		return errors.New("YC approval email configuration unavailable")
	}
	return sender.SendEmail(ctx, EmailMessage{
		From: from, To: j.Email, Subject: "Your Superserve YC offer is approved",
		Text:           "Your YC eligibility has been approved. Sign in with the approved signup email to review and accept your offer:\n\n" + origin + "/yc/accept?claim=" + j.ClaimID.String() + "\n\nApproval does not accept the offer or activate billing. No card is required for eligible new YC signups. This link does not grant access; your current account and approval will be checked when you sign in.",
		IdempotencyKey: "yc-approval/" + j.MessageID.String(),
	})
}

func (h *Handlers) ycApprovalMailRPC(ctx context.Context, op string, p any) (json.RawMessage, error) {
	if h.PromotionAuthPool == nil {
		return nil, errors.New("shared claim authority unavailable")
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	var out json.RawMessage
	err = h.PromotionAuthPool.QueryRow(ctx, "SELECT public.yc_claim_approval_mail_rpc($1,$2::jsonb)", op, b).Scan(&out)
	return out, err
}

func (h *Handlers) deliverYCApprovalMail(ctx context.Context, sender EmailSender, origin, from string) (bool, error) {
	lease := uuid.New()
	raw, err := h.ycApprovalMailRPC(ctx, "lease", map[string]any{"lease_id": lease})
	if err != nil {
		return false, err
	}
	var j ycMailJob
	if err = json.Unmarshal(raw, &j); err != nil {
		return false, err
	}
	if j.ClaimID == uuid.Nil {
		return false, nil
	}
	deliveryErr := sendYCApprovalMail(ctx, sender, origin, from, j)
	var unknown *unknownEmailOutcomeError
	var rejected *rejectedEmailError
	// A fresh bounded acknowledgement context survives the send timeout. If it
	// also fails, the pre-dispatch unknown state requires an audited retry.
	ackctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	_, ackErr := h.ycApprovalMailRPC(ackctx, "finish", map[string]any{"id": j.ClaimID, "message_id": j.MessageID, "lease_id": lease, "success": deliveryErr == nil, "unknown": errors.As(deliveryErr, &unknown), "rejected": errors.As(deliveryErr, &rejected)})
	return true, errors.Join(deliveryErr, ackErr)
}

func (h *Handlers) startYCApprovalMail(ctx context.Context, sender EmailSender, origin, from string) {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			for range 4 {
				jobctx, cancel := context.WithTimeout(ctx, 15*time.Second)
				found, err := h.deliverYCApprovalMail(jobctx, sender, origin, from)
				cancel()
				if err != nil {
					log.Warn().Msg("YC approval notification pending retry or operator review")
					break
				}
				if !found {
					break
				}
			}
		}
	}()
}

// A negative count means the latest observation failed, never a healthy zero.
func (h *Handlers) observeYCApprovalBacklog(ctx context.Context) error {
	raw, err := h.ycApprovalMailRPC(ctx, "backlog", map[string]any{})
	var sample struct {
		Count  int64   `json:"count"`
		Oldest float64 `json:"oldest_seconds"`
	}
	if err == nil {
		err = json.Unmarshal(raw, &sample)
	}
	if err != nil {
		currentBillingRecorder().RecordBillingBacklog(ctx, "yc_approval_notification", -1, 0)
		return err
	}
	currentBillingRecorder().RecordBillingBacklog(ctx, "yc_approval_notification", sample.Count, sample.Oldest)
	return nil
}

func (h *Handlers) startYCApprovalMonitoring(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			sample, cancel := context.WithTimeout(ctx, 3*time.Second)
			err := h.observeYCApprovalBacklog(sample)
			cancel()
			if err != nil {
				log.Warn().Msg("YC approval notification backlog observation unavailable")
			}
		}
	}()
}
