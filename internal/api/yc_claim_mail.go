package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

type ycMailJob struct {
	ClaimID   uuid.UUID `json:"claim_id"`
	MessageID uuid.UUID `json:"message_id"`
	Email     string    `json:"email"`
	Token     string    `json:"token"`
}

func ycConsoleOrigin() (string, error) {
	u, e := url.Parse(os.Getenv("YC_CONSOLE_URL"))
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("YC console origin is not configured")
	}
	return u.Scheme + "://" + u.Host, nil
}

func sendYCClaimMail(ctx context.Context, client *http.Client, endpoint, origin, key, from string, j ycMailJob) error {
	if key == "" || from == "" || !validYCToken(j.Token) || j.ClaimID == uuid.Nil || j.MessageID == uuid.Nil {
		return errors.New("YC email configuration unavailable")
	}
	link := origin + "/yc/confirm#claim=" + j.ClaimID.String() + "&token=" + j.Token
	body, _ := json.Marshal(map[string]any{"from": from, "to": []string{j.Email}, "subject": "Confirm your email for the Superserve YC offer", "text": "Confirm your email address to continue your YC claim:\n\n" + link + "\n\nThis link expires in 24 hours. After confirmation, sign up or sign in using this email and select your authorized team. Eligibility approval does not enable Pro access or issue credits; billing activation and a payment method are separate steps. If you did not request this, ignore this email."})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "yc-claim/"+j.MessageID.String())
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("YC email transport failed")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("YC email provider status %d", resp.StatusCode)
	}
	return nil
}

// Durable leases and provider idempotency allow every replica to poll safely.
// Provider I/O stays outside database transactions and signup requests.
func (h *Handlers) StartYCClaimMail(ctx context.Context) {
	if h.PromotionAuthPool == nil {
		return
	}
	origin, err := ycConsoleOrigin()
	key, from := os.Getenv("YC_EMAIL_API_KEY"), os.Getenv("YC_EMAIL_FROM")
	if err != nil || key == "" || from == "" {
		log.Warn().Msg("YC confirmation mail disabled; configure console origin and email provider before enabling claim capture")
		return
	}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
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
				lease := uuid.New()
				raw, e := h.ycClaimRPC(jobctx, "mail-lease", map[string]any{"lease_id": lease})
				var j ycMailJob
				if e != nil || json.Unmarshal(raw, &j) != nil {
					cancel()
					log.Warn().Msg("YC confirmation mail queue unavailable")
					break
				}
				if j.ClaimID == uuid.Nil {
					cancel()
					break
				}
				e = sendYCClaimMail(jobctx, client, resendEmailEndpoint, origin, key, from, j)
				_, ack := h.ycClaimRPC(jobctx, "mail-finish", map[string]any{"id": j.ClaimID, "lease_id": lease, "success": e == nil})
				cancel()
				if e != nil || ack != nil {
					log.Warn().Str("claim_id", j.ClaimID.String()).Msg("YC confirmation delivery pending retry or operator review")
				}
			}
		}
	}()
}
