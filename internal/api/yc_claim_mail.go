package api

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
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

func (h *Handlers) ycConsoleOrigin() (string, error) {
	u, e := url.Parse(os.Getenv("YC_CONSOLE_URL"))
	if e != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("YC console origin is not configured")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && h.ycLocalMailConfigured() && ycLoopbackOrigin(u)) {
		return "", errors.New("YC console origin is not configured")
	}
	return u.Scheme + "://" + u.Host, nil
}

// Local HTTP links require both a loopback API bind and the selected local SMTP
// transport. These are configuration prerequisites, not a devbox identity check.
func (h *Handlers) ycLocalMailConfigured() bool {
	if h.Config == nil || !net.ParseIP(h.Config.Host).IsLoopback() {
		return false
	}
	host, port, err := net.SplitHostPort(h.EmailTransport.SMTPAddr)
	n, portErr := strconv.Atoi(port)
	return err == nil && portErr == nil && n > 0 && n <= 65535 &&
		(host == "localhost" || net.ParseIP(host).IsLoopback())
}

func ycLoopbackOrigin(u *url.URL) bool {
	host := u.Hostname()
	if host != "localhost" && host != "127.0.0.1" && host != "::1" {
		return false
	}
	if u.RawPath != "" || u.ForceQuery {
		return false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		return err == nil && n > 0 && n <= 65535 && u.Host == net.JoinHostPort(host, port)
	}
	if host == "::1" {
		return u.Host == "[::1]"
	}
	return u.Host == host
}

func sendYCClaimMail(ctx context.Context, sender EmailSender, origin, from string, j ycMailJob) error {
	if sender == nil || from == "" || !validYCToken(j.Token) || j.ClaimID == uuid.Nil || j.MessageID == uuid.Nil {
		return errors.New("YC email configuration unavailable")
	}
	link := origin + "/yc/confirm#claim=" + j.ClaimID.String() + "&token=" + j.Token
	return sender.SendEmail(ctx, EmailMessage{
		From:           from,
		To:             j.Email,
		Subject:        "Confirm your email for the Superserve YC offer",
		Text:           "Confirm your email address to continue your YC claim:\n\n" + link + "\n\nThis link expires in 24 hours. After confirmation, sign up or sign in using this email and select your authorized team. Eligibility approval does not enable Pro access or issue credits; review and acceptance of the offer are separate steps. No card is required for eligible new YC signups. If you did not request this, ignore this email.",
		IdempotencyKey: "yc-claim/" + j.MessageID.String(),
	})
}

// Durable leases and provider idempotency allow every replica to poll safely.
// Provider I/O stays outside database transactions and signup requests.
func (h *Handlers) StartYCClaimMail(ctx context.Context) {
	if h.PromotionAuthPool == nil {
		return
	}
	h.startYCApprovalMonitoring(ctx)
	origin, err := h.ycConsoleOrigin()
	sender, from := h.EmailTransport.Sender(os.Getenv("YC_EMAIL_API_KEY")), os.Getenv("YC_EMAIL_FROM")
	if err != nil || sender == nil || from == "" {
		log.Warn().Msg("YC claim mail disabled; configure console origin and email provider before enabling claim capture")
		return
	}
	h.startYCApprovalMail(ctx, sender, origin, from)
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
				e = sendYCClaimMail(jobctx, sender, origin, from, j)
				_, ack := h.ycClaimRPC(jobctx, "mail-finish", map[string]any{"id": j.ClaimID, "lease_id": lease, "success": e == nil})
				cancel()
				if e != nil || ack != nil {
					log.Warn().Str("claim_id", j.ClaimID.String()).Msg("YC confirmation delivery pending retry or operator review")
				}
			}
		}
	}()
}
