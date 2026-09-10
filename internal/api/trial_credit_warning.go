package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

func dedupeWarningRecipients(addresses []string) []string {
	seen := make(map[string]struct{}, len(addresses))
	out := make([]string, 0, len(addresses))
	for _, address := range addresses {
		if address == "" {
			continue
		}
		if _, ok := seen[address]; ok {
			continue
		}
		seen[address] = struct{}{}
		out = append(out, address)
	}
	return out
}

func trialCreditWarningHTML(teamName string, remaining float64) string {
	return fmt.Sprintf("<h1>Less than 24 hours of trial credit remaining</h1><p>Based on your recent usage, your trial credit may run out within the next 24 hours.</p><p>Team: %s</p><p>Remaining trial credit: $%.2f</p>", teamName, remaining)
}

const trialCreditWarningTimeout = 30 * time.Second

// Keep advisory work bounded independently of the reconciliation batch size.
// A full scan must remain able to finish even when delivery is slow.
var trialCreditWarningSlots = make(chan struct{}, 32)

type trialCreditWarningJob struct {
	h      *Handlers
	ctx    context.Context
	teamID uuid.UUID
}

var (
	trialCreditWarningQueue   = make(chan trialCreditWarningJob, 256)
	trialCreditWarningWorkers sync.Once
)

func startTrialCreditWarningWorkers() {
	trialCreditWarningWorkers.Do(func() {
		for i := 0; i < cap(trialCreditWarningSlots); i++ {
			go func() {
				for job := range trialCreditWarningQueue {
					job.h.processTrialCreditWarning(job.ctx, job.teamID)
					job.h.asyncMu.Lock()
					job.h.asyncCount--
					if job.h.asyncCount == 0 && job.h.asyncCond != nil {
						job.h.asyncCond.Broadcast()
					}
					job.h.asyncMu.Unlock()
				}
			}()
		}
	})
}

type TrialCreditWarningSender interface {
	SendTrialCreditWarning(context.Context, uuid.UUID, float64) error
}

// trialCreditWarningIdempotentSender binds provider deduplication to the
// durable claim. This closes the acceptance/complete window without changing
// the existing sender contract used by tests and alternate senders.
type trialCreditWarningIdempotentSender interface {
	SendTrialCreditWarningWithKey(context.Context, uuid.UUID, float64, uuid.UUID) error
}

// ResendTrialCreditWarningSender delivers the warning to all current billing
// recipients without exposing addresses to one another.
type ResendTrialCreditWarningSender struct {
	apiKey, from string
	queries      *db.Queries
	endpoint     string
	client       *http.Client
}

func NewResendTrialCreditWarningSender(apiKey, from string, queries *db.Queries) *ResendTrialCreditWarningSender {
	return &ResendTrialCreditWarningSender{apiKey: apiKey, from: from, queries: queries, endpoint: resendEmailEndpoint, client: &http.Client{Timeout: 10 * time.Second}}
}
func (s *ResendTrialCreditWarningSender) SendTrialCreditWarning(ctx context.Context, teamID uuid.UUID, remaining float64) error {
	return s.sendTrialCreditWarning(ctx, teamID, remaining, uuid.Nil)
}

func (s *ResendTrialCreditWarningSender) SendTrialCreditWarningWithKey(ctx context.Context, teamID uuid.UUID, remaining float64, claimToken uuid.UUID) error {
	return s.sendTrialCreditWarning(ctx, teamID, remaining, claimToken)
}

func (s *ResendTrialCreditWarningSender) sendTrialCreditWarning(ctx context.Context, teamID uuid.UUID, remaining float64, claimToken uuid.UUID) error {
	if s == nil || s.apiKey == "" || s.from == "" || s.queries == nil {
		// A missing provider configuration is a delivery failure, not a
		// successful no-op. Returning nil here would mark the durable warning
		// state as sent even though Resend never accepted a message.
		return errors.New("trial credit warning provider is not configured")
	}
	recipients, err := s.queries.ListTrialCreditWarningRecipients(ctx, teamID)
	if err != nil {
		return err
	}
	recipients = dedupeWarningRecipients(recipients)
	if len(recipients) == 0 {
		return nil
	}
	team, err := s.queries.GetTeam(ctx, teamID)
	if err != nil {
		return err
	}
	// Submit one message per recipient. Resend's `to` array is rendered as a
	// shared To header, which would disclose other billing members' addresses.
	for i, recipient := range recipients {
		payload, _ := json.Marshal(map[string]any{"from": s.from, "to": recipient, "subject": "Your trial credit may run out soon", "html": trialCreditWarningHTML(team.Name, remaining)})
		// Each recipient is a distinct provider request. Include its stable
		// position in the claim-scoped idempotency key so Resend does not
		// collapse the fan-out into a single message while retries remain
		// deduplicated for that recipient.
		if err := s.sendEmailWithKey(ctx, payload, claimToken, i); err != nil {
			return err
		}
	}
	return nil
}

func (s *ResendTrialCreditWarningSender) sendEmail(ctx context.Context, payload []byte) error {
	return s.sendEmailWithKey(ctx, payload, uuid.Nil, 0)
}

func (s *ResendTrialCreditWarningSender) sendEmailWithKey(ctx context.Context, payload []byte, claimToken uuid.UUID, recipientIndex int) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/json")
	if claimToken != uuid.Nil {
		req.Header.Set("Idempotency-Key", fmt.Sprintf("trial-credit-warning/%s/%d", claimToken, recipientIndex))
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return &unknownTrialCreditWarningError{err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("resend returned %d: %s", resp.StatusCode, string(body))
}

// UnknownTrialCreditWarningOutcome indicates that delivery may have been
// accepted despite the returned error (for example, a timeout after submit).
// Such claims are terminal to preserve at-most-once delivery.
type UnknownTrialCreditWarningOutcome interface{ UnknownTrialCreditWarning() bool }

// Transport failures after submission have an unknown outcome: the provider
// may have accepted the message before the connection failed. Keep the claim
// terminal instead of releasing it for an automatic duplicate send.
type unknownTrialCreditWarningError struct{ err error }

func (e *unknownTrialCreditWarningError) Error() string                   { return e.err.Error() }
func (e *unknownTrialCreditWarningError) Unwrap() error                   { return e.err }
func (e *unknownTrialCreditWarningError) UnknownTrialCreditWarning() bool { return true }

func tryDispatchTrialCreditWarning(h *Handlers, ctx context.Context, teamID uuid.UUID) bool {
	startTrialCreditWarningWorkers()
	h.asyncMu.Lock()
	h.asyncCount++
	h.asyncMu.Unlock()
	select {
	case trialCreditWarningQueue <- trialCreditWarningJob{h: h, ctx: ctx, teamID: teamID}:
		return true
	case <-ctx.Done():
		h.asyncMu.Lock()
		h.asyncCount--
		if h.asyncCount == 0 && h.asyncCond != nil {
			h.asyncCond.Broadcast()
		}
		h.asyncMu.Unlock()
		return false
	default:
		// Advisory work is dropped when the bounded queue is full; the next
		// reconciliation pass will retry without extending its critical path.
		h.asyncMu.Lock()
		h.asyncCount--
		if h.asyncCount == 0 && h.asyncCond != nil {
			h.asyncCond.Broadcast()
		}
		h.asyncMu.Unlock()
		return false
	}
}

func (h *Handlers) processTrialCreditWarning(ctx context.Context, teamID uuid.UUID) {
	if h.DB == nil || h.TrialWarningSender == nil {
		return
	}
	// Provider calls are advisory and must not pin one of the bounded worker
	// slots indefinitely when the remote service or network stalls.
	workCtx, cancel := context.WithTimeout(ctx, trialCreditWarningTimeout)
	defer cancel()
	ctx = workCtx
	b, err := h.DB.GetTeamTrialBalance(ctx, teamID)
	if err != nil || !trialCreditWarningLifecycleEligible(b.Eligible, b.State) {
		return
	}
	remaining, err := numericFloat(b.RemainingUsd)
	if err != nil {
		return
	}
	s, err := h.DB.GetRecentTrialBurnSample(ctx, teamID)
	if err != nil {
		return
	}
	started, ok1 := s.StartedAt.(time.Time)
	ended, ok2 := s.EndedAt.(time.Time)
	if !ok1 || !ok2 {
		return
	}
	spent, err := numericFloat(s.SpentUsd)
	elapsedSeconds, elapsedErr := numericFloat(s.ElapsedSeconds)
	if elapsedErr != nil || elapsedSeconds <= 0 {
		return
	}
	if err != nil || !trialCreditWarningEligible(remaining, time.Now(), trialBurnSample{SpentUSD: spent, Started: started, Ended: ended, ElapsedSeconds: elapsedSeconds}) {
		return
	}
	claimToken, err := h.DB.ClaimTrialCreditWarning(ctx, teamID)
	if err != nil {
		return
	}
	// Claiming is deliberately separate from the balance read. Re-read the
	// authoritative trial state immediately before provider submission so an
	// expiry, exhaustion, or Stripe transition racing the forecast cannot emit
	// a warning for a no-longer-active trial.
	latest, err := h.DB.GetTeamTrialBalance(ctx, teamID)
	if err != nil || !trialCreditWarningLifecycleEligible(latest.Eligible, latest.State) {
		_ = h.DB.ReleaseTrialCreditWarning(ctx, db.ReleaseTrialCreditWarningParams{TeamID: teamID, ClaimToken: claimToken})
		return
	}
	latestRemaining, err := numericFloat(latest.RemainingUsd)
	if err != nil || latestRemaining <= 0 {
		_ = h.DB.ReleaseTrialCreditWarning(ctx, db.ReleaseTrialCreditWarningParams{TeamID: teamID, ClaimToken: claimToken})
		return
	}
	remaining = latestRemaining
	if err = sendTrialCreditWarningIfEligible(latest.Eligible, latest.State, func() error {
		if sender, ok := h.TrialWarningSender.(trialCreditWarningIdempotentSender); ok {
			return sender.SendTrialCreditWarningWithKey(ctx, teamID, remaining, uuid.UUID(claimToken.Bytes))
		}
		return h.TrialWarningSender.SendTrialCreditWarning(ctx, teamID, remaining)
	}); err != nil {
		var unknown UnknownTrialCreditWarningOutcome
		if errors.As(err, &unknown) && unknown.UnknownTrialCreditWarning() {
			_ = h.DB.MarkTrialCreditWarningUnknown(ctx, db.MarkTrialCreditWarningUnknownParams{TeamID: teamID, ClaimToken: claimToken})
		} else {
			_ = h.DB.ReleaseTrialCreditWarning(ctx, db.ReleaseTrialCreditWarningParams{TeamID: teamID, ClaimToken: claimToken})
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("trial credit warning send failed")
		return
	}
	_ = h.DB.CompleteTrialCreditWarning(ctx, db.CompleteTrialCreditWarningParams{TeamID: teamID, ClaimToken: claimToken})
}

// Keep the final lifecycle gate adjacent to delivery so an exhausted or
// Stripe-ended trial can never invoke the provider, even if state changes
// after the claim is acquired.
func sendTrialCreditWarningIfEligible(eligible bool, state string, send func() error) error {
	if !trialCreditWarningLifecycleEligible(eligible, state) {
		return nil
	}
	return send()
}

func trialCreditWarningLifecycleEligible(eligible bool, state string) bool {
	return eligible && state == "active"
}

func numericFloat(n pgtype.Numeric) (float64, error) {
	v, err := n.Float64Value()
	if err != nil {
		return 0, err
	}
	if !v.Valid {
		return 0, errors.New("numeric value is null")
	}
	return v.Float64, nil
}

// trialBurnSample is intentionally small: warning delivery is advisory and
// must not add work to request or enforcement paths.
type trialBurnSample struct {
	SpentUSD       float64
	Started        time.Time
	Ended          time.Time
	ElapsedSeconds float64
}

// trialCreditWarningEligible returns true only for a meaningful, recent
// sample whose wall-clock rate predicts strictly under 24 hours remaining.
// Concurrent runtime is deliberately not part of the denominator.
func trialCreditWarningEligible(remainingUSD float64, now time.Time, sample trialBurnSample) bool {
	if remainingUSD <= 0 || sample.SpentUSD <= 0 || sample.Ended.Before(sample.Started) {
		return false
	}
	// A sample older than six hours is too stale to support an advisory
	// forecast; skipping it also bounds work for teams with sparse usage.
	if !sample.Ended.After(now.Add(-6*time.Hour)) || sample.Ended.After(now.Add(5*time.Minute)) {
		return false
	}
	elapsed := sample.Ended.Sub(sample.Started)
	if elapsed < 5*time.Minute {
		return false
	}
	rate := sample.SpentUSD / elapsed.Hours()
	return rate > 0 && remainingUSD/rate < 24
}
