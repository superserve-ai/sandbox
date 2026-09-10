package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
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
	return fmt.Sprintf("<h1>Less than 24 hours of trial credit remaining</h1><p>Based on your recent usage, your trial credit may run out within the next 24 hours.</p><p>Team: %s</p><p>Remaining trial credit: $%.2f</p>", html.EscapeString(teamName), remaining)
}

const trialCreditWarningTimeout = 30 * time.Second

const trialCreditWarningConcurrency = 2

type trialCreditWarningAdmission struct {
	mu     sync.Mutex
	active int32
}

func (a *trialCreditWarningAdmission) tryAcquire(maxConns, acquiredConns int32) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Reserve at least half the configured pool for non-warning work. Count
	// admitted jobs against spare capacity even while they are between queries.
	limit := min(int32(trialCreditWarningConcurrency), maxConns/2, maxConns-acquiredConns-1)
	if a.active >= limit {
		return false
	}
	a.active++
	return true
}

func (a *trialCreditWarningAdmission) release() {
	a.mu.Lock()
	a.active--
	a.mu.Unlock()
}

var trialCreditWarningAdmissions trialCreditWarningAdmission

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
		for i := 0; i < trialCreditWarningConcurrency; i++ {
			go func() {
				for job := range trialCreditWarningQueue {
					job.h.processTrialCreditWarningWithCapacity(job.ctx, job.teamID)
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

func (h *Handlers) processTrialCreditWarningWithCapacity(ctx context.Context, teamID uuid.UUID) {
	if h.Pool == nil {
		return
	}
	stats := h.Pool.Stat()
	if !trialCreditWarningAdmissions.tryAcquire(stats.MaxConns(), stats.AcquiredConns()) {
		return
	}
	defer trialCreditWarningAdmissions.release()
	h.processTrialCreditWarning(ctx, teamID)
}

type TrialCreditWarningSender interface {
	SendTrialCreditWarning(context.Context, uuid.UUID, float64) error
}

// trialCreditWarningIdempotentSender passes the durable claim token used to
// fence recipient progress writes and identify provider requests.
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
	if claimToken == uuid.Nil {
		return errors.New("trial credit warning delivery requires a durable claim")
	}
	delivered, err := s.queries.ListTrialCreditWarningDeliveries(ctx, teamID)
	if err != nil {
		return err
	}
	resolved := make(map[string]bool, len(delivered))
	for _, recipient := range delivered {
		resolved[recipient] = true
	}
	rejected, err := s.queries.ListTrialCreditWarningRejections(ctx, teamID)
	if err != nil {
		return err
	}
	for _, recipient := range rejected {
		resolved[recipient] = true
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
	for _, recipient := range recipients {
		if resolved[recipient] {
			continue
		}
		payload, _ := json.Marshal(map[string]any{"from": s.from, "to": recipient, "subject": "Your trial credit may run out soon", "html": trialCreditWarningHTML(team.Name, remaining)})
		// Provider identity uses the recipient, independent of list order.
		// Persisted recipient outcomes suppress repeats across new claims.
		if err := s.sendEmailWithKey(ctx, payload, claimToken, recipient); err != nil {
			var permanent *permanentTrialCreditWarningError
			if !errors.As(err, &permanent) {
				return err
			}
			rows, recordErr := s.queries.RecordTrialCreditWarningRejection(ctx, db.RecordTrialCreditWarningRejectionParams{
				TeamID: teamID, Recipient: recipient, ClaimToken: pgtype.UUID{Bytes: claimToken, Valid: true},
			})
			if recordErr != nil {
				return &unknownTrialCreditWarningError{err: fmt.Errorf("record trial warning rejection: %w", recordErr)}
			}
			if rows != 1 {
				return &unknownTrialCreditWarningError{err: errors.New("trial warning rejection claim no longer current")}
			}
			log.Warn().Err(err).Str("team_id", teamID.String()).Msg("trial credit warning recipient permanently rejected; not retrying")
			continue
		}
		rows, err := s.queries.RecordTrialCreditWarningDelivery(ctx, db.RecordTrialCreditWarningDeliveryParams{
			TeamID: teamID, Recipient: recipient, ClaimToken: pgtype.UUID{Bytes: claimToken, Valid: true},
		})
		// Acceptance without durable progress must never release the claim:
		// a later attempt could otherwise resend this recipient's message.
		if err != nil {
			return &unknownTrialCreditWarningError{err: fmt.Errorf("record trial warning delivery: %w", err)}
		}
		if rows != 1 {
			return &unknownTrialCreditWarningError{err: errors.New("trial warning delivery claim no longer current")}
		}
	}
	return nil
}

func (s *ResendTrialCreditWarningSender) sendEmail(ctx context.Context, payload []byte) error {
	return s.sendEmailWithKey(ctx, payload, uuid.Nil, "")
}

func (s *ResendTrialCreditWarningSender) sendEmailWithKey(ctx context.Context, payload []byte, claimToken uuid.UUID, recipient string) error {
	var gettingConn, gotConn atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GetConn: func(string) { gettingConn.Store(true) },
		GotConn: func(httptrace.GotConnInfo) { gotConn.Store(true) },
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/json")
	if claimToken != uuid.Nil {
		req.Header.Set("Idempotency-Key", fmt.Sprintf("trial-credit-warning/%s/%x", claimToken, sha256.Sum256([]byte(recipient))))
	}
	resp, err := s.client.Do(req)
	if err != nil {
		// Failure to obtain a connection (including DNS, dial, and TLS)
		// precedes submission. Once connected, even a partial write may
		// have reached the provider. Untraced transports remain ambiguous.
		if gettingConn.Load() && !gotConn.Load() {
			return err
		}
		return &unknownTrialCreditWarningError{err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	var providerError struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(body, &providerError)
	err = fmt.Errorf("resend returned %d (%s)", resp.StatusCode, providerError.Name)
	// Keep recoverable provider configuration errors retryable, as in the quota notifier.
	if resp.StatusCode >= 400 && resp.StatusCode < 500 &&
		resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden &&
		resp.StatusCode != http.StatusTooManyRequests && providerError.Name != "invalid_from_address" {
		return &permanentTrialCreditWarningError{err: err}
	}
	return err
}

type permanentTrialCreditWarningError struct{ err error }

func (e *permanentTrialCreditWarningError) Error() string { return e.err.Error() }
func (e *permanentTrialCreditWarningError) Unwrap() error { return e.err }

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

// Resume after the last accepted UUID on overflow so a stable scan order
// cannot repeatedly fill the queue with the same prefix. Only one cursor is
// retained; the existing eligibility sweep supplies the remaining teams.
type trialCreditWarningPass struct {
	after uuid.UUID
	last  uuid.UUID
	full  bool
}

func (h *Handlers) beginTrialCreditWarningPass() *trialCreditWarningPass {
	h.asyncMu.Lock()
	defer h.asyncMu.Unlock()
	return &trialCreditWarningPass{after: h.trialWarningAfter, last: h.trialWarningAfter}
}

func (h *Handlers) finishTrialCreditWarningPass(pass *trialCreditWarningPass, complete bool) {
	h.asyncMu.Lock()
	defer h.asyncMu.Unlock()
	if complete && !pass.full {
		h.trialWarningAfter = uuid.Nil
	} else {
		h.trialWarningAfter = pass.last
	}
}

func (pass *trialCreditWarningPass) dispatch(h *Handlers, ctx context.Context, teamID uuid.UUID, queue chan<- trialCreditWarningJob) bool {
	if pass.full || bytes.Compare(teamID[:], pass.after[:]) <= 0 {
		return false
	}
	if ctx.Err() != nil {
		pass.full = true
		return false
	}
	// Hold the bookkeeping lock until admission is known. Failed enqueue
	// attempts must neither leak counts nor strand a waiter at zero.
	h.asyncMu.Lock()
	defer h.asyncMu.Unlock()
	select {
	case queue <- trialCreditWarningJob{h: h, ctx: ctx, teamID: teamID}:
		h.asyncCount++
		pass.last = teamID
		return true
	default:
		pass.full = true
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
	sample := trialBurnSample{SpentUSD: spent, Started: started, Ended: ended, ElapsedSeconds: elapsedSeconds}
	if err != nil || !trialCreditWarningEligible(remaining, time.Now(), sample) {
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
		h.releaseTrialCreditWarning(teamID, claimToken)
		return
	}
	latestRemaining, err := numericFloat(latest.RemainingUsd)
	if err != nil || !trialCreditWarningEligible(latestRemaining, time.Now(), sample) {
		h.releaseTrialCreditWarning(teamID, claimToken)
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
			h.releaseTrialCreditWarning(teamID, claimToken)
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("trial credit warning send failed")
		return
	}
	_ = h.DB.CompleteTrialCreditWarning(ctx, db.CompleteTrialCreditWarningParams{TeamID: teamID, ClaimToken: claimToken})
}

func (h *Handlers) releaseTrialCreditWarning(teamID uuid.UUID, claimToken pgtype.UUID) {
	// Definitive failures must remain retryable even after the work context expires.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.DB.ReleaseTrialCreditWarning(ctx, db.ReleaseTrialCreditWarningParams{TeamID: teamID, ClaimToken: claimToken}); err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("trial credit warning claim release failed")
	}
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
