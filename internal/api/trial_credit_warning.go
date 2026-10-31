package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"html"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

func dedupeWarningRecipients(addresses []string) []string {
	seen := make(map[string]struct{}, len(addresses))
	out := make([]string, 0, len(addresses))
	for _, address := range addresses {
		address = strings.ToLower(strings.TrimSpace(address))
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

// Warning kinds other than the legacy signup trial, as reported by
// GetTeamTrialBalance. A trial awaiting its first plan is warned once when it
// ends; a prepaid-funded subscription when its credit falls below the
// configured low-credit level.
const (
	creditWarningTrial   = "trial"
	creditWarningPrepaid = "prepaid"
)

func trialCreditWarningHTML(teamName string, remaining float64) string {
	const title = "Less than 24 hours of credit remaining"
	return emailShell(title, fmt.Sprintf("<h1>%s</h1><p>Based on your recent usage, your credit may run out within the next 24 hours.</p><p>When credit runs out, running sandboxes will be paused. Paused sandboxes keep their data.</p><p>Team: %s</p><p>Remaining credit: $%.2f</p>",
		title, html.EscapeString(teamName), remaining))
}

func prepaidLowCreditHTML(teamName, link string) string {
	const title = "Your credit balance is too low"
	return emailShell(title, fmt.Sprintf("<h1>%s</h1><p>Your credit balance is too low. Buy usage to continue running sandboxes.</p><p>Team: %s</p>%s",
		title, html.EscapeString(teamName), optionalEmailButton("Buy usage", link)))
}

func trialEndedHTML(teamName, link string) string {
	const title = "Your free trial has ended"
	return emailShell(title, fmt.Sprintf("<h1>%s</h1><p>Your free trial has ended, so your sandboxes are paused or will be shortly. Nothing has been deleted.</p><p>Choose a plan to resume where you left off.</p><p>Team: %s</p>%s",
		title, html.EscapeString(teamName), optionalEmailButton("Choose a plan", link)))
}

func optionalEmailButton(label, link string) string {
	if link == "" {
		return ""
	}
	return emailButton(label, link)
}

// consoleLink addresses a console page; it is empty when no console origin
// is configured.
func consoleLink(origin, path string) string {
	if origin == "" {
		return ""
	}
	return origin + path
}

// creditWarningEmail renders the message for the warning kind GetTeamTrialBalance reported.
func creditWarningEmail(kind, teamName string, remaining float64, consoleOrigin string) (subject, body string) {
	switch kind {
	case creditWarningTrial:
		return "Your Superserve free trial has ended", trialEndedHTML(teamName, consoleLink(consoleOrigin, "/"))
	case creditWarningPrepaid:
		return "Your Superserve credit balance is too low", prepaidLowCreditHTML(teamName, consoleLink(consoleOrigin, "/plan-usage/"))
	default:
		return "Your Superserve credit may run out soon", trialCreditWarningHTML(teamName, remaining)
	}
}

// creditWarningOpen reports whether a warning may still be delivered for the
// latest balance, and the remaining credit to quote. The legacy trial's
// runway forecast is checked separately before its claim.
func creditWarningOpen(b db.GetTeamTrialBalanceRow) (float64, bool) {
	remaining, err := numericFloat(b.RemainingUsd)
	if err != nil {
		return 0, false
	}
	switch b.Kind {
	case creditWarningTrial:
		return remaining, b.State == "exhausted"
	case creditWarningPrepaid:
		threshold, err := numericFloat(b.LowCreditUsd)
		return remaining, err == nil && (b.State == "active" || b.State == "exhausted") && remaining < threshold
	default:
		return remaining, trialCreditWarningLifecycleEligible(b.Eligible, b.State) && remaining > 0
	}
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
					job.h.finishTrialCreditWarningJob(job.teamID)
				}
			}()
		}
	})
}

func (h *Handlers) finishTrialCreditWarningJob(teamID uuid.UUID) {
	h.asyncMu.Lock()
	defer h.asyncMu.Unlock()
	delete(h.trialWarningPending, teamID)
	h.asyncCount--
	if h.asyncCount == 0 && h.asyncCond != nil {
		h.asyncCond.Broadcast()
	}
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

// EmailTrialCreditWarningSender delivers the warning to all current billing
// recipients without exposing addresses to one another.
type EmailTrialCreditWarningSender struct {
	sender        EmailSender
	from          string
	consoleOrigin string
	queries       *db.Queries
}

// NewEmailTrialCreditWarningSender links messages to consoleOrigin, and
// sends them without a link when it is empty.
func NewEmailTrialCreditWarningSender(sender EmailSender, from, consoleOrigin string, queries *db.Queries) *EmailTrialCreditWarningSender {
	return &EmailTrialCreditWarningSender{sender: sender, from: from, consoleOrigin: consoleOrigin, queries: queries}
}
func (s *EmailTrialCreditWarningSender) SendTrialCreditWarning(ctx context.Context, teamID uuid.UUID, remaining float64) error {
	return s.sendTrialCreditWarning(ctx, teamID, remaining, uuid.Nil)
}

func (s *EmailTrialCreditWarningSender) SendTrialCreditWarningWithKey(ctx context.Context, teamID uuid.UUID, remaining float64, claimToken uuid.UUID) error {
	return s.sendTrialCreditWarning(ctx, teamID, remaining, claimToken)
}

func (s *EmailTrialCreditWarningSender) sendTrialCreditWarning(ctx context.Context, teamID uuid.UUID, remaining float64, claimToken uuid.UUID) error {
	if s == nil || s.sender == nil || s.from == "" || s.queries == nil {
		// A missing provider configuration is a delivery failure, not a
		// successful no-op. Returning nil here would mark the durable warning
		// state as sent even though no provider accepted a message.
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
	for _, recipient := range dedupeWarningRecipients(delivered) {
		resolved[recipient] = true
	}
	rejected, err := s.queries.ListTrialCreditWarningRejections(ctx, teamID)
	if err != nil {
		return err
	}
	for _, recipient := range dedupeWarningRecipients(rejected) {
		resolved[recipient] = true
	}
	recipients, err := s.queries.ListTrialCreditWarningRecipients(ctx, teamID)
	if err != nil {
		return err
	}
	recipients = dedupeWarningRecipients(recipients)
	if len(recipients) == 0 {
		return errors.New("trial credit warning has no current billing recipients")
	}
	team, err := s.queries.GetTeam(ctx, teamID)
	if err != nil {
		return err
	}
	handled := len(resolved)
	// Submit one message per recipient. A shared To header would disclose
	// other billing members' addresses.
	for _, recipient := range recipients {
		if resolved[recipient] {
			continue
		}
		// Earlier submissions may outlive a membership or billing-role change.
		allowed, err := s.queries.IsTrialCreditWarningRecipientCurrent(ctx, db.IsTrialCreditWarningRecipientCurrentParams{
			TeamID: teamID, Recipient: recipient,
		})
		if err != nil {
			return err
		}
		if !allowed {
			continue
		}
		// Recipient resolution and earlier provider calls can take time. Read
		// the authoritative balance again immediately before each submission.
		balance, err := s.queries.GetTeamTrialBalance(ctx, teamID)
		if err != nil {
			return err
		}
		var open bool
		if remaining, open = creditWarningOpen(balance); !open {
			return errors.New("credit warning no longer applies")
		}
		current, err := s.queries.IsTrialCreditWarningClaimCurrent(ctx, db.IsTrialCreditWarningClaimCurrentParams{
			TeamID: teamID, ClaimToken: pgtype.UUID{Bytes: claimToken, Valid: true},
		})
		if err != nil {
			return err
		}
		if !current {
			return errors.New("trial credit warning lifecycle changed after claim")
		}
		// Persisted recipient outcomes suppress repeats across new claims.
		subject, body := creditWarningEmail(balance.Kind, team.Name, remaining, s.consoleOrigin)
		if err := s.sender.SendEmail(ctx, EmailMessage{
			From:           s.from,
			To:             recipient,
			Subject:        subject,
			HTML:           body,
			IdempotencyKey: trialCreditWarningIdempotencyKey(claimToken, recipient),
		}); err != nil {
			var rejected *rejectedEmailError
			if !errors.As(err, &rejected) {
				return err
			}
			rows, recordErr := s.queries.RecordTrialCreditWarningRejection(ctx, db.RecordTrialCreditWarningRejectionParams{
				TeamID: teamID, Recipient: recipient, ClaimToken: pgtype.UUID{Bytes: claimToken, Valid: true},
			})
			if recordErr != nil {
				return &unknownEmailOutcomeError{err: fmt.Errorf("record trial warning rejection: %w", recordErr)}
			}
			if rows != 1 {
				return &unknownEmailOutcomeError{err: errors.New("trial warning rejection claim no longer current")}
			}
			handled++
			log.Warn().Err(err).Str("team_id", teamID.String()).Msg("trial credit warning recipient permanently rejected; not retrying")
			continue
		}
		rows, err := s.queries.RecordTrialCreditWarningDelivery(ctx, db.RecordTrialCreditWarningDeliveryParams{
			TeamID: teamID, Recipient: recipient, ClaimToken: pgtype.UUID{Bytes: claimToken, Valid: true},
		})
		// Acceptance without durable progress must never release the claim:
		// a later attempt could otherwise resend this recipient's message.
		if err != nil {
			return &unknownEmailOutcomeError{err: fmt.Errorf("record trial warning delivery: %w", err)}
		}
		if rows != 1 {
			return &unknownEmailOutcomeError{err: errors.New("trial warning delivery claim no longer current")}
		}
		handled++
	}
	if handled == 0 {
		return errors.New("trial credit warning has no current billing recipients")
	}
	return nil
}

// trialCreditWarningIdempotencyKey identifies one claim's message to one
// recipient, independent of recipient list order.
func trialCreditWarningIdempotencyKey(claimToken uuid.UUID, recipient string) string {
	return fmt.Sprintf("trial-credit-warning/%s/%x", claimToken, sha256.Sum256([]byte(recipient)))
}

// Discover one bounded page per existing eligibility tick, outside reconciliation.
func (h *Handlers) scheduleTrialCreditWarningDiscovery(ctx context.Context) {
	if h.DB == nil || h.Pool == nil {
		return
	}
	h.asyncMu.Lock()
	if h.trialWarningDiscovery {
		h.asyncMu.Unlock()
		return
	}
	h.trialWarningDiscovery = true
	h.asyncMu.Unlock()
	h.asyncBookkeeping("trial-warning-discovery", func() {
		defer func() {
			h.asyncMu.Lock()
			h.trialWarningDiscovery = false
			h.asyncMu.Unlock()
		}()
		stats := h.Pool.Stat()
		if !trialCreditWarningAdmissions.tryAcquire(stats.MaxConns(), stats.AcquiredConns()) {
			return
		}
		pass := h.beginTrialCreditWarningPass()
		queryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), trialCreditWarningTimeout)
		teams, err := h.DB.ListTrialCreditWarningTeams(queryCtx, db.ListTrialCreditWarningTeamsParams{
			AfterTeamID: pgtype.UUID{Bytes: pass.after, Valid: true},
			BatchLimit:  256,
		})
		cancel()
		trialCreditWarningAdmissions.release()
		if err != nil {
			log.Error().Err(err).Msg("billing: list trial warning teams failed")
			return
		}
		startTrialCreditWarningWorkers()
		for _, teamID := range teams {
			pass.dispatch(h, context.WithoutCancel(ctx), teamID, trialCreditWarningQueue)
		}
		h.finishTrialCreditWarningPass(pass, len(teams) < 256)
	})
}

// Resume after the last accepted UUID on overflow so a stable scan order
// cannot repeatedly fill the queue with the same prefix. Only one cursor is
// retained; subsequent discovery pages supply the remaining teams.
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
	if _, pending := h.trialWarningPending[teamID]; pending {
		pass.last = teamID
		return false
	}
	select {
	case queue <- trialCreditWarningJob{h: h, ctx: ctx, teamID: teamID}:
		if h.trialWarningPending == nil {
			h.trialWarningPending = make(map[uuid.UUID]struct{})
		}
		h.trialWarningPending[teamID] = struct{}{}
		h.asyncCount++
		pass.last = teamID
		return true
	default:
		pass.full = true
		return false
	}
}

func (h *Handlers) processTrialCreditWarning(ctx context.Context, teamID uuid.UUID) {
	if h.DB == nil {
		return
	}
	// Provider calls are advisory and must not pin one of the bounded worker
	// slots indefinitely when the remote service or network stalls.
	workCtx, cancel := context.WithTimeout(ctx, trialCreditWarningTimeout)
	defer cancel()
	ctx = workCtx
	observedAt := time.Now().UTC()
	cached, err := h.DB.GetTeamTrialRunway(ctx, teamID)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("trial runway lifecycle read failed")
		return
	}
	b, balanceErr := h.DB.GetTeamTrialBalance(ctx, teamID)
	if balanceErr == nil && (b.Kind == creditWarningTrial || b.Kind == creditWarningPrepaid) {
		if _, open := creditWarningOpen(b); open && h.TrialWarningSender != nil {
			h.deliverCreditWarning(ctx, teamID, cached.LifecycleKey, creditWarningOpen)
		}
		return
	}
	state := "unknown"
	var remaining float64
	var sample trialBurnSample
	s, sampleErr := h.DB.GetRecentTrialBurnSample(ctx, teamID)
	if sampleErr != nil || balanceErr != nil {
		log.Error().Err(errors.Join(sampleErr, balanceErr)).Str("team_id", teamID.String()).Msg("trial runway inputs read failed")
	} else if trialCreditWarningLifecycleEligible(b.Eligible, b.State) {
		started, ok1 := s.StartedAt.(time.Time)
		ended, ok2 := s.EndedAt.(time.Time)
		spent, spentErr := numericFloat(s.SpentUsd)
		elapsed, elapsedErr := numericFloat(s.ElapsedSeconds)
		var remainingErr error
		remaining, remainingErr = numericFloat(b.RemainingUsd)
		sample = trialBurnSample{SpentUSD: spent, Started: started, Ended: ended, ElapsedSeconds: elapsed}
		if ok1 && ok2 && spentErr == nil && elapsedErr == nil && elapsed > 0 && remainingErr == nil {
			state = trialRunwayState(remaining, time.Now(), sample)
		}
	}
	if err := h.DB.UpsertTeamTrialRunway(ctx, db.UpsertTeamTrialRunwayParams{
		TeamID: teamID, LifecycleKey: cached.LifecycleKey, State: state, ObservedAt: observedAt,
	}); err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("trial runway persistence failed")
		return
	}
	if state != "under_24h" || h.TrialWarningSender == nil {
		return
	}
	h.deliverCreditWarning(ctx, teamID, cached.LifecycleKey, func(latest db.GetTeamTrialBalanceRow) (float64, bool) {
		if !trialCreditWarningLifecycleEligible(latest.Eligible, latest.State) {
			return 0, false
		}
		latestRemaining, err := numericFloat(latest.RemainingUsd)
		return latestRemaining, err == nil && trialCreditWarningEligible(latestRemaining, time.Now(), sample)
	})
}

// deliverCreditWarning claims the lifecycle's single warning and sends it if
// the latest balance, read after the claim, still calls for it.
func (h *Handlers) deliverCreditWarning(ctx context.Context, teamID uuid.UUID, lifecycleKey string, open func(db.GetTeamTrialBalanceRow) (float64, bool)) {
	claimToken, err := h.DB.ClaimTrialCreditWarningForLifecycle(ctx, db.ClaimTrialCreditWarningForLifecycleParams{
		TeamID: teamID, LifecycleKey: lifecycleKey,
	})
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("trial credit warning claim failed")
		}
		return
	}
	// Claiming is deliberately separate from the balance read. Re-read the
	// authoritative state immediately before provider submission so an
	// expiry, exhaustion, top-up or plan change racing the decision cannot
	// emit a warning that no longer applies.
	latest, err := h.DB.GetTeamTrialBalance(ctx, teamID)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("trial credit warning final balance read failed")
		h.releaseTrialCreditWarning(teamID, claimToken)
		return
	}
	remaining, ok := open(latest)
	if !ok {
		h.releaseTrialCreditWarning(teamID, claimToken)
		return
	}
	if sender, ok := h.TrialWarningSender.(trialCreditWarningIdempotentSender); ok {
		err = sender.SendTrialCreditWarningWithKey(ctx, teamID, remaining, uuid.UUID(claimToken.Bytes))
	} else {
		err = h.TrialWarningSender.SendTrialCreditWarning(ctx, teamID, remaining)
	}
	if err != nil {
		var unknown *unknownEmailOutcomeError
		if errors.As(err, &unknown) {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if stateErr := h.DB.MarkTrialCreditWarningUnknown(cleanupCtx, db.MarkTrialCreditWarningUnknownParams{TeamID: teamID, ClaimToken: claimToken}); stateErr != nil {
				log.Error().Err(stateErr).Str("team_id", teamID.String()).Msg("trial credit warning unknown outcome persistence failed")
			}
		} else {
			h.releaseTrialCreditWarning(teamID, claimToken)
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("trial credit warning send failed")
		return
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cleanupCancel()
	if err := h.DB.CompleteTrialCreditWarning(cleanupCtx, db.CompleteTrialCreditWarningParams{TeamID: teamID, ClaimToken: claimToken}); err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("trial credit warning completion failed; claim retained")
	}
}

func (h *Handlers) releaseTrialCreditWarning(teamID uuid.UUID, claimToken pgtype.UUID) {
	// Definitive failures must remain retryable even after the work context expires.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.DB.ReleaseTrialCreditWarning(ctx, db.ReleaseTrialCreditWarningParams{TeamID: teamID, ClaimToken: claimToken}); err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("trial credit warning claim release failed")
	}
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
	return trialRunwayState(remainingUSD, now, sample) == "under_24h"
}

func trialRunwayState(remainingUSD float64, now time.Time, sample trialBurnSample) string {
	if math.IsNaN(remainingUSD) || math.IsInf(remainingUSD, 0) || math.IsNaN(sample.SpentUSD) || math.IsInf(sample.SpentUSD, 0) || remainingUSD <= 0 || sample.SpentUSD < 0.05 || sample.Ended.Before(sample.Started) {
		return "unknown"
	}
	// Require recent activity and at least five cents of measured spend; a
	// fast workload needs no minimum duration to supply that signal.
	if !sample.Ended.After(now.Add(-15*time.Minute)) || sample.Ended.After(now) {
		return "unknown"
	}
	// Include idle wall time since the last interval instead of extrapolating
	// a short, completed burst as though it were still running.
	elapsed := now.Sub(sample.Started)
	if elapsed <= 0 {
		return "unknown"
	}
	rate := sample.SpentUSD / elapsed.Hours()
	if rate <= 0 || math.IsInf(rate, 0) || math.IsNaN(rate) {
		return "unknown"
	}
	if remainingUSD/rate < 24 {
		return "under_24h"
	}
	return "over_24h"
}
