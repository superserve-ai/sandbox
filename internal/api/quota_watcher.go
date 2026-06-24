package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
)

const (
	// A team is alerted once on reaching quotaAlertPct, and not again until it has
	// both fallen under quotaResetPct (hysteresis, so hovering doesn't re-alert)
	// and aged past quotaAlertCooldown — at most one alert per cooldown window,
	// even across recover/re-cross cycles.
	quotaAlertPct      = 80
	quotaResetPct      = 70
	quotaAlertCooldown = 7 * 24 * time.Hour

	quotaWatchInterval = 15 * time.Minute
	quotaWatchTimeout  = 30 * time.Second

	resendEmailEndpoint = "https://api.resend.com/emails"
)

// QuotaAlert is a team crossing the usage threshold for one resource.
type QuotaAlert struct {
	TeamID   uuid.UUID
	TeamName string
	Resource string
	Used     int
	Limit    int
	Pct      int
}

// QuotaNotifier delivers a quota alert over one channel. Channel is the stable
// de-dup key for that channel; Handles reports whether it covers a resource;
// Notify returns an error to make the watcher retry on the next tick.
type QuotaNotifier interface {
	Channel() string
	Handles(resource string) bool
	Notify(ctx context.Context, a QuotaAlert) error
}

type quotaKey struct {
	team uuid.UUID
	typ  string
}

// quotaCheck extracts (used, limit) for one resource from a usage row.
type quotaCheck struct {
	name  string
	value func(db.ListTeamQuotaUsageRow) (used, limit int)
}

var quotaChecks = []quotaCheck{
	{"sandboxes", func(r db.ListTeamQuotaUsageRow) (int, int) {
		return int(r.ActiveSandboxCount), int(r.MaxSandboxes)
	}},
	{"templates", func(r db.ListTeamQuotaUsageRow) (int, int) {
		limit := defaultMaxTemplates
		if r.MaxTemplates != nil {
			limit = int(*r.MaxTemplates)
		}
		return int(r.TemplateCount), limit
	}},
}

// teamsOverPct returns the (team, resource) pairs at or over pct% of their limit.
func teamsOverPct(rows []db.ListTeamQuotaUsageRow, pct int) map[quotaKey]QuotaAlert {
	out := make(map[quotaKey]QuotaAlert)
	for _, r := range rows {
		for _, c := range quotaChecks {
			used, limit := c.value(r)
			// used/limit >= pct/100, as integers to avoid float boundary fuzz.
			if limit <= 0 || used*100 < limit*pct {
				continue
			}
			out[quotaKey{r.ID, c.name}] = QuotaAlert{
				TeamID:   r.ID,
				TeamName: r.Name,
				Resource: c.name,
				Used:     used,
				Limit:    limit,
				Pct:      used * 100 / limit,
			}
		}
	}
	return out
}

// computeQuotaAlerts returns the pairs at or over the alert threshold.
func computeQuotaAlerts(rows []db.ListTeamQuotaUsageRow) map[quotaKey]QuotaAlert {
	return teamsOverPct(rows, quotaAlertPct)
}

// StartQuotaWatcher periodically alerts on teams over the threshold, off the
// request path, fanning each alert out to every notifier that handles it.
// Blocks until ctx is cancelled.
func StartQuotaWatcher(ctx context.Context, queries *db.Queries, notifiers []QuotaNotifier) {
	defer sentrylog.Recover("quota-watcher-loop")
	channels := make([]string, len(notifiers))
	for i, n := range notifiers {
		channels[i] = n.Channel()
	}
	log.Info().Int("alert_pct", quotaAlertPct).Int("reset_pct", quotaResetPct).
		Dur("interval", quotaWatchInterval).Strs("channels", channels).Msg("quota watcher started")
	ticker := time.NewTicker(quotaWatchInterval)
	defer ticker.Stop()

	// Every run — initial and tick-driven — gets the same bounded deadline.
	runOnce := func() {
		runCtx, cancel := context.WithTimeout(ctx, quotaWatchTimeout)
		defer cancel()
		sentrylog.RunSafe("quota-watcher", func() { quotaWatchOnce(runCtx, queries, notifiers) })
	}

	runOnce()
	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("quota watcher exiting")
			return
		case <-ticker.C:
			runOnce()
		}
	}
}

func quotaWatchOnce(ctx context.Context, queries *db.Queries, notifiers []QuotaNotifier) {
	rows, err := queries.ListTeamQuotaUsage(ctx)
	if err != nil {
		log.Error().Err(err).Msg("quota watcher: ListTeamQuotaUsage failed")
		return
	}
	over := computeQuotaAlerts(rows)              // >= alert threshold
	elevated := teamsOverPct(rows, quotaResetPct) // >= reset threshold (hysteresis band)

	// Per over-threshold (team, resource), claim and notify each channel
	// independently so a flaky channel retries without re-sending the others.
	for k, alert := range over {
		for _, n := range notifiers {
			if !n.Handles(k.typ) {
				continue
			}
			ch := n.Channel()
			claimed, err := queries.ClaimQuotaAlert(ctx, db.ClaimQuotaAlertParams{TeamID: k.team, QuotaType: k.typ, Channel: ch})
			if err != nil {
				log.Error().Err(err).Str("channel", ch).Msg("quota watcher: ClaimQuotaAlert failed")
				continue
			}
			if claimed == 0 {
				continue // already alerted this episode, or still within cooldown
			}
			if err := n.Notify(ctx, alert); err != nil {
				log.Error().Err(err).Str("team", k.team.String()).Str("resource", k.typ).Str("channel", ch).
					Msg("quota watcher: notify failed; releasing claim")
				// Detached from the run deadline so cleanup still runs if Notify
				// failed because the tick budget expired (else the claim sticks).
				releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				_ = queries.ClearQuotaAlert(releaseCtx, db.ClearQuotaAlertParams{TeamID: k.team, QuotaType: k.typ, Channel: ch})
				cancel()
			}
		}
	}

	// Re-arm a key only once it has both fallen below the reset threshold
	// (hysteresis) and aged past the cooldown. Satisfying just one keeps the
	// row, so we neither flap on the boundary nor re-alert too soon.
	states, err := queries.ListQuotaAlertState(ctx)
	if err != nil {
		log.Error().Err(err).Msg("quota watcher: ListQuotaAlertState failed")
		return
	}
	cooldownCutoff := time.Now().Add(-quotaAlertCooldown)
	for _, s := range states {
		if !shouldRearm(s, elevated, cooldownCutoff) {
			continue
		}
		if err := queries.ClearQuotaAlert(ctx, db.ClearQuotaAlertParams{TeamID: s.TeamID, QuotaType: s.QuotaType, Channel: s.Channel}); err != nil {
			log.Error().Err(err).Msg("quota watcher: ClearQuotaAlert failed")
		}
	}
}

// shouldRearm reports whether a stored alert state should be cleared so the key
// can alert again. It clears only when the key has both fallen out of the
// elevated (reset-threshold) band and aged past the cooldown; satisfying just
// one keeps the row, which is what prevents boundary flapping and too-soon
// re-alerts.
func shouldRearm(s db.ListQuotaAlertStateRow, elevated map[quotaKey]QuotaAlert, cooldownCutoff time.Time) bool {
	if _, stillElevated := elevated[quotaKey{s.TeamID, s.QuotaType}]; stillElevated {
		return false
	}
	return !s.CreatedAt.After(cooldownCutoff)
}

// SlackQuotaNotifier posts quota alerts to a Slack webhook; empty URL = no-op.
// It handles every resource.
type SlackQuotaNotifier struct {
	webhookURL string
	client     *http.Client
}

// NewSlackQuotaNotifier builds a notifier; pass "" to disable (no-op).
func NewSlackQuotaNotifier(webhookURL string) *SlackQuotaNotifier {
	return &SlackQuotaNotifier{webhookURL: webhookURL, client: &http.Client{Timeout: 5 * time.Second}}
}

func (n *SlackQuotaNotifier) Channel() string { return "slack" }

func (n *SlackQuotaNotifier) Handles(string) bool { return true }

func (n *SlackQuotaNotifier) Notify(ctx context.Context, a QuotaAlert) error {
	if n == nil || n.webhookURL == "" {
		return nil
	}
	text := fmt.Sprintf("⚠️ Team *%s* (`%s`) is at %d%% of its %s limit (%d/%d) — consider reaching out.",
		a.TeamName, a.TeamID, a.Pct, a.Resource, a.Used, a.Limit)
	body, _ := json.Marshal(map[string]string{"text": text})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("slack webhook returned %d", resp.StatusCode)
	}
	return nil
}

// teamEmailLookup resolves a team's quota-email recipient. *db.Queries satisfies
// it; narrowing to this interface keeps the notifier unit-testable.
type teamEmailLookup interface {
	GetTeamNotifyEmail(ctx context.Context, teamID uuid.UUID) (string, error)
}

// EmailQuotaNotifier emails a team's owner when it crosses the sandbox quota
// threshold, via the Resend API. Disabled (no-op) when apiKey or from is empty.
// Scoped to the sandbox limit; it does not handle the template limit.
type EmailQuotaNotifier struct {
	apiKey     string
	from       string
	recipients teamEmailLookup
	endpoint   string
	client     *http.Client
}

// NewEmailQuotaNotifier builds a notifier; pass "" for apiKey or from to disable.
func NewEmailQuotaNotifier(apiKey, from string, queries *db.Queries) *EmailQuotaNotifier {
	return &EmailQuotaNotifier{
		apiKey:     apiKey,
		from:       from,
		recipients: queries,
		endpoint:   resendEmailEndpoint,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (n *EmailQuotaNotifier) Channel() string { return "email" }

func (n *EmailQuotaNotifier) Handles(resource string) bool { return resource == "sandboxes" }

func (n *EmailQuotaNotifier) Notify(ctx context.Context, a QuotaAlert) error {
	if n == nil || n.apiKey == "" || n.from == "" {
		return nil
	}
	to, err := n.recipients.GetTeamNotifyEmail(ctx, a.TeamID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// No recipient on file — nothing to retry. Drop quietly so we don't
			// spin on it every tick.
			log.Warn().Str("team", a.TeamID.String()).Msg("quota email: team has no recipient; skipping")
			return nil
		}
		return err
	}

	payload := map[string]any{
		"from":    n.from,
		"to":      []string{to},
		"subject": fmt.Sprintf("You've used %d%% of your sandbox limit", a.Pct),
		"html":    quotaEmailHTML(a),
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+n.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Info().Str("team", a.TeamID.String()).Int("pct", a.Pct).Msg("quota email sent")
		return nil
	}

	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	// Non-429 4xx is permanent (unverified domain, bad recipient) — retrying
	// every tick only spins, so drop it. 5xx/429 are transient: return an error.
	if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
		log.Warn().Int("status", resp.StatusCode).Str("team", a.TeamID.String()).Str("body", string(snippet)).
			Msg("quota email: permanent rejection; not retrying")
		return nil
	}
	return fmt.Errorf("resend returned %d: %s", resp.StatusCode, string(snippet))
}

// quotaEmailHTML renders the customer-facing sandbox-limit email body.
func quotaEmailHTML(a QuotaAlert) string {
	team := html.EscapeString(a.TeamName)
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
  <body style="margin:0;padding:24px;background:#0b0b0f;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#e7e7ea;">
    <table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="max-width:480px;margin:0 auto;background:#15151b;border-radius:12px;">
      <tr><td style="padding:28px 28px 8px;">
        <h1 style="margin:0;font-size:18px;font-weight:600;">You're approaching your sandbox limit</h1>
      </td></tr>
      <tr><td style="padding:8px 28px 0;font-size:14px;line-height:22px;color:#b6b6bf;">
        <p style="margin:0 0 16px;">Team <strong style="color:#e7e7ea;">%s</strong> is using <strong style="color:#e7e7ea;">%d of %d</strong> sandboxes (%d%%).</p>
        <p style="margin:0 0 20px;">You've hit %d%% of your sandbox limit. Please contact our team to raise it before you run out of room to create new sandboxes.</p>
        <p style="margin:0 0 28px;"><a href="mailto:support@superserve.ai" style="display:inline-block;padding:10px 18px;background:#5b5bd6;color:#fff;text-decoration:none;border-radius:8px;font-size:14px;font-weight:500;">Contact the team</a></p>
        <p style="margin:0;font-size:12px;color:#6f6f7a;">Or reply to this email and we'll help you out.</p>
      </td></tr>
    </table>
  </body>
</html>`, team, a.Used, a.Limit, a.Pct, a.Pct)
}
