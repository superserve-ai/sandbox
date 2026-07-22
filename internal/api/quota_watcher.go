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
	// A team at or over quotaAlertPct of a limit is alerted at most once per
	// quotaAlertCooldown — a fixed suppression window that ignores how the team
	// bounces across the threshold in between. Simple, predictable guarantee; the
	// always-on console banner carries the real-time state.
	quotaAlertPct      = 80
	quotaAlertCooldown = 30 * 24 * time.Hour

	quotaWatchInterval = 15 * time.Minute
	quotaWatchTimeout  = 30 * time.Second

	resendEmailEndpoint = "https://api.resend.com/emails"

	// Shared brand assets, mirroring the console's EmailLayout.
	emailLogoURL     = "https://superserve.ai/assets/logo-light.png"
	emailMeetingURL  = "https://www.superserve.ai/meet/?utm_source=email&utm_medium=quota"
	emailSupportAddr = "support@superserve.ai"
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
	log.Info().Int("alert_pct", quotaAlertPct).Dur("cooldown", quotaAlertCooldown).
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
	// The sharded counter has no write-time reconciliation; a sum biased low
	// (row surgery, partial restore) silently widens a team's quota. Both
	// aggregates in the query share one snapshot, so any mismatch is real.
	// Error level so it reaches Sentry; repair is re-running the migration's
	// seed recount.
	if drift, err := queries.ListQuotaCounterDrift(ctx); err != nil {
		log.Error().Err(err).Msg("quota watcher: ListQuotaCounterDrift failed")
	} else {
		for _, d := range drift {
			log.Error().Str("team", d.TeamID.String()).
				Int32("shard_sum", d.ShardSum).Int32("true_count", d.TrueCount).
				Msg("quota watcher: sandbox counter drift detected")
		}
	}

	rows, err := queries.ListTeamQuotaUsage(ctx)
	if err != nil {
		log.Error().Err(err).Msg("quota watcher: ListTeamQuotaUsage failed")
		return
	}
	over := computeQuotaAlerts(rows) // >= alert threshold

	// Per over-threshold (team, resource), claim and notify each channel
	// independently so a flaky channel retries without re-sending the others.
	// A claim that returns 0 is suppressed by the cooldown window.
	var alerted, suppressed int
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
				suppressed++
				continue // within the cooldown window
			}
			alerted++
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
	if alerted > 0 || suppressed > 0 {
		log.Info().Int("over_threshold", len(over)).Int("alerted", alerted).Int("suppressed", suppressed).
			Msg("quota watcher: alert pass")
	}

	// Re-arm a key once its row ages past the cooldown, regardless of where the
	// team currently sits — a fixed one-per-window suppression.
	states, err := queries.ListQuotaAlertState(ctx)
	if err != nil {
		log.Error().Err(err).Msg("quota watcher: ListQuotaAlertState failed")
		return
	}
	cooldownCutoff := time.Now().Add(-quotaAlertCooldown)
	for _, s := range states {
		if !shouldRearm(s, cooldownCutoff) {
			continue
		}
		if err := queries.ClearQuotaAlert(ctx, db.ClearQuotaAlertParams{TeamID: s.TeamID, QuotaType: s.QuotaType, Channel: s.Channel}); err != nil {
			log.Error().Err(err).Msg("quota watcher: ClearQuotaAlert failed")
		}
	}
}

// shouldRearm reports whether a stored alert state has aged past the cooldown and
// can be cleared so the key may alert again.
func shouldRearm(s db.ListQuotaAlertStateRow, cooldownCutoff time.Time) bool {
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
		"subject": "Verify your team on Superserve",
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
	var rerr struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(snippet, &rerr)
	// Retry transient errors (429/5xx) and recoverable config errors an operator
	// will fix: bad API key / unverified domain (401/403) and a malformed
	// QUOTA_EMAIL_FROM, which Resend reports as invalid_from_address (a 422).
	// Other 4xx (e.g. a bad recipient) won't self-heal, so drop rather than spin.
	switch {
	case resp.StatusCode == http.StatusUnauthorized,
		resp.StatusCode == http.StatusForbidden,
		resp.StatusCode == http.StatusTooManyRequests,
		resp.StatusCode >= 500,
		rerr.Name == "invalid_from_address":
		return fmt.Errorf("resend returned %d (%s): %s", resp.StatusCode, rerr.Name, string(snippet))
	default:
		log.Warn().Int("status", resp.StatusCode).Str("team", a.TeamID.String()).Str("body", string(snippet)).
			Msg("quota email: permanent rejection; not retrying")
		return nil
	}
}

// quotaEmailHTML renders the team-verification email body inside the shared shell.
func quotaEmailHTML(a QuotaAlert) string {
	body := fmt.Sprintf(`<h1 style="font-family:'Instrument Sans',Helvetica,Arial,sans-serif;color:#e5e5e5;font-size:20px;font-weight:600;letter-spacing:-0.01em;margin:0 0 24px 0;">Verify your team on Superserve</h1>
<p style="color:#a3a3a3;font-size:14px;line-height:24px;margin:0 0 16px 0;">We're glad to see increasing usage on your Superserve account. For security reasons, we limit the number of active sandboxes on new accounts to <strong style="color:#e5e5e5;">%d</strong>. To request a higher limit, book a meeting using the link below, or reply to this email with:</p>
<ul style="color:#a3a3a3;font-size:14px;line-height:24px;margin:0 0 16px 0;padding-left:20px;">
<li>a link to your website or domain</li>
<li>a company email address</li>
<li>a brief description of your use case</li>
</ul>
<p style="color:#a3a3a3;font-size:14px;line-height:24px;margin:0 0 16px 0;">We review every request and aim to respond within 48 hours. Our goal is to provide infinite compute to power your agents, and this verification helps us allocate capacity safely and responsibly across all our customers.</p>
<a href="%s" style="background-color:#e5e5e5;color:#0a0a0a;font-family:'Geist Mono',monospace;font-size:12px;font-weight:500;letter-spacing:0.06em;text-transform:uppercase;text-decoration:none;text-align:center;display:block;padding:14px 24px;margin:28px 0 0 0;">Book a Meeting</a>`,
		a.Limit, emailMeetingURL)
	return emailShell("Verify your team on Superserve", body)
}

// emailShell wraps body HTML in the shared Superserve email chrome — logo header,
// dashed card, footer — mirroring the console's EmailLayout so control-plane mail
// matches the auth/welcome emails. Styles are inlined for email-client support.
func emailShell(preview, body string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Instrument+Sans:wght@400;500;600&family=Geist+Mono:wght@500&display=swap">
  </head>
  <body style="background-color:#0a0a0a;font-family:'Instrument Sans',Helvetica,Arial,sans-serif;margin:0;padding:0;color:#e5e5e5;">
    <div style="display:none;overflow:hidden;line-height:1px;max-height:0;max-width:0;opacity:0;">%s</div>
    <table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="max-width:520px;margin:0 auto;padding:40px 20px;">
      <tr><td style="text-align:center;padding:0 0 32px 0;">
        <img src="%s" width="173" height="32" alt="Superserve">
      </td></tr>
      <tr><td style="background-color:#171717;border:1px dashed #262626;padding:40px 32px;">%s</td></tr>
      <tr><td style="padding:32px 0 0 0;text-align:center;">
        <p style="color:#737373;font-family:'Geist Mono',monospace;font-size:11px;font-weight:500;letter-spacing:0.08em;line-height:20px;margin:0 0 8px 0;">SUPERSERVE</p>
        <p style="color:#525252;font-size:11px;line-height:18px;margin:0;">455 Market St Ste 1940 PMB 924076, San Francisco, California 94105-2448 US.</p>
        <p style="color:#525252;font-size:11px;line-height:18px;margin:0;">Questions? Contact <a href="mailto:%s" style="color:#e5e5e5;text-decoration:underline;text-underline-offset:2px;">%s</a></p>
      </td></tr>
    </table>
  </body>
</html>`, html.EscapeString(preview), emailLogoURL, body, emailSupportAddr, emailSupportAddr)
}
