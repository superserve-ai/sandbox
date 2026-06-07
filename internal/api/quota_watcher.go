package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
)

const (
	// quotaAlertPct flags a team for outreach at this % of a limit (per-plan later).
	quotaAlertPct      = 80
	quotaWatchInterval = 15 * time.Minute
	quotaWatchTimeout  = 30 * time.Second
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

// QuotaNotifier delivers a quota alert; a returned error makes the watcher retry.
type QuotaNotifier interface {
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

// computeQuotaAlerts returns the (team, resource) pairs at or over the threshold.
func computeQuotaAlerts(rows []db.ListTeamQuotaUsageRow) map[quotaKey]QuotaAlert {
	out := make(map[quotaKey]QuotaAlert)
	for _, r := range rows {
		for _, c := range quotaChecks {
			used, limit := c.value(r)
			// used/limit >= pct/100, as integers to avoid float boundary fuzz.
			if limit <= 0 || used*100 < limit*quotaAlertPct {
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

// StartQuotaWatcher periodically alerts on teams over the threshold, off the
// request path. Blocks until ctx is cancelled.
func StartQuotaWatcher(ctx context.Context, queries *db.Queries, notifier QuotaNotifier) {
	defer sentrylog.Recover("quota-watcher-loop")
	log.Info().Int("threshold_pct", quotaAlertPct).Dur("interval", quotaWatchInterval).Msg("quota watcher started")
	ticker := time.NewTicker(quotaWatchInterval)
	defer ticker.Stop()

	// Every run — initial and tick-driven — gets the same bounded deadline.
	runOnce := func() {
		runCtx, cancel := context.WithTimeout(ctx, quotaWatchTimeout)
		defer cancel()
		sentrylog.RunSafe("quota-watcher", func() { quotaWatchOnce(runCtx, queries, notifier) })
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

func quotaWatchOnce(ctx context.Context, queries *db.Queries, notifier QuotaNotifier) {
	rows, err := queries.ListTeamQuotaUsage(ctx)
	if err != nil {
		log.Error().Err(err).Msg("quota watcher: ListTeamQuotaUsage failed")
		return
	}
	over := computeQuotaAlerts(rows)

	// Atomic claim → exactly one replica sends; released on failure to retry.
	for k, alert := range over {
		claimed, err := queries.ClaimQuotaAlert(ctx, db.ClaimQuotaAlertParams{TeamID: k.team, QuotaType: k.typ})
		if err != nil {
			log.Error().Err(err).Msg("quota watcher: ClaimQuotaAlert failed")
			continue
		}
		if claimed == 0 {
			continue // already alerted this episode
		}
		if err := notifier.Notify(ctx, alert); err != nil {
			log.Error().Err(err).Str("team", k.team.String()).Str("resource", k.typ).Msg("quota watcher: notify failed; releasing claim")
			_ = queries.ClearQuotaAlert(ctx, db.ClearQuotaAlertParams{TeamID: k.team, QuotaType: k.typ})
		}
	}

	// Release teams that dropped back under threshold so a re-crossing alerts again.
	states, err := queries.ListQuotaAlertState(ctx)
	if err != nil {
		log.Error().Err(err).Msg("quota watcher: ListQuotaAlertState failed")
		return
	}
	for _, s := range states {
		if _, ok := over[quotaKey{s.TeamID, s.QuotaType}]; ok {
			continue
		}
		if err := queries.ClearQuotaAlert(ctx, db.ClearQuotaAlertParams{TeamID: s.TeamID, QuotaType: s.QuotaType}); err != nil {
			log.Error().Err(err).Msg("quota watcher: ClearQuotaAlert failed")
		}
	}
}

// SlackQuotaNotifier posts quota alerts to a Slack webhook; empty URL = no-op.
type SlackQuotaNotifier struct {
	webhookURL string
	client     *http.Client
}

// NewSlackQuotaNotifier builds a notifier; pass "" to disable (no-op).
func NewSlackQuotaNotifier(webhookURL string) *SlackQuotaNotifier {
	return &SlackQuotaNotifier{webhookURL: webhookURL, client: &http.Client{Timeout: 5 * time.Second}}
}

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
