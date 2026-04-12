package vm

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog"
)

// HeartbeatConfig controls the VMD → control plane heartbeat loop.
type HeartbeatConfig struct {
	// ControlPlaneURL is the base URL of the control plane API (e.g.
	// "http://localhost:8080"). The heartbeat POSTs to
	// {ControlPlaneURL}/internal/hosts/{HostID}/heartbeat.
	ControlPlaneURL string

	// HostID is this host's identifier in the host table.
	HostID string

	// Interval is how often the heartbeat fires. Default: 30s.
	Interval time.Duration
}

// StartHeartbeat launches a background goroutine that periodically POSTs
// to the control plane's heartbeat endpoint. Blocks until ctx is cancelled.
func StartHeartbeat(ctx context.Context, cfg HeartbeatConfig, log zerolog.Logger) {
	log = log.With().Str("component", "heartbeat").Logger()

	interval := cfg.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}

	url := fmt.Sprintf("%s/internal/hosts/%s/heartbeat", cfg.ControlPlaneURL, cfg.HostID)
	client := &http.Client{Timeout: 10 * time.Second}

	log.Info().
		Str("url", url).
		Dur("interval", interval).
		Msg("heartbeat started")

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Fire once immediately so the host is marked alive on startup.
	sendHeartbeat(ctx, client, url, log)

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("heartbeat exiting")
			return
		case <-ticker.C:
			sendHeartbeat(ctx, client, url, log)
		}
	}
}

func sendHeartbeat(ctx context.Context, client *http.Client, url string, log zerolog.Logger) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		log.Error().Err(err).Msg("failed to create heartbeat request")
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Warn().Err(err).Msg("heartbeat failed")
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Warn().Int("status", resp.StatusCode).Msg("heartbeat got non-200 response")
	}
}
