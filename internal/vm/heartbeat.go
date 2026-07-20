package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/auth"
)

// HeartbeatConfig controls the VMD → control plane heartbeat loop.
type HeartbeatConfig struct {
	// ControlPlaneURL is the base URL of the control plane API (e.g.
	// "http://localhost:8080"). The heartbeat POSTs to
	// {ControlPlaneURL}/internal/hosts/{HostID}/heartbeat.
	ControlPlaneURL string

	// HostID is this host's identifier in the host table.
	HostID string

	// Token is the shared secret for authenticating internal API calls.
	// Sent as `Authorization: Bearer <token>`.
	Token string

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
	token := cfg.Token
	client := &http.Client{Timeout: 10 * time.Second}

	log.Info().
		Str("url", url).
		Dur("interval", interval).
		Msg("heartbeat started")

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Fire once immediately so the host is marked alive on startup.
	sendHeartbeat(ctx, client, url, token, log)

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("heartbeat exiting")
			return
		case <-ticker.C:
			sendHeartbeat(ctx, client, url, token, log)
		}
	}
}

// hostCapabilities is what this vmd build's data plane enforces, advertised on
// every heartbeat. The control plane refuses to enable a preview policy on a
// host that has not advertised the matching capability, so a fleet where only
// some hosts run this build fails those API calls instead of recording
// policies the old hosts would not enforce. Hardcoded per build on purpose:
// the binary that serves the /instances records IS the enforcement surface,
// so what it ships is what it can advertise.
var hostCapabilities = []string{
	auth.HostCapabilityPreviewPorts,
	auth.HostCapabilityPreviewPortTokens,
}

// heartbeatRequest is the JSON body POSTed to the control plane.
type heartbeatRequest struct {
	Capabilities []string `json:"capabilities"`
}

func sendHeartbeat(ctx context.Context, client *http.Client, url, token string, log zerolog.Logger) {
	body, err := json.Marshal(heartbeatRequest{Capabilities: hostCapabilities})
	if err != nil {
		log.Error().Err(err).Msg("failed to encode heartbeat body")
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Error().Err(err).Msg("failed to create heartbeat request")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
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
