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

	"github.com/superserve-ai/sandbox/internal/preview"
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

	// ProxyHealthURL is the host-local edge proxy health endpoint. The default
	// is http://127.0.0.1:5007/health. VMD advertises preview-port enforcement
	// only when this endpoint confirms the matching proxy protocol.
	ProxyHealthURL string

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
	proxyHealthURL := cfg.ProxyHealthURL
	if proxyHealthURL == "" {
		proxyHealthURL = "http://127.0.0.1:5007/health"
	}
	client := &http.Client{Timeout: 10 * time.Second}

	log.Info().
		Str("url", url).
		Str("proxy_health_url", proxyHealthURL).
		Dur("interval", interval).
		Msg("heartbeat started")

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Fire once immediately so the host is marked alive on startup.
	sendHeartbeat(ctx, client, url, token, proxyHealthURL, log)

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("heartbeat exiting")
			return
		case <-ticker.C:
			sendHeartbeat(ctx, client, url, token, proxyHealthURL, log)
		}
	}
}

type heartbeatRequest struct {
	Capabilities []string `json:"capabilities"`
}

type proxyHealthResponse struct {
	Capabilities []string `json:"capabilities"`
}

func sendHeartbeat(ctx context.Context, client *http.Client, url, token, proxyHealthURL string, log zerolog.Logger) {
	capabilities, err := proxyPreviewCapabilities(ctx, client, proxyHealthURL)
	if err != nil {
		log.Warn().Err(err).Msg("proxy capability probe failed; advertising no preview capabilities")
		capabilities = nil
	}

	body, err := json.Marshal(heartbeatRequest{Capabilities: capabilities})
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

func proxyPreviewCapabilities(ctx context.Context, client *http.Client, healthURL string) ([]string, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, healthURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build proxy health request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request proxy health: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("proxy health returned %d", resp.StatusCode)
	}
	var health proxyHealthResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&health); err != nil {
		if err == io.EOF {
			// Pre-capability proxies returned an empty 200 health response.
			return nil, nil
		}
		return nil, fmt.Errorf("decode proxy health: %w", err)
	}
	advertised := make(map[string]bool, len(health.Capabilities))
	for _, capability := range health.Capabilities {
		advertised[capability] = true
	}
	if !advertised[preview.HostCapabilityPorts] {
		return nil, nil
	}
	out := []string{preview.HostCapabilityPorts}
	if advertised[preview.HostCapabilityPortAccess] {
		out = append(out, preview.HostCapabilityPortAccess)
		if advertised[preview.HostCapabilityPortTokens] {
			out = append(out, preview.HostCapabilityPortTokens)
			if advertised[preview.HostCapabilityPortBrowserAuth] {
				out = append(out, preview.HostCapabilityPortBrowserAuth)
			}
		}
	}
	return out, nil
}
