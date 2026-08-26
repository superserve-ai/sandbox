package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/preview"
)

// Keep the stale logical-size billing window short for overlays activated
// after startup while retaining a bounded, periodic fleet scan.
const overlayStorageSampleInterval = 5 * time.Minute

type HeartbeatConfig struct {
	ControlPlaneURL   string
	HostID            string
	Token             string
	ProxyHealthURL    string
	RunDir            string
	Interval          time.Duration
	VMDAddr           string
	ProxyAddr         string
	Region            string
	CapacityMemoryMib int32
	CapacityVcpus     int32
}

func StartHeartbeat(ctx context.Context, cfg HeartbeatConfig, log zerolog.Logger) {
	log = log.With().Str("component", "heartbeat").Logger()
	interval := cfg.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	runDir := cfg.RunDir
	if runDir == "" {
		runDir = "/var/lib/sandbox/rundir"
	}
	url := fmt.Sprintf("%s/internal/hosts/%s/heartbeat", cfg.ControlPlaneURL, cfg.HostID)
	proxyHealthURL := cfg.ProxyHealthURL
	if proxyHealthURL == "" {
		proxyHealthURL = "http://127.0.0.1:5007/health"
	}
	client := &http.Client{Timeout: 30 * time.Second}
	log.Info().Str("url", url).Str("proxy_health_url", proxyHealthURL).Dur("interval", interval).Msg("heartbeat started")

	cache := &heartbeatStorageCache{}

	// Keep the first liveness POST independent of the fleet-sized filesystem
	// scan. Storage sampling runs in a separate goroutine so heartbeat posts
	// can continue even if a host has a large number of sandboxes.
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	_, _ = sendHeartbeat(ctx, client, cfg, url, cfg.Token, proxyHealthURL, nil, log)
	go runOverlayStorageSampler(ctx, runDir, overlayStorageSampleInterval, cache, log)
	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("heartbeat exiting")
			return
		case <-ticker.C:
			now := time.Now()
			version, storage := cache.snapshot()
			publishStorage := cache.shouldSend(version, now)
			if !publishStorage {
				storage = nil
			}
			if ok, accepted := sendHeartbeat(ctx, client, cfg, url, cfg.Token, proxyHealthURL, storage, log); ok && publishStorage && accepted {
				cache.markSent(version, now)
			}
		}
	}
}

type heartbeatStorageMeasurement struct {
	SandboxID      string `json:"sandbox_id"`
	AllocatedBytes int64  `json:"allocated_bytes"`
}

type heartbeatRequest struct {
	Capabilities      []string                      `json:"capabilities"`
	Storage           []heartbeatStorageMeasurement `json:"storage,omitempty"`
	VMDAddr           string                        `json:"vmd_addr,omitempty"`
	ProxyAddr         string                        `json:"proxy_addr,omitempty"`
	Region            string                        `json:"region,omitempty"`
	CapacityMemoryMib int32                         `json:"capacity_memory_mib,omitempty"`
	CapacityVcpus     int32                         `json:"capacity_vcpus,omitempty"`
}

type proxyHealthResponse struct {
	Capabilities []string `json:"capabilities"`
}

type heartbeatStorageCache struct {
	mu           sync.RWMutex
	measurements []heartbeatStorageMeasurement
	version      uint64
	sentVersion  uint64
	sentAt       time.Time
}

func (c *heartbeatStorageCache) snapshot() (uint64, []heartbeatStorageMeasurement) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.measurements) == 0 {
		return c.version, nil
	}
	out := make([]heartbeatStorageMeasurement, len(c.measurements))
	copy(out, c.measurements)
	return c.version, out
}

func (c *heartbeatStorageCache) shouldSend(version uint64, now time.Time) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.measurements) == 0 {
		return false
	}
	if version > c.sentVersion {
		return true
	}
	return !c.sentAt.IsZero() && now.Sub(c.sentAt) >= overlayStorageSampleInterval
}

func (c *heartbeatStorageCache) markSent(version uint64, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if version < c.sentVersion {
		return
	}
	c.sentVersion = version
	c.sentAt = now
}

func (c *heartbeatStorageCache) store(measurements []heartbeatStorageMeasurement) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if reflect.DeepEqual(c.measurements, measurements) {
		return
	}
	if len(measurements) == 0 {
		c.measurements = nil
		c.version++
		return
	}
	c.measurements = make([]heartbeatStorageMeasurement, len(measurements))
	copy(c.measurements, measurements)
	c.version++
}

func sendHeartbeat(ctx context.Context, client *http.Client, cfg HeartbeatConfig, url, token, proxyHealthURL string, storage []heartbeatStorageMeasurement, log zerolog.Logger) (bool, bool) {
	started := time.Now()
	capabilities, err := proxyPreviewCapabilities(ctx, client, proxyHealthURL)
	if err != nil {
		log.Warn().Err(err).
			Dur("duration", time.Since(started)).
			Msg("proxy capability probe failed; advertising no preview capabilities")
		capabilities = nil
	}
	return postHeartbeat(ctx, client, cfg, url, token, capabilities, storage, log, started)
}

func postHeartbeat(ctx context.Context, client *http.Client, cfg HeartbeatConfig, url, token string, capabilities []string, storage []heartbeatStorageMeasurement, log zerolog.Logger, started time.Time) (bool, bool) {
	body, err := json.Marshal(buildHeartbeatRequest(cfg, capabilities, storage))
	if err != nil {
		log.Error().Err(err).Msg("failed to encode heartbeat body")
		return false, false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Error().Err(err).Msg("failed to create heartbeat request")
		return false, false
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Warn().Err(err).Str("host_id", cfg.HostID).
			Strs("capabilities", capabilities).Dur("duration", time.Since(started)).
			Msg("heartbeat failed")
		return false, false
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if len(storage) > 0 && resp.StatusCode == http.StatusBadRequest && isStorageFieldUnsupported(respBody) {
			log.Warn().
				Int("status", resp.StatusCode).
				Msg("heartbeat storage field rejected by an older control plane; retrying without storage")
			return postHeartbeat(ctx, client, cfg, url, token, capabilities, nil, log, started)
		}
		log.Warn().Int("status", resp.StatusCode).Msg("heartbeat got non-200 response")
		return false, false
	}
	return true, storage != nil
}

func isStorageFieldUnsupported(body []byte) bool {
	return bytes.Contains(body, []byte(`unknown field "storage"`)) ||
		bytes.Contains(body, []byte(`unknown field \"storage\"`))
}

func buildHeartbeatRequest(cfg HeartbeatConfig, capabilities []string, storage []heartbeatStorageMeasurement) heartbeatRequest {
	req := heartbeatRequest{
		Capabilities: capabilities,
		Storage:      storage,
	}
	if cfg.VMDAddr != "" && cfg.ProxyAddr != "" && cfg.Region != "" &&
		cfg.CapacityMemoryMib > 0 && cfg.CapacityVcpus > 0 {
		req.VMDAddr = cfg.VMDAddr
		req.ProxyAddr = cfg.ProxyAddr
		req.Region = cfg.Region
		req.CapacityMemoryMib = cfg.CapacityMemoryMib
		req.CapacityVcpus = cfg.CapacityVcpus
	}
	return req
}

func sampleOverlayStorage(runDir string, cache *heartbeatStorageCache, log zerolog.Logger) {
	measurements, err := measureOverlayStorage(runDir)
	if err != nil {
		log.Warn().Err(err).Msg("overlay storage measurement failed; keeping previous cached sample")
		return
	}
	cache.store(measurements)
}

func runOverlayStorageSampler(ctx context.Context, runDir string, interval time.Duration, cache *heartbeatStorageCache, log zerolog.Logger) {
	if interval <= 0 {
		interval = overlayStorageSampleInterval
	}
	sampleOverlayStorage(runDir, cache, log)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sampleOverlayStorage(runDir, cache, log)
		}
	}
}

// DetectHostCapacity reports the machine's PHYSICAL memory (MiB) and
// logical CPU count. Never advertised as capacity: the schedulable
// capacity a host registers is explicitly configured because physical
// totals include everything the OS, the daemons, and the deliberate cgroup
// headroom already spend.
func DetectHostCapacity() (memoryMib, vcpus int32) {
	vcpus = int32(runtime.NumCPU())
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, vcpus
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, vcpus
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0, vcpus
		}
		return int32(kb / 1024), vcpus
	}
	return 0, vcpus
}

// measureOverlayStorage reads allocation metadata only; it never walks ext4
// contents. st_blocks is the same physical allocation quantity used by du.
func measureOverlayStorage(runDir string) ([]heartbeatStorageMeasurement, error) {
	entries, err := os.ReadDir(runDir)
	if err != nil {
		return nil, err
	}
	out := make([]heartbeatStorageMeasurement, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := uuid.Parse(entry.Name()); err != nil {
			continue
		}
		info, err := os.Stat(filepath.Join(runDir, entry.Name(), "overlay.ext4"))
		if os.IsNotExist(err) {
			// Legacy sandboxes keep their per-sandbox disk as rootfs.ext4.
			info, err = os.Stat(filepath.Join(runDir, entry.Name(), "rootfs.ext4"))
		}
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		out = append(out, heartbeatStorageMeasurement{
			SandboxID:      entry.Name(),
			AllocatedBytes: stat.Blocks * 512,
		})
	}
	return out, nil
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
