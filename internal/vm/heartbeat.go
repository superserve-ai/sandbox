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
	// Pressure, when set, is sampled after each SUCCESSFUL heartbeat and
	// published to the separate best-effort pressure endpoint — never
	// inside the heartbeat body, so no pressure outcome can ever affect
	// host liveness. Nil (older wiring, tests, hosts without the
	// advertise config) publishes nothing and the process behaves
	// exactly as before.
	Pressure func() HostPressure
	// PressureReady, when set, holds publication off until it reports
	// true — wired to the manager's reattach completion, so a restarting
	// vmd never publishes a near-zero snapshot of a half-rebuilt
	// instance map (the control plane keeps the previous report; its age
	// is the staleness signal). Nil means always ready.
	PressureReady func() bool
	// LocalAdmission declares that this daemon enforces the operator's
	// capacity limits itself. Advertised as a capability so placement can
	// tell an enforcing host from one that merely reports its load. False
	// on every host that has not opted in, which is the default.
	LocalAdmission bool
	// MaxSandboxes and MaxNetworkSlots are operator-configured admission
	// limits published alongside pressure; 0 means unset (no cap).
	MaxSandboxes    int32
	MaxNetworkSlots int32
	// LifecycleReady gates lifecycle capability publication until VMD is ready.
	LifecycleReady func() bool
	// ResolverReady gates proxy, file, and preview capability publication.
	ResolverReady func() bool
}

// pressureProbeEvery is how many beats a publisher that found the
// pressure endpoint unsupported (404: an older control plane) waits
// before probing again. Jittered per process so a fleet that all backed
// off during one deploy does not re-probe in lockstep.
const pressureProbeEvery = 20

// pressureState tracks the publisher's back-off across beats. Owned by
// the heartbeat goroutine; never shared.
type pressureState struct {
	unsupported     bool
	beatsUntilProbe int
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

	pressureURL := fmt.Sprintf("%s/internal/hosts/%s/pressure", cfg.ControlPlaneURL, cfg.HostID)

	// Pressure runs on its OWN goroutine, kicked (never blocked on) after
	// each successful heartbeat: PressureReady's dynamic gates can probe
	// systemd and cgroups with per-item budgets, and any of that on the
	// heartbeat goroutine could starve ticker beats past the control
	// plane's unhealthy threshold — best-effort telemetry must not be
	// able to interrupt liveness, by construction. The kick channel has
	// capacity one and drops when the worker is busy: a slow pressure
	// pass skips beats instead of queueing them. Same reasoning that
	// keeps the storage sampler below off this goroutine.
	pressureKick := make(chan struct{}, 1)
	go pressureLoop(ctx, client, cfg, pressureURL, cfg.Token, pressureKick, log)
	kickPressure := func() {
		select {
		case pressureKick <- struct{}{}:
		default:
		}
	}

	// Keep the first liveness POST independent of the fleet-sized filesystem
	// scan. Storage sampling runs in a separate goroutine so heartbeat posts
	// can continue even if a host has a large number of sandboxes.
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	if ok, _ := sendHeartbeat(ctx, client, cfg, url, cfg.Token, proxyHealthURL, nil, log); ok {
		kickPressure()
	}
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
			// Pressure publishes only AFTER a successful heartbeat, and
			// to its own endpoint: liveness never carries it, and the
			// ordering disambiguates the pressure 404 (after a 200
			// heartbeat the host row provably exists, so 404 can only
			// mean an older control plane without the route).
			ok, accepted := sendHeartbeat(ctx, client, cfg, url, cfg.Token, proxyHealthURL, storage, log)
			if ok {
				kickPressure()
				if publishStorage && accepted {
					cache.markSent(version, now)
				}
			}
		}
	}
}

type heartbeatStorageMeasurement struct {
	SandboxID      string `json:"sandbox_id"`
	AllocatedBytes int64  `json:"allocated_bytes"`
}

// pressureLoop owns the pressure publisher's state and serializes its
// passes; one pass per kick, kicks dropped while busy.
func pressureLoop(ctx context.Context, client *http.Client, cfg HeartbeatConfig, url, token string, kick <-chan struct{}, log zerolog.Logger) {
	ps := &pressureState{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-kick:
			sendPressure(ctx, client, cfg, url, token, ps, log)
		}
	}
}

// pressureRequest is the pressure endpoint's body. vmd_addr is the
// identity fence: the control plane refuses a report whose address does
// not match the host row, so a reclaimed-away daemon cannot overwrite
// the new holder's numbers.
type pressureRequest struct {
	VMDAddr               string `json:"vmd_addr"`
	RunningSandboxes      int32  `json:"running_sandboxes"`
	ProvisioningSandboxes int32  `json:"provisioning_sandboxes"`
	PausedSandboxes       int32  `json:"paused_sandboxes"`
	AllocatedMemoryMib    int64  `json:"allocated_memory_mib"`
	AllocatedVcpus        int64  `json:"allocated_vcpus"`
	UsedNetSlots          int32  `json:"used_net_slots"`
	ProvisioningNetSlots  int32  `json:"provisioning_net_slots"`
	WarmNetSlots          int32  `json:"warm_net_slots"`
	NetSlotCeiling        int32  `json:"net_slot_ceiling"`
	MaxNetworkSlots       int32  `json:"max_network_slots,omitempty"`
	MaxSandboxes          int32  `json:"max_sandboxes,omitempty"`
	// Omitted when zero so a control plane that predates the field is
	// unaffected; a fully described host sends nothing extra.
	UnknownAllocationVMs int32 `json:"unknown_allocation_vms,omitempty"`
}

// sendPressure publishes the capacity summary, best-effort. Runs only
// after a successful heartbeat. A 404 means the control plane predates
// the endpoint: back off and re-probe every pressureProbeEvery beats
// (jittered), so a rollout or rollback converges without operator
// action. Every other failure — auth, identity conflict, 5xx, transport
// — logs and retries on the next beat at the normal cadence; none of
// them back anything off, and none can affect the heartbeat that
// already succeeded.
func sendPressure(ctx context.Context, client *http.Client, cfg HeartbeatConfig, url, token string, ps *pressureState, log zerolog.Logger) {
	if cfg.Pressure == nil || cfg.VMDAddr == "" {
		return
	}
	if cfg.PressureReady != nil && !cfg.PressureReady() {
		return
	}
	if ps.unsupported {
		ps.beatsUntilProbe--
		if ps.beatsUntilProbe > 0 {
			return
		}
		ps.unsupported = false
	}
	p := cfg.Pressure()
	body, err := json.Marshal(pressureRequest{
		VMDAddr:               cfg.VMDAddr,
		RunningSandboxes:      p.RunningSandboxes,
		ProvisioningSandboxes: p.ProvisioningSandboxes,
		PausedSandboxes:       p.PausedSandboxes,
		AllocatedMemoryMib:    p.AllocatedMemoryMib,
		AllocatedVcpus:        p.AllocatedVcpus,
		UsedNetSlots:          p.UsedNetSlots,
		ProvisioningNetSlots:  p.ProvisioningNetSlots,
		WarmNetSlots:          p.WarmNetSlots,
		NetSlotCeiling:        p.NetSlotCeiling,
		MaxNetworkSlots:       cfg.MaxNetworkSlots,
		MaxSandboxes:          cfg.MaxSandboxes,
		UnknownAllocationVMs:  p.UnknownAllocationVMs,
	})
	if err != nil {
		log.Error().Err(err).Msg("failed to encode pressure body")
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		log.Error().Err(err).Msg("failed to create pressure request")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Warn().Err(err).Str("host_id", cfg.HostID).Msg("pressure publish failed; retrying next beat")
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		ps.unsupported = true
		ps.beatsUntilProbe = pressureProbeEvery + int(time.Now().UnixNano()%7)
		log.Info().Str("host_id", cfg.HostID).Int("probe_after_beats", ps.beatsUntilProbe).
			Msg("control plane does not support pressure publication; backing off")
	case resp.StatusCode == http.StatusConflict:
		log.Error().Str("host_id", cfg.HostID).
			Msg("pressure publish rejected: host identity held by another address")
	case resp.StatusCode != http.StatusOK:
		log.Warn().Int("status", resp.StatusCode).Str("host_id", cfg.HostID).
			Msg("pressure publish got non-200 response; retrying next beat")
	}
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
	Capabilities  []string `json:"capabilities"`
	FilesEnabled  bool     `json:"files_enabled"`
	ResolverReady bool     `json:"resolver_ready"`
}

type proxyHealthState struct {
	PreviewCapabilities []string
	FilesEnabled        bool
	ResolverReady       bool
}

const (
	capabilityCanCreate       = preview.HostCapabilityCanCreate
	capabilityCanResume       = preview.HostCapabilityCanResume
	capabilityCanPause        = preview.HostCapabilityCanPause
	capabilityCanDestroy      = preview.HostCapabilityCanDestroy
	capabilityCanProxyTraffic = preview.HostCapabilityCanProxyTraffic
	capabilityCanReadFiles    = preview.HostCapabilityCanReadFiles
	capabilityCanWriteFiles   = preview.HostCapabilityCanWriteFiles

	// capabilityCapacityPressure marks a heartbeat from a daemon that
	// publishes capacity pressure for this host.
	//
	// It is the wire contract the control plane keys its three-state
	// classification on: a host that advertises this but has no fresh
	// report is treated as one whose publisher broke or is still
	// converging, while a host that never advertises it is simply a
	// daemon that does not publish. Without it every publishing host is
	// indistinguishable from a legacy one.
	//
	// Must match the consumer-side constant
	// (internal/scheduler.HostCapabilityCapacityPressure); the two live
	// in different packages because the daemon does not import the
	// control plane.
	capabilityCapacityPressure = "capacity_pressure_v1"

	// capabilityLocalAdmission marks a daemon that enforces the operator's
	// capacity limits itself, refusing creates it has no room for.
	//
	// Separate from capacity_pressure_v1 because the two are independently
	// deployable and a host can do the first without the second: publishing
	// what it is carrying says nothing about whether it will refuse
	// anything. Placement needs to tell them apart — only a host that
	// admits locally can be relied on to hold a limit, and only such a host
	// answers a create with a capacity refusal the caller is meant to retry
	// elsewhere.
	//
	// Advertised whenever the gate is enabled, not only once it is open:
	// "enforcing, but still reconstructing" is a state the control plane
	// should see as enforcing-and-currently-refusing, never mistake for a
	// daemon that does not enforce at all.
	capabilityLocalAdmission = "local_admission_v1"
)

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
	proxyState, err := proxyHealthCapabilities(ctx, client, proxyHealthURL)
	if err != nil {
		log.Warn().Err(err).
			Str("host_id", cfg.HostID).
			Dur("duration", time.Since(started)).
			Msg("proxy health probe failed; advertising no proxy or file capabilities")
		proxyState = proxyHealthState{}
	}
	capabilities := make([]string, 0, 7)
	lifecycleReady := cfg.LifecycleReady != nil && cfg.LifecycleReady()
	resolverReady := cfg.ResolverReady != nil && cfg.ResolverReady()
	if lifecycleReady {
		capabilities = append(capabilities, capabilityCanCreate, capabilityCanResume, capabilityCanPause, capabilityCanDestroy)
	}
	if err == nil {
		if resolverReady && proxyState.ResolverReady {
			capabilities = append(capabilities, capabilityCanProxyTraffic)
			if proxyState.FilesEnabled {
				capabilities = append(capabilities, capabilityCanReadFiles, capabilityCanWriteFiles)
			}
		}
		capabilities = append(capabilities, proxyState.PreviewCapabilities...)
	}
	if cfg.Pressure != nil && cfg.VMDAddr != "" {
		// Advertised under exactly the condition sendPressure publishes
		// — deliberately NOT gated on PressureReady, which is the
		// transient startup gate. "Capable, but no fresh report yet" is
		// precisely how a host whose accounting is still converging
		// should read to a consumer: not describable, and not silently
		// mistaken for a daemon that never publishes.
		capabilities = append(capabilities, capabilityCapacityPressure)
	}
	if cfg.LocalAdmission {
		capabilities = append(capabilities, capabilityLocalAdmission)
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
	state, err := proxyHealthCapabilities(ctx, client, healthURL)
	return state.PreviewCapabilities, err
}

func proxyHealthCapabilities(ctx context.Context, client *http.Client, healthURL string) (proxyHealthState, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, healthURL, nil)
	if err != nil {
		return proxyHealthState{}, fmt.Errorf("build proxy health request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return proxyHealthState{}, fmt.Errorf("request proxy health: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return proxyHealthState{}, fmt.Errorf("proxy health returned %d", resp.StatusCode)
	}
	var health proxyHealthResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&health); err != nil {
		if err == io.EOF {
			return proxyHealthState{}, nil
		}
		return proxyHealthState{}, fmt.Errorf("decode proxy health: %w", err)
	}
	advertised := make(map[string]bool, len(health.Capabilities))
	for _, capability := range health.Capabilities {
		advertised[capability] = true
	}
	if !advertised[preview.HostCapabilityPorts] {
		return proxyHealthState{FilesEnabled: health.FilesEnabled, ResolverReady: health.ResolverReady}, nil
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
	return proxyHealthState{PreviewCapabilities: out, FilesEnabled: health.FilesEnabled, ResolverReady: health.ResolverReady}, nil
}
