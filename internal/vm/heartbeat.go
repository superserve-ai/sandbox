package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

const storageReportVersionFilename = ".storage-report-version"
const storageReportQueueFilename = ".storage-report-queue"

const (
	storageReportRetryInitial = time.Second
	storageReportRetryMax     = time.Minute

	// The local report spool is a crash-recovery buffer, not an unbounded
	// history. Once either bound is reached, the oldest unsent snapshots are
	// discarded so a prolonged control-plane outage cannot exhaust the run
	// directory. The next successful sample is still retained and retried.
	storageReportQueueMaxEntries = 32
	storageReportQueueMaxBytes   = 64 << 20
)

type HeartbeatConfig struct {
	TemplateBuildReady func() bool

	IncarnationID string
	// StorageReportID is populated by the legacy heartbeat publisher when a
	// storage snapshot is carried in the heartbeat body. It gives the
	// compatibility handoff the same retry identity as the dedicated stream.
	StorageReportID   string
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
	// Filesystem calls in storage workers cannot be canceled. Do not hold up
	// daemon shutdown waiting for a stalled disk after liveness has stopped.
	_ = runHeartbeat(ctx, cfg, log)
}

// runHeartbeat returns a join function for callers that need to release the
// run directory only after all storage I/O has finished.
func runHeartbeat(ctx context.Context, cfg HeartbeatConfig, log zerolog.Logger) func() {
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

	// Cache construction only initializes in-memory state and paths. Restoring
	// the disk-backed spool can read and decode up to the full spool bound, so
	// defer it until after the first liveness POST.
	cache := newHeartbeatStorageCacheState(runDir, log, cfg.IncarnationID)
	var storageWorkers sync.WaitGroup
	waitForStorage := func() {
		storageWorkers.Wait()
		cache.acknowledgementWrites.Wait()
	}

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
	storageURL := fmt.Sprintf("%s/internal/hosts/%s/storage-reports", cfg.ControlPlaneURL, cfg.HostID)
	// Wake-ups are coalesced; the disk-backed cache owns pending reports.
	storageKick := make(chan struct{}, 1)
	storageReady := make(chan struct{})
	storageWorkers.Add(1)
	go func() {
		defer storageWorkers.Done()
		select {
		case <-ctx.Done():
			return
		case <-storageReady:
			if cfg.IncarnationID == "" {
				legacyStorageRefreshLoop(ctx, cache, storageKick, log)
			} else {
				storageReportLoop(ctx, client, cfg, storageURL, cfg.Token, cache, storageKick, log)
			}
		}
	}()
	endpointAcknowledged := false
	heartbeatAccepted := func() {
		// A bound host also needs an acknowledgement when clearing its endpoint.
		if !endpointAcknowledged && (cfg.IncarnationID != "" || buildHeartbeatRequest(cfg, nil, nil).ProxyAddr != "") {
			log.Info().Str("host_id", cfg.HostID).Str("proxy_addr", cfg.ProxyAddr).
				Msg("host endpoint heartbeat accepted")
			endpointAcknowledged = true
		}
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
		heartbeatAccepted()
	}
	storageWorkers.Add(1)
	go func() {
		defer storageWorkers.Done()
		cache.restore()
		close(storageReady)
	}()
	storageWorkers.Add(1)
	go func() {
		defer storageWorkers.Done()
		select {
		case <-ctx.Done():
			return
		case <-storageReady:
			runOverlayStorageSampler(ctx, runDir, overlayStorageSampleInterval, cache, log)
		}
	}()
	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("heartbeat exiting")
			return waitForStorage
		case <-ticker.C:
			now := time.Now()
			var version uint64
			var heartbeatStorage []heartbeatStorageMeasurement
			heartbeatCfg := cfg
			if cfg.IncarnationID == "" {
				if pending, ok := cache.oldestPendingSnapshot(); ok {
					version = pending.version
					heartbeatStorage = pending.measurements
					heartbeatCfg.StorageReportID = cache.reportID(version).String()
				}
			}
			// Pressure publishes only AFTER a successful heartbeat, and
			// to its own endpoint: liveness never carries it, and the
			// ordering disambiguates the pressure 404 (after a 200
			// heartbeat the host row provably exists, so 404 can only
			// mean an older control plane without the route).
			// Bound VMDs publish storage through the separately acknowledged
			// stream; legacy VMDs retain the compatibility field above.
			ok, accepted := sendHeartbeat(ctx, client, heartbeatCfg, url, cfg.Token, proxyHealthURL, heartbeatStorage, log)
			if ok {
				heartbeatAccepted()
				if cfg.IncarnationID == "" && accepted {
					cache.markSentInMemory(version, now)
				}
				select {
				case storageKick <- struct{}{}:
				default:
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

type storagePublish struct {
	reportID     uuid.UUID
	version      uint64
	measurements []heartbeatStorageMeasurement
}

func legacyStorageRefreshLoop(ctx context.Context, cache *heartbeatStorageCache, kick <-chan struct{}, log zerolog.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-kick:
			version, measurements := cache.snapshot()
			if err := cache.queueForPublish(version, measurements, time.Now()); err != nil {
				log.Warn().Err(err).Msg("legacy storage refresh persistence failed")
			}
		}
	}
}

func storageReportLoop(ctx context.Context, client *http.Client, cfg HeartbeatConfig, url, token string, cache *heartbeatStorageCache, kick <-chan struct{}, log zerolog.Logger) {
	retryDelay := storageReportRetryInitial
	for {
		pending := cache.pendingSnapshot()
		if len(pending) == 0 {
			select {
			case <-ctx.Done():
				return
			case <-kick:
			}
			version, measurements := cache.snapshot()
			now := time.Now()
			if cache.shouldSend(version, now) && len(measurements) > 0 {
				if err := cache.queueForPublish(version, measurements, now); err != nil {
					log.Warn().Err(err).Str("host_id", cfg.HostID).Msg("storage report queue persistence failed")
				}
			}
			continue
		}
		p := pending[0]
		// The report ID is persisted with the queued sample. Entries from an
		// older queue format fall back to the legacy deterministic ID so an
		// in-flight retry remains idempotent across the rollout.
		reportID := p.reportID
		if reportID == uuid.Nil {
			reportID = storageReportID(cfg.HostID, cfg.IncarnationID, p.version)
		}
		if postStorageReport(ctx, client, cfg, url, token, reportID, p.measurements, log) {
			if err := cache.markSent(p.version, time.Now()); err != nil {
				// Retain the report if the local acknowledgement could not be
				// persisted. Reusing the stable report ID makes the next attempt
				// an idempotent retry after a restart.
				log.Warn().Err(err).Str("host_id", cfg.HostID).Msg("storage report acknowledgement persistence failed")
				if !waitStorageReportRetry(ctx, retryDelay) {
					return
				}
				retryDelay = nextStorageReportRetry(retryDelay)
				continue
			}
			retryDelay = storageReportRetryInitial
			continue
		}
		if !waitStorageReportRetry(ctx, retryDelay) {
			return
		}
		retryDelay = nextStorageReportRetry(retryDelay)
	}
}

func waitStorageReportRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func nextStorageReportRetry(delay time.Duration) time.Duration {
	if delay >= storageReportRetryMax/2 {
		return storageReportRetryMax
	}
	return delay * 2
}

type storageReportWire struct {
	IncarnationID string                        `json:"incarnation_id"`
	ReportID      string                        `json:"report_id"`
	Measurements  []heartbeatStorageMeasurement `json:"measurements"`
}

func postStorageReport(ctx context.Context, client *http.Client, cfg HeartbeatConfig, url, token string, reportID uuid.UUID, measurements []heartbeatStorageMeasurement, log zerolog.Logger) bool {
	body, err := json.Marshal(storageReportWire{IncarnationID: cfg.IncarnationID, ReportID: reportID.String(), Measurements: measurements})
	if err != nil {
		log.Error().Err(err).Str("host_id", cfg.HostID).Msg("failed to encode storage report")
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Error().Err(err).Str("host_id", cfg.HostID).Msg("failed to create storage report request")
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Warn().Err(err).Str("host_id", cfg.HostID).Msg("storage report publish failed; retaining report for retry")
		return false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		log.Warn().Int("status", resp.StatusCode).Str("host_id", cfg.HostID).Msg("storage report rejected; retaining report for retry")
		return false
	}
	return true
}

// pressureRequest is the pressure endpoint's body. vmd_addr is the
// identity fence: the control plane refuses a report whose address does
// not match the host row, so a reclaimed-away daemon cannot overwrite
// the new holder's numbers.
type pressureRequest struct {
	IncludedBuildVMIDs     []string `json:"included_build_vm_ids"`
	IncludedBuildSlotVMIDs []string `json:"included_build_slot_vm_ids,omitempty"`
	IncarnationID          string   `json:"incarnation_id,omitempty"`
	VMDAddr                string   `json:"vmd_addr"`
	RunningSandboxes       int32    `json:"running_sandboxes"`
	ProvisioningSandboxes  int32    `json:"provisioning_sandboxes"`
	PausedSandboxes        int32    `json:"paused_sandboxes"`
	AllocatedMemoryMib     int64    `json:"allocated_memory_mib"`
	AllocatedVcpus         int64    `json:"allocated_vcpus"`
	UsedNetSlots           int32    `json:"used_net_slots"`
	ProvisioningNetSlots   int32    `json:"provisioning_net_slots"`
	WarmNetSlots           int32    `json:"warm_net_slots"`
	NetSlotCeiling         int32    `json:"net_slot_ceiling"`
	MaxNetworkSlots        int32    `json:"max_network_slots,omitempty"`
	MaxSandboxes           int32    `json:"max_sandboxes,omitempty"`
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
		IncludedBuildVMIDs:     p.IncludedBuildVMIDs,
		IncludedBuildSlotVMIDs: p.IncludedBuildSlotVMIDs,
		IncarnationID:          cfg.IncarnationID,
		VMDAddr:                cfg.VMDAddr,
		RunningSandboxes:       p.RunningSandboxes,
		ProvisioningSandboxes:  p.ProvisioningSandboxes,
		PausedSandboxes:        p.PausedSandboxes,
		AllocatedMemoryMib:     p.AllocatedMemoryMib,
		AllocatedVcpus:         p.AllocatedVcpus,
		UsedNetSlots:           p.UsedNetSlots,
		ProvisioningNetSlots:   p.ProvisioningNetSlots,
		WarmNetSlots:           p.WarmNetSlots,
		NetSlotCeiling:         p.NetSlotCeiling,
		MaxNetworkSlots:        cfg.MaxNetworkSlots,
		MaxSandboxes:           cfg.MaxSandboxes,
		UnknownAllocationVMs:   p.UnknownAllocationVMs,
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
	IncarnationID     string                        `json:"incarnation_id,omitempty"`
	StorageReportID   string                        `json:"storage_report_id,omitempty"`
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
	capabilitySavedSnapshots  = preview.HostCapabilitySavedSnapshots
	capabilitySnapshotForks   = preview.HostCapabilitySnapshotForks

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
)

type heartbeatStorageCache struct {
	mu                    sync.RWMutex
	persistMu             sync.Mutex
	acknowledgementWrites sync.WaitGroup

	measurements  []heartbeatStorageMeasurement
	version       uint64
	reportSpace   uuid.UUID
	sentVersion   uint64
	sentAt        time.Time
	versionPath   string
	queuePath     string
	pending       []storagePublish
	incarnationID string
	log           zerolog.Logger
}

type storageReportQueueState struct {
	IncarnationID string                        `json:"incarnation_id,omitempty"`
	ReportSpace   string                        `json:"report_space,omitempty"`
	Version       uint64                        `json:"version"`
	Measurements  []heartbeatStorageMeasurement `json:"measurements,omitempty"`
	Pending       []storageReportQueueEntry     `json:"pending"`
}

type storageReportQueueEntry struct {
	ReportID     string                        `json:"report_id,omitempty"`
	Version      uint64                        `json:"version"`
	Measurements []heartbeatStorageMeasurement `json:"measurements"`
}

func newHeartbeatStorageCache(runDir string, log zerolog.Logger, incarnationIDs ...string) *heartbeatStorageCache {
	c := newHeartbeatStorageCacheState(runDir, log, incarnationIDs...)
	c.restore()
	return c
}

func newHeartbeatStorageCacheState(runDir string, log zerolog.Logger, incarnationIDs ...string) *heartbeatStorageCache {
	c := &heartbeatStorageCache{reportSpace: uuid.New(), log: log}
	if len(incarnationIDs) > 0 {
		c.incarnationID = incarnationIDs[0]
	}
	if runDir == "" {
		return c
	}
	c.versionPath = filepath.Join(runDir, storageReportVersionFilename)
	// Legacy heartbeats also need the spool: their compatibility handoff is
	// acknowledged separately and must survive a VMD restart while it is
	// waiting for durable acceptance.
	if runDir != "" {
		c.queuePath = filepath.Join(runDir, storageReportQueueFilename)
	}
	return c
}

func (c *heartbeatStorageCache) restore() {
	// Perform filesystem I/O against an isolated state object. Applying the
	// decoded snapshot is a short mutex-protected swap, so a slow spool read
	// cannot block heartbeat snapshots after the first liveness POST.
	state := heartbeatStorageCache{
		reportSpace:   c.reportSpace,
		versionPath:   c.versionPath,
		queuePath:     c.queuePath,
		incarnationID: c.incarnationID,
		log:           c.log,
	}
	state.restoreFromDisk()
	c.mu.Lock()
	c.reportSpace = state.reportSpace
	c.measurements = state.measurements
	c.version = state.version
	c.sentVersion = state.sentVersion
	c.sentAt = state.sentAt
	c.pending = state.pending
	c.mu.Unlock()
}

func (c *heartbeatStorageCache) restoreFromDisk() {
	incarnationReset := false
	if c.queuePath != "" {
		var data []byte
		var err error
		if info, statErr := os.Stat(c.queuePath); statErr == nil && info.Size() > storageReportQueueMaxBytes {
			c.log.Warn().Str("path", c.queuePath).Int64("bytes", info.Size()).
				Int("max_bytes", storageReportQueueMaxBytes).
				Msg("storage report queue exceeds spool limit; starting fresh")
			data = nil
		} else {
			data, err = os.ReadFile(c.queuePath)
		}
		if err == nil {
			var state storageReportQueueState
			if err := json.Unmarshal(data, &state); err != nil {
				c.log.Warn().Err(err).Str("path", c.queuePath).Msg("storage report queue state invalid; starting fresh")
			} else {
				if reportSpace, parseErr := uuid.Parse(state.ReportSpace); parseErr == nil && reportSpace != uuid.Nil {
					c.reportSpace = reportSpace
				}
				c.version = state.Version
				c.measurements = append([]heartbeatStorageMeasurement(nil), state.Measurements...)
				if state.IncarnationID == c.incarnationID {
					c.pending = make([]storagePublish, len(state.Pending))
					for i, p := range state.Pending {
						var reportID uuid.UUID
						if parsed, parseErr := uuid.Parse(p.ReportID); parseErr == nil {
							reportID = parsed
						}
						c.pending[i] = storagePublish{reportID: reportID, version: p.Version, measurements: append([]heartbeatStorageMeasurement(nil), p.Measurements...)}
					}
					var dropped int
					c.pending, dropped = c.boundPending(c.version, c.measurements, c.pending)
					if dropped > 0 {
						c.log.Warn().Int("dropped_reports", dropped).Int("max_reports", storageReportQueueMaxEntries).
							Msg("storage report queue overflow; dropping oldest unsent snapshots")
					}
				} else {
					// A run directory can survive a VMD reclaim. Never replay the
					// previous incarnation's payload or acknowledgement state under
					// the new identity.
					c.reportSpace = uuid.New()
					c.pending = nil
					c.measurements = nil
					c.sentVersion = 0
					c.sentAt = time.Time{}
					incarnationReset = true
				}
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			c.log.Warn().Err(err).Str("path", c.queuePath).Msg("storage report queue state unavailable; starting fresh")
		}
	}
	data, err := os.ReadFile(c.versionPath)
	if errors.Is(err, os.ErrNotExist) {
		if len(c.pending) == 0 && !incarnationReset {
			c.sentVersion = c.version
		}
		return
	}
	if err != nil {
		c.log.Warn().Err(err).Str("path", c.versionPath).Msg("storage report version state unavailable; starting fresh")
		if len(c.pending) == 0 && !incarnationReset {
			c.sentVersion = c.version
		}
		return
	}
	version, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		c.log.Warn().Err(err).Str("path", c.versionPath).Msg("storage report version state invalid; starting fresh")
	} else if version > c.version {
		c.version = version
	}
	if len(c.pending) == 0 && !incarnationReset {
		c.sentVersion = c.version
	}
}

func storageReportID(hostID, incarnationID string, version uint64) uuid.UUID {
	// This is retained for compatibility with queue entries written before
	// reportSpace was persisted. New reports use the cache's durable namespace
	// so a reset version cannot collide with an accepted report.
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("storage-report:"+hostID+":"+incarnationID+":"+strconv.FormatUint(version, 10)))
}

func storageReportIDInSpace(reportSpace uuid.UUID, version uint64) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("storage-report:"+reportSpace.String()+":"+strconv.FormatUint(version, 10)))
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
	if len(c.pending) > 0 {
		return true
	}
	if len(c.measurements) == 0 {
		return false
	}
	if version > c.sentVersion {
		return true
	}
	if c.sentAt.IsZero() {
		return true
	}
	return !c.sentAt.IsZero() && now.Sub(c.sentAt) >= overlayStorageSampleInterval
}

func (c *heartbeatStorageCache) pendingSnapshot() []storagePublish {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return cloneStoragePublishes(c.pending)
}

func (c *heartbeatStorageCache) oldestPendingSnapshot() (storagePublish, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.pending) == 0 {
		return storagePublish{}, false
	}
	p := c.pending[0]
	p.measurements = append([]heartbeatStorageMeasurement(nil), p.measurements...)
	return p, true
}

func (c *heartbeatStorageCache) reportID(version uint64) uuid.UUID {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, p := range c.pending {
		if p.version == version && p.reportID != uuid.Nil {
			return p.reportID
		}
	}
	if c.reportSpace != uuid.Nil {
		return storageReportIDInSpace(c.reportSpace, version)
	}
	return uuid.New()
}

func cloneStoragePublishes(in []storagePublish) []storagePublish {
	if len(in) == 0 {
		return nil
	}
	out := make([]storagePublish, len(in))
	for i, p := range in {
		out[i] = storagePublish{reportID: p.reportID, version: p.version, measurements: append([]heartbeatStorageMeasurement(nil), p.measurements...)}
	}
	return out
}

func (c *heartbeatStorageCache) markSent(version uint64, now time.Time) error {
	return c.updatePersistedState(func(state *heartbeatStorageCache) error {
		return state.markSentLocked(version, now, true)
	})
}

func (c *heartbeatStorageCache) markSentInMemory(version uint64, now time.Time) {
	c.mu.Lock()
	_ = c.markSentLocked(version, now, false)
	c.mu.Unlock()

	// Legacy heartbeat acknowledgements arrive on the liveness goroutine, so
	// persist the cleared spool asynchronously. Without this write, a VMD
	// restart would restore an already accepted snapshot and resend it forever.
	c.acknowledgementWrites.Add(1)
	go func() {
		defer c.acknowledgementWrites.Done()
		if err := c.updatePersistedState(func(state *heartbeatStorageCache) error {
			return state.persistStateLocked(state.version, state.measurements, state.pending)
		}); err != nil {
			c.log.Warn().Err(err).Msg("storage report acknowledgement persistence failed")
		}
	}()
}

// Writers serialize against each other, but persist a detached snapshot so
// filesystem latency never holds the mutex used by heartbeat readers. Only
// legacy acknowledgements can change the live state while a write is pending.
func (c *heartbeatStorageCache) updatePersistedState(update func(*heartbeatStorageCache) error) error {
	c.persistMu.Lock()
	defer c.persistMu.Unlock()
	c.mu.RLock()
	state := heartbeatStorageCache{
		measurements: c.measurements, version: c.version, reportSpace: c.reportSpace,
		sentVersion: c.sentVersion, sentAt: c.sentAt,
		versionPath: c.versionPath, queuePath: c.queuePath, pending: c.pending,
		incarnationID: c.incarnationID, log: c.log,
	}
	c.mu.RUnlock()
	if err := update(&state); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sentVersion > state.sentVersion || (c.sentVersion == state.sentVersion && c.sentAt.After(state.sentAt)) {
		_ = state.markSentLocked(c.sentVersion, c.sentAt, false)
	}
	c.measurements = state.measurements
	c.version = state.version
	c.reportSpace = state.reportSpace
	c.sentVersion = state.sentVersion
	c.sentAt = state.sentAt
	c.pending = state.pending
	return nil
}

func (c *heartbeatStorageCache) markSentLocked(version uint64, now time.Time, persist bool) error {
	if version < c.sentVersion {
		return nil
	}
	pending := make([]storagePublish, 0, len(c.pending))
	for _, p := range c.pending {
		if p.version > version {
			pending = append(pending, p)
		}
	}
	if persist {
		if err := c.persistStateLocked(c.version, c.measurements, pending); err != nil {
			return err
		}
	}
	c.pending = pending
	c.sentVersion = version
	c.sentAt = now
	return nil
}

func (c *heartbeatStorageCache) store(measurements []heartbeatStorageMeasurement) error {
	return c.updatePersistedState(func(state *heartbeatStorageCache) error {
		return state.storeState(measurements)
	})
}

func (c *heartbeatStorageCache) storeState(measurements []heartbeatStorageMeasurement) error {
	if reflect.DeepEqual(c.measurements, measurements) {
		return nil
	}
	nextVersion := c.version + 1
	if c.reportSpace == uuid.Nil {
		c.reportSpace = uuid.New()
	}
	pending := cloneStoragePublishes(c.pending)
	if len(measurements) == 0 {
	} else {
		pending = append(pending, storagePublish{reportID: storageReportIDInSpace(c.reportSpace, nextVersion), version: nextVersion, measurements: append([]heartbeatStorageMeasurement(nil), measurements...)})
	}
	var dropped int
	pending, dropped = c.boundPending(nextVersion, measurements, pending)
	if dropped > 0 {
		c.log.Warn().Int("dropped_reports", dropped).Int("max_reports", storageReportQueueMaxEntries).
			Msg("storage report queue overflow; dropping oldest unsent snapshots")
	}
	if err := c.persistStateLocked(nextVersion, measurements, pending); err != nil {
		return err
	}
	c.measurements = append([]heartbeatStorageMeasurement(nil), measurements...)
	c.version = nextVersion
	c.pending = pending
	return nil
}

func (c *heartbeatStorageCache) queueForPublish(version uint64, measurements []heartbeatStorageMeasurement, now time.Time) error {
	return c.updatePersistedState(func(state *heartbeatStorageCache) error {
		return state.queueForPublishState(version, measurements, now)
	})
}

func (c *heartbeatStorageCache) queueForPublishState(version uint64, measurements []heartbeatStorageMeasurement, now time.Time) error {
	// A sample may have changed while this publisher waited for the writer.
	// Never append an older snapshot behind a newer one or replace a retry.
	if version != c.version || !reflect.DeepEqual(measurements, c.measurements) || len(measurements) == 0 || len(c.pending) > 0 {
		return nil
	}
	if version <= c.sentVersion && !c.sentAt.IsZero() && now.Sub(c.sentAt) < overlayStorageSampleInterval {
		return nil
	}
	// Unchanged bytes are a new observation once the refresh interval elapses.
	// Reusing an acknowledged identity would deduplicate away that observation.
	if version <= c.sentVersion {
		version = c.version + 1
	}
	if c.reportSpace == uuid.Nil {
		c.reportSpace = uuid.New()
	}
	pending := []storagePublish{{reportID: storageReportIDInSpace(c.reportSpace, version), version: version, measurements: append([]heartbeatStorageMeasurement(nil), measurements...)}}
	var dropped int
	pending, dropped = c.boundPending(version, measurements, pending)
	if dropped > 0 {
		c.log.Warn().Int("dropped_reports", dropped).Int("max_reports", storageReportQueueMaxEntries).
			Msg("storage report queue overflow; dropping oldest unsent snapshots")
	}
	if err := c.persistStateLocked(version, measurements, pending); err != nil {
		return err
	}
	c.version = version
	c.measurements = append([]heartbeatStorageMeasurement(nil), measurements...)
	c.pending = pending
	return nil
}

func (c *heartbeatStorageCache) persistStateLocked(version uint64, measurements []heartbeatStorageMeasurement, pending []storagePublish) error {
	if c.queuePath != "" {
		data, err := json.Marshal(storageReportQueueState{
			IncarnationID: c.incarnationID,
			ReportSpace:   c.reportSpace.String(),
			Version:       version,
			Measurements:  append([]heartbeatStorageMeasurement(nil), measurements...),
			Pending:       storageReportQueueEntries(pending),
		})
		if err != nil {
			return err
		}
		if len(data)+1 > storageReportQueueMaxBytes {
			return fmt.Errorf("storage report queue exceeds spool limit: %d bytes", len(data)+1)
		}
		if err := persistStorageReportFile(c.queuePath, data); err != nil {
			return err
		}
	}
	if c.versionPath != "" {
		if err := persistStorageReportVersion(c.versionPath, version); err != nil {
			// The queue file is the authoritative durable stream. Its state
			// already carries the version, so a secondary version-file failure
			// must not turn a durably queued report into an in-memory-only one.
			if c.queuePath == "" {
				return err
			}
		}
	}
	return nil
}

func (c *heartbeatStorageCache) boundPending(version uint64, measurements []heartbeatStorageMeasurement, pending []storagePublish) ([]storagePublish, int) {
	dropped := 0
	for len(pending) > storageReportQueueMaxEntries {
		pending = pending[1:]
		dropped++
	}
	base, err := json.Marshal(storageReportQueueState{
		IncarnationID: c.incarnationID,
		ReportSpace:   c.reportSpace.String(),
		Version:       version,
		Measurements:  measurements,
		Pending:       []storageReportQueueEntry{},
	})
	if err != nil {
		return pending, dropped
	}
	entryBytes := make([]int, len(pending))
	total := len(base)
	for i, p := range pending {
		data, marshalErr := json.Marshal(storageReportQueueEntry{
			ReportID:     p.reportID.String(),
			Version:      p.version,
			Measurements: p.measurements,
		})
		if marshalErr != nil {
			return pending, dropped
		}
		entryBytes[i] = len(data)
		total += len(data)
	}
	if len(pending) > 1 {
		total += len(pending) - 1
	}
	for len(pending) > 0 && total+1 > storageReportQueueMaxBytes {
		separator := 0
		if len(pending) > 1 {
			separator = 1
		}
		total -= entryBytes[0] + separator
		entryBytes = entryBytes[1:]
		pending = pending[1:]
		dropped++
	}
	return pending, dropped
}

func storageReportQueueEntries(pending []storagePublish) []storageReportQueueEntry {
	queue := make([]storageReportQueueEntry, len(pending))
	for i, p := range pending {
		queue[i] = storageReportQueueEntry{ReportID: p.reportID.String(), Version: p.version, Measurements: append([]heartbeatStorageMeasurement(nil), p.measurements...)}
	}
	return queue
}

func persistStorageReportFile(path string, data []byte) error {
	return writeStorageReportFile(path, data, syncDir)
}

func writeStorageReportFile(path string, data []byte, syncDirectory func(string) error) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	// Renaming makes the new state visible, but only syncing the parent makes
	// that name durable. On failure retain the in-memory state for a safe retry.
	return syncDirectory(filepath.Dir(path))
}

func persistStorageReportVersion(path string, version uint64) error {
	return persistStorageReportFile(path, []byte(strconv.FormatUint(version, 10)))
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
	capabilities := make([]string, 0, 8)
	if cfg.TemplateBuildReady != nil && cfg.TemplateBuildReady() && cfg.Token != "" && cfg.ControlPlaneURL != "" {
		capabilities = append(capabilities, "template_build_v1")
	}
	lifecycleReady := cfg.LifecycleReady != nil && cfg.LifecycleReady()
	resolverReady := cfg.ResolverReady != nil && cfg.ResolverReady()
	if lifecycleReady {
		capabilities = append(capabilities, capabilityCanCreate, capabilityCanResume, capabilityCanPause, capabilityCanDestroy, capabilitySavedSnapshots, capabilitySnapshotForks)
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
			cfg.StorageReportID = ""
			return postHeartbeat(ctx, client, cfg, url, token, capabilities, nil, log, started)
		}
		if len(storage) > 0 && resp.StatusCode == http.StatusBadRequest && isStorageReportIDUnsupported(respBody) {
			log.Warn().
				Int("status", resp.StatusCode).
				Msg("heartbeat storage report ID rejected by an older control plane; retrying without storage")
			// Do not send the same snapshot through the old random-ID staging
			// path: the local spool retains it until a control plane that can
			// acknowledge its stable identity is available.
			cfg.StorageReportID = ""
			return postHeartbeat(ctx, client, cfg, url, token, capabilities, nil, log, started)
		}
		log.Warn().Int("status", resp.StatusCode).Msg("heartbeat got non-200 response")
		return false, false
	}
	if storage == nil {
		return true, false
	}
	var response struct {
		StorageAccepted *bool `json:"storage_accepted"`
	}
	if err := json.Unmarshal(respBody, &response); err != nil || response.StorageAccepted == nil {
		// A legacy control plane that does not describe the compatibility
		// handoff has not durably acknowledged this snapshot.
		return true, false
	}
	return true, *response.StorageAccepted
}

func isStorageFieldUnsupported(body []byte) bool {
	return bytes.Contains(body, []byte(`unknown field "storage"`)) ||
		bytes.Contains(body, []byte(`unknown field \"storage\"`))
}

func isStorageReportIDUnsupported(body []byte) bool {
	return bytes.Contains(body, []byte(`unknown field "storage_report_id"`)) ||
		bytes.Contains(body, []byte(`unknown field \"storage_report_id\"`))
}

func buildHeartbeatRequest(cfg HeartbeatConfig, capabilities []string, storage []heartbeatStorageMeasurement) heartbeatRequest {
	req := heartbeatRequest{
		IncarnationID:   cfg.IncarnationID,
		StorageReportID: cfg.StorageReportID,
		Capabilities:    capabilities,
		Storage:         storage,
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
	if err := cache.store(measurements); err != nil {
		log.Warn().Err(err).Msg("overlay storage sample not persisted; keeping previous cached sample")
	}
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
