package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

const (
	maxHostCapabilities     = 32
	maxHostCapabilityLength = 64
	maxHostFieldLength      = 256
	maxHostStorageSamples   = 200000
)

type hostStorageMeasurement struct {
	SandboxID      string `json:"sandbox_id"`
	AllocatedBytes int64  `json:"allocated_bytes"`
}

type hostHeartbeatRequest struct {
	Capabilities []string                 `json:"capabilities"`
	Storage      []hostStorageMeasurement `json:"storage,omitempty"`

	// Self-description, sent by vmds that support self-registration. When a
	// heartbeat arrives for an unknown host id with a complete description,
	// the host row is created in 'provisioning'; an operator activates it.
	VMDAddr           string `json:"vmd_addr,omitempty"`
	ProxyAddr         string `json:"proxy_addr,omitempty"`
	Region            string `json:"region,omitempty"`
	CapacityMemoryMib int32  `json:"capacity_memory_mib,omitempty"`
	CapacityVcpus     int32  `json:"capacity_vcpus,omitempty"`
}

func (r hostHeartbeatRequest) describesHost() bool {
	return r.VMDAddr != "" && r.ProxyAddr != "" && r.Region != "" &&
		r.CapacityMemoryMib > 0 && r.CapacityVcpus > 0
}

var (
	errHostNotRegistered      = errors.New("host not registered")
	errHostIdentityConflict   = errors.New("host identity in use")
	errHostPartialDescription = errors.New("partial host description")
	errHostIdentityRequired   = errors.New("host identity required")
)

// HostHeartbeat handles POST /internal/hosts/:host_id/heartbeat.
// VMD calls this every 30s to prove liveness. The control plane updates
// last_heartbeat_at; a background detector marks hosts unhealthy after
// 2 minutes of silence. If the host was previously marked unhealthy, the
// heartbeat automatically re-activates it (recovery from transient outage).
func (h *Handlers) HostHeartbeat(c *gin.Context) {
	hostID := c.Param("host_id")
	if hostID == "" {
		respondErrorMsg(c, "bad_request", "host_id is required", http.StatusBadRequest)
		return
	}

	var req hostHeartbeatRequest
	if c.Request.ContentLength != 0 {
		if err := bindJSONStrict(c, &req); err != nil {
			respondErrorMsg(c, "bad_request", "Invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if len(req.Capabilities) > maxHostCapabilities {
		respondErrorMsg(c, "bad_request", "too many capabilities", http.StatusBadRequest)
		return
	}
	if len(req.Storage) > maxHostStorageSamples {
		respondErrorMsg(c, "bad_request", "too many storage measurements", http.StatusBadRequest)
		return
	}
	for _, f := range []string{req.VMDAddr, req.ProxyAddr, req.Region} {
		if len(f) > maxHostFieldLength {
			respondErrorMsg(c, "bad_request", "host description fields must be short", http.StatusBadRequest)
			return
		}
	}
	capabilities := make([]string, 0, len(req.Capabilities))
	for _, capability := range req.Capabilities {
		if capability == "" || len(capability) > maxHostCapabilityLength {
			respondErrorMsg(c, "bad_request", "capability entries must be non-empty and short", http.StatusBadRequest)
			return
		}
		capabilities = append(capabilities, capability)
	}
	storageIDs := make([]uuid.UUID, 0, len(req.Storage))
	storageMiB := make([]int32, 0, len(req.Storage))
	for _, measurement := range req.Storage {
		sandboxID, err := uuid.Parse(measurement.SandboxID)
		if err != nil || measurement.AllocatedBytes < 0 {
			respondErrorMsg(c, "bad_request", "invalid storage measurement", http.StatusBadRequest)
			return
		}
		mib := (measurement.AllocatedBytes + (1 << 20) - 1) >> 20
		if mib > int64(^uint32(0)>>1) {
			respondErrorMsg(c, "bad_request", "storage measurement is too large", http.StatusBadRequest)
			return
		}
		storageIDs = append(storageIDs, sandboxID)
		storageMiB = append(storageMiB, int32(mib))
	}

	ctx := c.Request.Context()
	registered := false
	reclaimed := false
	beat := func(q *db.Queries) (status, prevStatus string, _ error) {
		host, err := q.GetHostForUpdate(ctx, hostID)
		if err == pgx.ErrNoRows {
			if !req.describesHost() {
				return "", "", errHostNotRegistered
			}
			created, err := q.RegisterHost(ctx, db.RegisterHostParams{
				ID:                hostID,
				VmdAddr:           req.VMDAddr,
				ProxyAddr:         req.ProxyAddr,
				Region:            req.Region,
				CapacityMemoryMib: req.CapacityMemoryMib,
				CapacityVcpus:     req.CapacityVcpus,
			})
			if err != nil {
				return "", "", err
			}
			registered = true
			if err := q.SyncHostCapabilities(ctx, db.SyncHostCapabilitiesParams{
				HostID: hostID, Capabilities: capabilities,
			}); err != nil {
				return "", "", err
			}
			if len(storageIDs) > 0 {
				if _, err := q.UpdateHostSandboxStorageMeasurements(ctx, db.UpdateHostSandboxStorageMeasurementsParams{
					SandboxIds: storageIDs,
					DiskMib:    storageMiB,
					HostID:     hostID,
				}); err != nil {
					return "", "", err
				}
			}
			return created.Status, created.Status, nil
		}
		if err != nil {
			return "", "", err
		}

		if host.IdentityBound && !req.describesHost() {
			return "", "", errHostIdentityRequired
		}

		if req.VMDAddr != "" && req.VMDAddr != host.VmdAddr {
			holderAlive := host.LastHeartbeatAt.Valid &&
				time.Since(host.LastHeartbeatAt.Time) < heartbeatTimeout
			if holderAlive {
				return "", "", errHostIdentityConflict
			}
			if !req.describesHost() {
				return "", "", errHostPartialDescription
			}
			if err := q.UpdateHostAddresses(ctx, db.UpdateHostAddressesParams{
				ID:                hostID,
				VmdAddr:           req.VMDAddr,
				ProxyAddr:         req.ProxyAddr,
				Region:            req.Region,
				CapacityMemoryMib: req.CapacityMemoryMib,
				CapacityVcpus:     req.CapacityVcpus,
			}); err != nil {
				return "", "", err
			}
			// The old machine's pressure is meaningless for the new
			// holder: clear it in the same transaction, or a stale report
			// would describe a machine that no longer holds the identity.
			if err := q.DeleteHostPressure(ctx, hostID); err != nil {
				return "", "", err
			}
			reclaimed = true
			log.Warn().Str("host_id", hostID).Str("vmd_addr", req.VMDAddr).
				Msg("host identity reclaimed from a silent holder")
		}

		row, err := q.UpdateHostHeartbeat(ctx, hostID)
		if err != nil {
			return "", "", err
		}
		if err := q.SyncHostCapabilities(ctx, db.SyncHostCapabilitiesParams{
			HostID: hostID, Capabilities: capabilities,
		}); err != nil {
			return "", "", err
		}
		if len(storageIDs) > 0 {
			if _, err := q.UpdateHostSandboxStorageMeasurements(ctx, db.UpdateHostSandboxStorageMeasurementsParams{
				SandboxIds: storageIDs,
				DiskMib:    storageMiB,
				HostID:     hostID,
			}); err != nil {
				return "", "", err
			}
		}
		if !host.IdentityBound && req.describesHost() && req.VMDAddr == host.VmdAddr {
			if err := q.BindHostIdentity(ctx, hostID); err != nil {
				return "", "", err
			}
		}
		return row.Status, row.PrevStatus, nil
	}

	var host db.UpdateHostHeartbeatRow
	var err error
	if h.Pool == nil {
		var status, prevStatus string
		status, prevStatus, err = beat(h.DB)
		host.Status = status
		host.PrevStatus = prevStatus
	} else {
		var tx pgx.Tx
		if tx, err = h.Pool.Begin(ctx); err == nil {
			defer tx.Rollback(ctx)
			var status, prevStatus string
			if status, prevStatus, err = beat(h.DB.WithTx(tx)); err == nil {
				host.Status = status
				host.PrevStatus = prevStatus
				err = tx.Commit(ctx)
			}
		}
	}
	if err != nil {
		if err == errHostNotRegistered {
			respondErrorMsg(c, "not_found", "host not found", http.StatusNotFound)
			return
		}
		if err == errHostIdentityConflict {
			log.Warn().Str("host_id", hostID).Str("vmd_addr", req.VMDAddr).
				Msg("heartbeat rejected: identity in use by a live host at another address")
			respondErrorMsg(c, "conflict", "host identity in use by a live host", http.StatusConflict)
			return
		}
		if err == errHostIdentityRequired {
			log.Warn().Str("host_id", hostID).
				Msg("heartbeat rejected: identity-bound host sent a description-less heartbeat")
			respondErrorMsg(c, "conflict",
				"host identity is bound; heartbeats must carry the complete self-description",
				http.StatusConflict)
			return
		}
		if err == errHostPartialDescription {
			log.Warn().Str("host_id", hostID).Str("vmd_addr", req.VMDAddr).
				Msg("heartbeat rejected: address claim without a complete host description")
			respondErrorMsg(c, "bad_request", "claiming a host address requires a complete host description", http.StatusBadRequest)
			return
		}
		log.Error().Err(err).Str("host_id", hostID).Msg("UpdateHostHeartbeat failed")
		respondError(c, ErrInternal)
		return
	}

	if registered {
		log.Info().Str("host_id", hostID).Str("vmd_addr", req.VMDAddr).
			Str("region", req.Region).Msg("host self-registered as provisioning")
	}
	if reclaimed {
		if h.Hosts != nil {
			h.Hosts.Invalidate(hostID)
		}
		if h.Scheduler != nil {
			h.Scheduler.Invalidate()
		}
	}
	log.Debug().Str("host_id", hostID).Strs("capabilities", capabilities).
		Str("status", host.Status).Str("prev_status", host.PrevStatus).
		Msg("host heartbeat persisted")
	if host.PrevStatus == "unhealthy" && host.Status == "active" {
		// The heartbeat just recovered this host; drop the scheduler's cached
		// list so its capacity is usable now, not after the cache TTL.
		log.Info().Str("host_id", hostID).Msg("host recovered via heartbeat")
		if h.Scheduler != nil {
			h.Scheduler.Invalidate()
		}
	}

	c.JSON(http.StatusOK, gin.H{"status": host.Status})
}

type hostStatusRequest struct {
	Status string `json:"status"`
}

// HostUpdateStatus handles POST /internal/hosts/:host_id/status — the
// operator lever (hostctl) for activate and drain. Machine-managed states
// (provisioning, unhealthy) are not settable here.
func (h *Handlers) HostUpdateStatus(c *gin.Context) {
	hostID := c.Param("host_id")
	var req hostStatusRequest
	if err := bindJSONStrict(c, &req); err != nil {
		respondErrorMsg(c, "bad_request", "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Status != "active" && req.Status != "draining" {
		respondErrorMsg(c, "bad_request", "status must be one of: active, draining", http.StatusBadRequest)
		return
	}

	ctx := c.Request.Context()
	host, err := h.DB.UpdateHostStatus(ctx, db.UpdateHostStatusParams{
		ID: hostID, Status: req.Status,
		// Activation demands a heartbeat fresher than the unhealthy
		// threshold; the predicate lives in the UPDATE so there is no
		// check-then-act window.
		ActiveHeartbeatAfter: pgtype.Timestamptz{Time: time.Now().Add(-heartbeatTimeout), Valid: true},
	})
	if err == pgx.ErrNoRows {
		// Zero rows is either an unknown host or an activation refused for
		// heartbeat staleness — disambiguate for the operator.
		if _, gerr := h.DB.GetHost(ctx, hostID); gerr == pgx.ErrNoRows {
			respondErrorMsg(c, "not_found", "host not found", http.StatusNotFound)
			return
		}
		log.Warn().Str("host_id", hostID).Msg("activation refused: heartbeat stale or absent")
		respondErrorMsg(c, "conflict",
			"host has no live heartbeat; refusing to activate a host the fleet cannot see",
			http.StatusConflict)
		return
	}
	if err != nil {
		log.Error().Err(err).Str("host_id", hostID).Msg("UpdateHostStatus failed")
		respondError(c, ErrInternal)
		return
	}

	log.Info().Str("host_id", hostID).Str("status", host.Status).
		Msg("host status changed by operator")
	if h.Scheduler != nil {
		h.Scheduler.Invalidate()
	}
	c.JSON(http.StatusOK, gin.H{"id": host.ID, "status": host.Status})
}

// HostList handles GET /internal/hosts — the operator view behind
// `hostctl list`: every host with liveness and sandbox counts. `?id=` scopes
// the counts to one host so drain polling doesn't recompute them fleet-wide.
func (h *Handlers) HostList(c *gin.Context) {
	var idFilter *string
	if id := c.Query("id"); id != "" {
		idFilter = &id
	}
	rows, err := h.DB.ListHostsAdmin(c.Request.Context(), idFilter)
	if err != nil {
		log.Error().Err(err).Msg("ListHostsAdmin failed")
		respondError(c, ErrInternal)
		return
	}

	type hostView struct {
		ID                string  `json:"id"`
		Status            string  `json:"status"`
		Region            string  `json:"region"`
		VMDAddr           string  `json:"vmd_addr"`
		ProxyAddr         string  `json:"proxy_addr"`
		CapacityMemoryMib int32   `json:"capacity_memory_mib"`
		CapacityVcpus     int32   `json:"capacity_vcpus"`
		LastHeartbeatAt   *string `json:"last_heartbeat_at"`
		RunningCount      int32   `json:"running_count"`
		TransitionalCount int32   `json:"transitional_count"`
		PausedCount       int32   `json:"paused_count"`
		BuildingCount     int32   `json:"building_count"`
		PausedUnbacked    int32   `json:"paused_unbacked_count"`
		// Pressure fields are pointers: nil means the host has never
		// published pressure (older vmd, or publication not enabled) —
		// "unknown" must never render as a plausible zero.
		PressureAllocatedMemoryMib *int64  `json:"pressure_allocated_memory_mib"`
		PressureAllocatedVcpus     *int64  `json:"pressure_allocated_vcpus"`
		PressureRunning            *int32  `json:"pressure_running_sandboxes"`
		PressureProvisioning       *int32  `json:"pressure_provisioning_sandboxes"`
		PressureUsedNetSlots       *int32  `json:"pressure_used_net_slots"`
		PressureWarmNetSlots       *int32  `json:"pressure_warm_net_slots"`
		PressureReportedAt         *string `json:"pressure_reported_at"`
	}
	hosts := make([]hostView, 0, len(rows))
	for _, r := range rows {
		v := hostView{
			ID:                r.ID,
			Status:            r.Status,
			Region:            r.Region,
			VMDAddr:           r.VmdAddr,
			ProxyAddr:         r.ProxyAddr,
			CapacityMemoryMib: r.CapacityMemoryMib,
			CapacityVcpus:     r.CapacityVcpus,
			RunningCount:      r.RunningCount,
			TransitionalCount: r.TransitionalCount,
			PausedCount:       r.PausedCount,
			BuildingCount:     r.BuildingCount,
			PausedUnbacked:    r.PausedUnbackedCount,
		}
		if r.LastHeartbeatAt.Valid {
			s := r.LastHeartbeatAt.Time.UTC().Format(time.RFC3339)
			v.LastHeartbeatAt = &s
		}
		v.PressureAllocatedMemoryMib = r.PressureAllocatedMemoryMib
		v.PressureAllocatedVcpus = r.PressureAllocatedVcpus
		v.PressureRunning = r.PressureRunningSandboxes
		v.PressureProvisioning = r.PressureProvisioningSandboxes
		v.PressureUsedNetSlots = r.PressureUsedNetSlots
		v.PressureWarmNetSlots = r.PressureWarmNetSlots
		if r.PressureReportedAt.Valid {
			s := r.PressureReportedAt.Time.UTC().Format(time.RFC3339)
			v.PressureReportedAt = &s
		}
		hosts = append(hosts, v)
	}
	c.JSON(http.StatusOK, gin.H{"hosts": hosts})
}

func timestamptzString(ts pgtype.Timestamptz) any {
	if !ts.Valid {
		return nil
	}
	return ts.Time.Format(time.RFC3339Nano)
}

// pressureReport mirrors vmd's pressureRequest. vmd_addr is the identity
// fence checked against the host row inside the upsert itself.
type pressureReport struct {
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
	MaxNetworkSlots       int32  `json:"max_network_slots"`
	MaxSandboxes          int32  `json:"max_sandboxes"`
	// Live VMs whose allocation the host could not determine. Non-zero
	// means the allocation totals are an UNDERCOUNT, so a consumer must
	// not read the difference as free capacity.
	UnknownAllocationVMs int32 `json:"unknown_allocation_vms"`
}

func (r pressureReport) valid() bool {
	return r.VMDAddr != "" && len(r.VMDAddr) <= 256 &&
		r.RunningSandboxes >= 0 && r.ProvisioningSandboxes >= 0 &&
		r.PausedSandboxes >= 0 && r.AllocatedMemoryMib >= 0 &&
		r.AllocatedVcpus >= 0 && r.UsedNetSlots >= 0 &&
		r.ProvisioningNetSlots >= 0 && r.WarmNetSlots >= 0 &&
		r.NetSlotCeiling >= 0 && r.MaxNetworkSlots >= 0 && r.MaxSandboxes >= 0 &&
		r.UnknownAllocationVMs >= 0
}

// HostReportPressure handles PUT /internal/hosts/:host_id/pressure — the
// best-effort capacity telemetry channel, deliberately SEPARATE from the
// heartbeat: no outcome here can touch host liveness, and older control
// planes simply lack the route (vmd backs off on the 404). The upsert is
// identity-fenced on vmd_addr and wholesale last-write-wins with a
// DB-clock reported_at; consumers treat any control-plane reservation
// created after reported_at as a delta on top of this report.
func (h *Handlers) HostReportPressure(c *gin.Context) {
	hostID := c.Param("host_id")
	if hostID == "" {
		respondErrorMsg(c, "bad_request", "host_id is required", http.StatusBadRequest)
		return
	}
	var req pressureReport
	if err := bindJSONStrict(c, &req); err != nil {
		respondErrorMsg(c, "bad_request", "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !req.valid() {
		respondErrorMsg(c, "bad_request", "pressure fields must be non-negative and vmd_addr set", http.StatusBadRequest)
		return
	}
	rows, err := h.DB.UpsertHostPressure(c.Request.Context(), db.UpsertHostPressureParams{
		HostID:                hostID,
		VmdAddr:               req.VMDAddr,
		RunningSandboxes:      req.RunningSandboxes,
		ProvisioningSandboxes: req.ProvisioningSandboxes,
		PausedSandboxes:       req.PausedSandboxes,
		AllocatedMemoryMib:    req.AllocatedMemoryMib,
		AllocatedVcpus:        req.AllocatedVcpus,
		UsedNetSlots:          req.UsedNetSlots,
		ProvisioningNetSlots:  req.ProvisioningNetSlots,
		WarmNetSlots:          req.WarmNetSlots,
		NetSlotCeiling:        req.NetSlotCeiling,
		MaxNetworkSlots:       req.MaxNetworkSlots,
		MaxSandboxes:          req.MaxSandboxes,
		UnknownAllocationVms:  req.UnknownAllocationVMs,
	})
	if err != nil {
		log.Error().Err(err).Str("host_id", hostID).Msg("UpsertHostPressure failed")
		respondError(c, ErrInternal)
		return
	}
	if rows == 0 {
		// Unknown host or an address that no longer holds the identity.
		// 409, not 404: after a successful heartbeat the row exists, so
		// vmd must treat this as an identity problem to surface, never as
		// "old control plane" (404 is reserved for exactly that).
		respondErrorMsg(c, "conflict", "host identity is not held by this address", http.StatusConflict)
		return
	}
	c.JSON(http.StatusOK, gin.H{"recorded": true})
}
