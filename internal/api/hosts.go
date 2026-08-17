package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

const (
	maxHostCapabilities     = 32
	maxHostCapabilityLength = 64
	maxHostFieldLength      = 256
)

type hostHeartbeatRequest struct {
	Capabilities []string `json:"capabilities"`

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
)

// HostHeartbeat handles POST /internal/hosts/:host_id/heartbeat.
// VMD calls this every 30s to prove liveness. The control plane updates
// last_heartbeat_at; a background detector marks hosts unhealthy after
// 2 minutes of silence. If the host was previously marked unhealthy, the
// heartbeat automatically re-activates it (recovery from transient outage).
//
// A heartbeat for an unknown host id that carries a complete self-description
// registers the host in 'provisioning' — never serving — until an operator
// activates it. A heartbeat claiming an existing id from a different vmd_addr
// is rejected while the row's holder is still heartbeating: two live daemons
// must never share an identity (each would reconcile the other's sandboxes).
// If the holder has gone silent past the unhealthy threshold, the identity is
// released to the new address (re-provisioned host, new internal IP).
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
			if err := insertCapabilities(ctx, q, hostID, capabilities); err != nil {
				return "", "", err
			}
			return created.Status, created.Status, nil
		}
		if err != nil {
			return "", "", err
		}

		if req.VMDAddr != "" && req.VMDAddr != host.VmdAddr {
			holderAlive := host.LastHeartbeatAt.Valid &&
				time.Since(host.LastHeartbeatAt.Time) < heartbeatTimeout
			if holderAlive {
				return "", "", errHostIdentityConflict
			}
			// Claiming an existing identity from a new address is a
			// re-registration: it rewrites the whole row, so it needs the
			// whole description. A partial one would blank proxy_addr or
			// region, and heartbeating without reclaiming would mark a row
			// live while its address points at the silent old machine.
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
			reclaimed = true
			log.Warn().Str("host_id", hostID).Str("vmd_addr", req.VMDAddr).
				Msg("host identity reclaimed from a silent holder")
		}

		row, err := q.UpdateHostHeartbeat(ctx, hostID)
		if err != nil {
			return "", "", err
		}
		// Missing capabilities is an explicit empty replacement. This clears a
		// stale attestation immediately when VMD can no longer verify its proxy.
		if err := q.DeleteHostCapabilities(ctx, hostID); err != nil {
			return "", "", err
		}
		if err := insertCapabilities(ctx, q, hostID, capabilities); err != nil {
			return "", "", err
		}
		return row.Status, row.PrevStatus, nil
	}

	var status, prevStatus string
	var err error
	if h.Pool == nil {
		status, prevStatus, err = beat(h.DB)
	} else {
		var tx pgx.Tx
		if tx, err = h.Pool.Begin(ctx); err == nil {
			defer tx.Rollback(ctx)
			if status, prevStatus, err = beat(h.DB.WithTx(tx)); err == nil {
				err = tx.Commit(ctx)
			}
		}
	}
	switch {
	case err == errHostNotRegistered:
		respondErrorMsg(c, "not_found", "host not found", http.StatusNotFound)
		return
	case err == errHostIdentityConflict:
		log.Warn().Str("host_id", hostID).Str("vmd_addr", req.VMDAddr).
			Msg("heartbeat rejected: identity in use by a live host at another address")
		respondErrorMsg(c, "conflict", "host identity in use by a live host", http.StatusConflict)
		return
	case err == errHostPartialDescription:
		log.Warn().Str("host_id", hostID).Str("vmd_addr", req.VMDAddr).
			Msg("heartbeat rejected: address claim without a complete host description")
		respondErrorMsg(c, "bad_request", "claiming a host address requires a complete host description", http.StatusBadRequest)
		return
	case err != nil:
		log.Error().Err(err).Str("host_id", hostID).Msg("host heartbeat failed")
		respondError(c, ErrInternal)
		return
	}

	if registered {
		log.Info().Str("host_id", hostID).Str("vmd_addr", req.VMDAddr).
			Str("region", req.Region).Msg("host self-registered as provisioning")
	}
	if reclaimed && h.Hosts != nil {
		// The row's vmd_addr changed; a cached client still dials the old
		// machine (the registry only self-evicts on dead transports, and a
		// live old daemon would silently take the wrong host's RPCs).
		h.Hosts.Invalidate(hostID)
	}
	if prevStatus == "unhealthy" && status == "active" {
		// The heartbeat just recovered this host; drop the scheduler's cached
		// list so its capacity is usable now, not after the cache TTL.
		log.Info().Str("host_id", hostID).Msg("host recovered via heartbeat")
		if h.Scheduler != nil {
			h.Scheduler.Invalidate()
		}
	}

	c.JSON(http.StatusOK, gin.H{"status": status})
}

func insertCapabilities(ctx context.Context, q *db.Queries, hostID string, capabilities []string) error {
	for _, capability := range capabilities {
		if err := q.InsertHostCapability(ctx, db.InsertHostCapabilityParams{
			HostID: hostID, Capability: capability,
		}); err != nil {
			return err
		}
	}
	return nil
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
// `hostctl list`: every host with liveness and sandbox counts.
func (h *Handlers) HostList(c *gin.Context) {
	rows, err := h.DB.ListHostsAdmin(c.Request.Context())
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
	}
	hosts := make([]hostView, 0, len(rows))
	for _, r := range rows {
		v := hostView{
			ID: r.ID, Status: r.Status, Region: r.Region,
			VMDAddr: r.VmdAddr, ProxyAddr: r.ProxyAddr,
			CapacityMemoryMib: r.CapacityMemoryMib,
			CapacityVcpus:     r.CapacityVcpus,
			RunningCount:      r.RunningCount,
			TransitionalCount: r.TransitionalCount,
			PausedCount:       r.PausedCount,
			BuildingCount:     r.BuildingCount,
		}
		if r.LastHeartbeatAt.Valid {
			s := r.LastHeartbeatAt.Time.UTC().Format(time.RFC3339)
			v.LastHeartbeatAt = &s
		}
		hosts = append(hosts, v)
	}
	c.JSON(http.StatusOK, gin.H{"hosts": hosts})
}
