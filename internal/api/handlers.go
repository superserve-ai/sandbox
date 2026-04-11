package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// VMDClient is the interface for talking to a VM daemon.
type VMDClient = vmdclient.Client

// Scheduler selects a host for new sandboxes.
type Scheduler interface {
	SelectHost(ctx context.Context) (hostID string, err error)
}

// HostRegistry resolves a host ID to a VMD client.
type HostRegistry interface {
	ClientFor(ctx context.Context, hostID string) (vmdclient.Client, error)
}

// Handlers holds shared dependencies for all route handlers.
type Handlers struct {
	VMD       VMDClient     // default VMD client (used when Hosts is nil or host lookup fails on legacy sandboxes)
	DB        *db.Queries
	Config    *config.Config
	Hosts     HostRegistry  // when set, routes VMD calls via host_id
	Scheduler Scheduler     // when set, picks host on create
}

// NewHandlers creates a new Handlers instance.
func NewHandlers(vmd VMDClient, queries *db.Queries, cfg *config.Config) *Handlers {
	return &Handlers{
		VMD:    vmd,
		DB:     queries,
		Config: cfg,
	}
}

// vmdForHost returns the VMDClient for the given host. When a registry is
// configured, it resolves via DB lookup. If the lookup fails (e.g. legacy
// sandbox with a backfilled host_id that has no host row), falls back to
// the default VMD client so existing sandboxes keep working during the
// migration period.
func (h *Handlers) vmdForHost(ctx context.Context, hostID string) (VMDClient, error) {
	if h.Hosts == nil {
		return h.VMD, nil
	}
	c, err := h.Hosts.ClientFor(ctx, hostID)
	if err != nil {
		if h.VMD != nil {
			log.Warn().Err(err).Str("host_id", hostID).Msg("host registry lookup failed, falling back to default VMD client")
			return h.VMD, nil
		}
		return nil, err
	}
	return c, nil
}

// vmdTimeout is the default deadline for VMD gRPC calls.
const vmdTimeout = 30 * time.Second

// asyncTimeout is the deadline for fire-and-forget DB writes.
const asyncTimeout = 5 * time.Second

// logActivityAsync writes an activity record in a background goroutine.
//
// The caller passes the request context. We strip cancellation via
// context.WithoutCancel so the goroutine is not killed when the HTTP
// response completes, but we KEEP the trace/span context so the async
// write appears in the same request trace as the synchronous work.
func (h *Handlers) logActivityAsync(reqCtx context.Context, sandboxID, teamID uuid.UUID, category, action, status string, sandboxName *string, durationMs *int32, metadata []byte) {
	asyncCtx := context.WithoutCancel(reqCtx)
	go func() {
		ctx, cancel := context.WithTimeout(asyncCtx, asyncTimeout)
		defer cancel()
		_, err := h.DB.CreateActivity(ctx, db.CreateActivityParams{
			SandboxID:   sandboxID,
			TeamID:      teamID,
			Category:    category,
			Action:      action,
			Status:      &status,
			SandboxName: sandboxName,
			DurationMs:  durationMs,
			Metadata:    metadata,
		})
		if err != nil {
			log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msgf("async %s/%s activity log failed", category, action)
		}
	}()
}

// updateLastActivityAsync bumps last_activity_at in a background goroutine.
// Same detached-but-traced context pattern as logActivityAsync.
func (h *Handlers) updateLastActivityAsync(reqCtx context.Context, sandboxID, teamID uuid.UUID) {
	asyncCtx := context.WithoutCancel(reqCtx)
	go func() {
		ctx, cancel := context.WithTimeout(asyncCtx, asyncTimeout)
		defer cancel()
		if err := h.DB.UpdateSandboxLastActivity(ctx, db.UpdateSandboxLastActivityParams{
			ID:     sandboxID,
			TeamID: teamID,
		}); err != nil {
			log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("async last_activity_at update failed")
		}
	}()
}

// AutoWake returns middleware that loads a sandbox, verifies team ownership, and
// transparently resumes idle sandboxes. On success it stores *db.Sandbox under
// the "sandbox" context key for downstream handlers.
func (h *Handlers) AutoWake() gin.HandlerFunc {
	return func(c *gin.Context) {
		sandboxID, err := parseSandboxID(c)
		if err != nil {
			c.Abort()
			return
		}

		teamID, err := teamIDFromContext(c)
		if err != nil {
			c.Abort()
			return
		}

		sandbox, err := h.DB.GetSandbox(c.Request.Context(), db.GetSandboxParams{
			ID:     sandboxID,
			TeamID: teamID,
		})
		if err != nil {
			if err == pgx.ErrNoRows {
				respondError(c, ErrSandboxNotFound)
			} else {
				log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB GetSandbox failed")
				respondError(c, ErrInternal)
			}
			c.Abort()
			return
		}

		switch sandbox.Status {
		case db.SandboxStatusActive:
			// Ready.
		case db.SandboxStatusIdle:
			vmd, vmdErr := h.vmdForHost(c.Request.Context(), sandbox.HostID)
			if vmdErr != nil {
				log.Error().Err(vmdErr).Str("sandbox_id", sandboxID.String()).Msg("auto-wake resolve VMD failed")
				respondError(c, ErrInternal)
				c.Abort()
				return
			}
			vmdCtx, vmdCancel := context.WithTimeout(c.Request.Context(), vmdTimeout)
			defer vmdCancel()
			if err := h.wakeIdleSandbox(vmdCtx, vmd, &sandbox); err != nil {
				log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("auto-wake ResumeInstance failed")
				respondError(c, ErrInternal)
				c.Abort()
				return
			}
			// VM is running — detach from cancellation so a client
			// disconnect cannot leave the row stuck in "idle", but
			// keep the trace/span context so post-VMD writes show
			// up in the same request trace.
			postCtx, postCancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), vmdTimeout)
			defer postCancel()
			if err := h.DB.UpdateSandboxStatus(postCtx, db.UpdateSandboxStatusParams{
				ID:     sandboxID,
				Status: db.SandboxStatusActive,
				TeamID: teamID,
			}); err != nil {
				log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("auto-wake UpdateSandboxStatus failed")
				respondError(c, ErrInternal)
				c.Abort()
				return
			}
			// Reapply persisted egress rules — nftables + proxy state are fresh after restore.
			if err := h.reapplyNetworkConfig(postCtx, vmd, sandboxID.String(), sandbox.NetworkConfig); err != nil {
				log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("auto-wake reapply network config failed")
				respondError(c, ErrInternal)
				c.Abort()
				return
			}
		default:
			respondError(c, ErrInvalidState)
			c.Abort()
			return
		}

		c.Set("sandbox", &sandbox)
		c.Next()
	}
}

// sandboxFromContext retrieves the *db.Sandbox stored by the AutoWake middleware.
func sandboxFromContext(c *gin.Context) *db.Sandbox {
	val, _ := c.Get("sandbox")
	sb, _ := val.(*db.Sandbox)
	return sb
}

// wakeIdleSandbox transparently brings an idle sandbox back online. It first
// tries the stateful ResumeInstance path. If VMD has no record of the VM
// (typically after a VMD restart that lost the in-memory map), it falls back
// to the stateless RestoreSnapshot path using the snapshot files from the DB.
//
// The fallback is only attempted when:
//   - VMD returned NotFound
//   - The sandbox has a linked snapshot row
//   - The snapshot file is still readable on disk
func (h *Handlers) wakeIdleSandbox(ctx context.Context, vmd VMDClient, sandbox *db.Sandbox) error {
	sandboxID := sandbox.ID.String()
	_, _, _, err := vmd.ResumeInstance(ctx, sandboxID, "", "", nil)
	if err == nil {
		return nil
	}
	if !isVMDNotFound(err) || !sandbox.SnapshotID.Valid {
		return err
	}

	snap, snapErr := h.DB.GetSnapshot(ctx, db.GetSnapshotParams{
		ID:     sandbox.SnapshotID.Bytes,
		TeamID: sandbox.TeamID,
	})
	if snapErr != nil {
		return err
	}
	if !snapshotFileExists(snap.Path) {
		return err
	}

	memPath := filepath.Join(filepath.Dir(snap.Path), "mem.snap")
	log.Warn().Str("sandbox_id", sandboxID).Msg("auto-wake ResumeInstance NotFound, falling back to stateless restore")
	_, _, _, err = vmd.RestoreSnapshot(ctx, sandboxID, snap.Path, memPath)
	return err
}

// persistedEgressConfig mirrors the jsonb shape stored in sandbox.network_config.
type persistedEgressConfig struct {
	Egress struct {
		AllowedCIDRs   []string `json:"allowed_cidrs"`
		DeniedCIDRs    []string `json:"denied_cidrs"`
		AllowedDomains []string `json:"allowed_domains"`
	} `json:"egress"`
}

// reapplyNetworkConfig reads the sandbox's persisted egress config from the DB
// record and pushes it back to VMD. Called after every resume path (explicit
// /resume, AutoWake, post-restore in CreateSandbox) because the nftables rules
// and proxy state are fresh after a snapshot restore.
//
// Uses a caller-supplied context so the caller controls timeout/cancellation.
// Silently returns nil if there is no persisted config (default allow-all).
func (h *Handlers) reapplyNetworkConfig(ctx context.Context, vmd VMDClient, sandboxID string, raw []byte) error {
	if len(raw) == 0 {
		return nil
	}

	var cfg persistedEgressConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("parse persisted network_config: %w", err)
	}

	if len(cfg.Egress.AllowedCIDRs) == 0 &&
		len(cfg.Egress.DeniedCIDRs) == 0 &&
		len(cfg.Egress.AllowedDomains) == 0 {
		return nil
	}

	return vmd.UpdateSandboxNetwork(ctx, sandboxID,
		cfg.Egress.AllowedCIDRs,
		cfg.Egress.DeniedCIDRs,
		cfg.Egress.AllowedDomains,
	)
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

func (h *Handlers) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"version": "0.1.0",
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func parseSandboxID(c *gin.Context) (uuid.UUID, error) {
	raw := c.Param("sandbox_id")
	id, err := uuid.Parse(raw)
	if err != nil {
		respondErrorMsg(c, "bad_request",
			fmt.Sprintf("Invalid sandbox_id: %q is not a valid UUID", raw),
			http.StatusBadRequest)
		return uuid.Nil, err
	}
	return id, nil
}

func teamIDFromContext(c *gin.Context) (uuid.UUID, error) {
	raw, _ := c.Get("team_id")
	s, ok := raw.(string)
	if !ok || s == "" {
		respondError(c, ErrUnauthorized)
		return uuid.Nil, fmt.Errorf("missing team_id")
	}
	id, err := uuid.Parse(s)
	if err != nil {
		respondError(c, ErrUnauthorized)
		return uuid.Nil, err
	}
	return id, nil
}

// ---------------------------------------------------------------------------
// Sandbox lifecycle
// ---------------------------------------------------------------------------

func (h *Handlers) ResumeSandbox(c *gin.Context) {
	sandboxID, err := parseSandboxID(c)
	if err != nil {
		return
	}

	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}

	// Verify sandbox exists and belongs to this team.
	sandbox, err := h.DB.GetSandbox(c.Request.Context(), db.GetSandboxParams{
		ID:     sandboxID,
		TeamID: teamID,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			respondError(c, ErrSandboxNotFound)
			return
		}
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB GetSandbox failed")
		respondError(c, ErrInternal)
		return
	}

	// Only idle sandboxes can be resumed.
	if sandbox.Status != db.SandboxStatusIdle {
		respondError(c, ErrInvalidState)
		return
	}

	// Read the snapshot to get paths for VMD.
	if !sandbox.SnapshotID.Valid {
		log.Error().Str("sandbox_id", sandboxID.String()).Msg("idle sandbox has no snapshot_id")
		respondError(c, ErrInternal)
		return
	}

	snapshot, err := h.DB.GetSnapshot(c.Request.Context(), db.GetSnapshotParams{
		ID:     sandbox.SnapshotID.Bytes,
		TeamID: teamID,
	})
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB GetSnapshot failed")
		respondError(c, ErrInternal)
		return
	}

	snapshotPath := snapshot.Path
	memPath := filepath.Join(filepath.Dir(snapshotPath), "mem.snap")

	// Resolve the VMD client for this sandbox's host.
	vmd, vmdLookupErr := h.vmdForHost(c.Request.Context(), sandbox.HostID)
	if vmdLookupErr != nil {
		log.Error().Err(vmdLookupErr).Str("sandbox_id", sandboxID.String()).Msg("resolve VMD for resume failed")
		respondError(c, ErrInternal)
		return
	}

	// Resume the VM. Cancellation of this call still follows the request
	// context — if the client hangs up mid-resume, abort the VMD call.
	vmdCtx, vmdCancel := context.WithTimeout(c.Request.Context(), vmdTimeout)
	defer vmdCancel()
	ipAddress, actualVcpu, actualMemMiB, err := vmd.ResumeInstance(vmdCtx, sandboxID.String(), snapshotPath, memPath, nil)
	if err != nil {
		// If VMD has no record of this VM (crashed before pause, or VMD
		// restart lost its state), fall back to the stateless RestoreSnapshot
		// path as long as the snapshot files are actually on disk. This is
		// the "handler degradation" property from the Phase 3 design doc.
		if isVMDNotFound(err) && snapshotFileExists(snapshotPath) {
			log.Warn().Err(err).Str("sandbox_id", sandboxID.String()).
				Msg("VMD ResumeInstance: VM not in map, falling back to stateless RestoreSnapshot")
			ipAddress, actualVcpu, actualMemMiB, err = vmd.RestoreSnapshot(vmdCtx, sandboxID.String(), snapshotPath, memPath)
			if err != nil {
				log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("VMD RestoreSnapshot fallback failed")
				respondError(c, ErrInternal)
				return
			}
		} else {
			log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("VMD ResumeInstance failed")
			respondError(c, ErrInternal)
			return
		}
	}

	// The fallback may have returned 0 for vcpu/mem. Fall back to the DB values.
	if actualVcpu == 0 {
		actualVcpu = uint32(sandbox.VcpuCount)
	}
	if actualMemMiB == 0 {
		actualMemMiB = uint32(sandbox.MemoryMib)
	}

	// Past this point the VM is running. Detach from cancellation so a
	// client disconnect cannot leave the sandbox stuck in "idle" while
	// the VM is actually up, but preserve the trace/span context so
	// these DB writes still appear in the request trace.
	postCtx, postCancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), vmdTimeout)
	defer postCancel()

	var ipAddr *netip.Addr
	if ipAddress != "" {
		if addr, parseErr := netip.ParseAddr(ipAddress); parseErr == nil {
			ipAddr = &addr
		}
	}
	if err := h.DB.ActivateSandbox(postCtx, db.ActivateSandboxParams{
		ID:        sandboxID,
		VcpuCount: int32(actualVcpu),
		MemoryMib: int32(actualMemMiB),
		IpAddress: ipAddr,
		TeamID:    teamID,
	}); err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB ActivateSandbox failed")
		respondError(c, ErrInternal)
		return
	}

	// Reapply persisted egress rules — the nftables rules and proxy state
	// are fresh after a snapshot restore, so user rules must be re-pushed.
	if err := h.reapplyNetworkConfig(postCtx, vmd, sandboxID.String(), sandbox.NetworkConfig); err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("reapply network config on resume failed")
		respondError(c, ErrInternal)
		return
	}

	// Async observability writes.
	h.updateLastActivityAsync(c.Request.Context(), sandboxID, teamID)
	h.logActivityAsync(c.Request.Context(), sandboxID, teamID, "sandbox", "resumed", "success", &sandbox.Name, nil, nil)

	sandbox.Status = db.SandboxStatusActive
	sandbox.VcpuCount = int32(actualVcpu)
	sandbox.MemoryMib = int32(actualMemMiB)
	sandbox.IpAddress = ipAddr
	c.JSON(http.StatusOK, h.sandboxToResponse(sandbox))
}

// ---------------------------------------------------------------------------
// Sandbox CRUD
// ---------------------------------------------------------------------------

func (h *Handlers) DeleteSandbox(c *gin.Context) {
	sandboxID, err := parseSandboxID(c)
	if err != nil {
		return
	}

	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}

	// Verify sandbox exists and belongs to this team.
	sandbox, err := h.DB.GetSandbox(c.Request.Context(), db.GetSandboxParams{
		ID:     sandboxID,
		TeamID: teamID,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			respondError(c, ErrSandboxNotFound)
			return
		}
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB GetSandbox failed")
		respondError(c, ErrInternal)
		return
	}

	// Destroy the VM (skip if sandbox never booted).
	if sandbox.Status != db.SandboxStatusFailed {
		vmd, vmdLookupErr := h.vmdForHost(c.Request.Context(), sandbox.HostID)
		if vmdLookupErr != nil {
			log.Error().Err(vmdLookupErr).Str("sandbox_id", sandboxID.String()).Msg("resolve VMD for delete failed")
			respondError(c, ErrInternal)
			return
		}
		vmdCtx, vmdCancel := context.WithTimeout(c.Request.Context(), vmdTimeout)
		defer vmdCancel()
		if err := vmd.DestroyInstance(vmdCtx, sandboxID.String(), true); err != nil {
			// Delete is idempotent — if the VM is already gone, proceed
			// with DB cleanup instead of failing the request.
			if isVMDNotFound(err) {
				log.Warn().Err(err).Str("sandbox_id", sandboxID.String()).Msg("VMD DestroyInstance: VM already gone, proceeding with DB cleanup")
			} else {
				log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("VMD DestroyInstance failed")
				respondError(c, ErrInternal)
				return
			}
		}
	}

	// Soft-delete in DB.
	if err := h.DB.DestroySandbox(c.Request.Context(), db.DestroySandboxParams{
		ID:     sandboxID,
		TeamID: teamID,
	}); err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB DestroySandbox failed")
		respondError(c, ErrInternal)
		return
	}

	// Async activity log.
	h.logActivityAsync(c.Request.Context(), sandboxID, teamID, "sandbox", "deleted", "success", &sandbox.Name, nil, nil)

	c.Status(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Sandbox Create
// ---------------------------------------------------------------------------

type networkConfigRequest struct {
	AllowOut []string `json:"allow_out,omitempty"` // Allowed CIDRs or domains.
	DenyOut  []string `json:"deny_out,omitempty"`  // Denied CIDRs.
}

type createSandboxRequest struct {
	Name         string                `json:"name" binding:"required,min=1,max=64"`
	FromSnapshot *string               `json:"from_snapshot,omitempty"`
	Network      *networkConfigRequest `json:"network,omitempty"`

	// TimeoutSeconds is a hard lifetime cap in seconds, measured from
	// created_at. When set, the reaper pauses the sandbox that many seconds
	// after creation if it is still active. Already-idle sandboxes are left
	// alone. Matches the user intent "stop this sandbox in N seconds so it
	// cannot burn resources indefinitely."
	//
	// The field name includes "_seconds" so the unit is obvious at every
	// call site without having to read the docs.
	//
	// Nil means no cap — the sandbox lives until explicitly paused or
	// deleted (this is the default philosophy of the platform: sandboxes
	// don't die on their own).
	TimeoutSeconds *int32 `json:"timeout_seconds,omitempty"`

	// Metadata is a flat string→string map of user-supplied tags that get
	// attached to the sandbox at creation. Updatable after creation via
	// PATCH /sandboxes/:id. Filterable on GET /sandboxes via metadata.<key>=<value>
	// query params (jsonb @> containment, so all conditions must match).
	//
	// Strings only — no nested objects, numbers, or arrays. This is
	// deliberate: it keeps URL filters unambiguous (no "is 42 the number
	// or the string?" questions) and matches what every other tagging
	// system in this space does (AWS tags, GCE labels, k8s labels).
	//
	// Limits are enforced by validateMetadata: 64 keys, 256-byte keys,
	// 2 KB values, 16 KB total. Keys starting with `superserve.` or
	// `_superserve` are reserved for platform use and rejected.
	Metadata map[string]string `json:"metadata,omitempty"`

	// EnvVars are environment variables injected into every process inside
	// the sandbox (terminal sessions, exec calls). Not stored in the DB —
	// they live in boxd's memory for the sandbox's lifetime and survive
	// pause/resume via snapshot.
	EnvVars map[string]string `json:"env_vars,omitempty"`
}

type sandboxResponse struct {
	ID             uuid.UUID             `json:"id"`
	Name           string                `json:"name"`
	Status         string                `json:"status"`
	VcpuCount      int32                 `json:"vcpu_count"`
	MemoryMib      int32                 `json:"memory_mib"`
	AccessToken    string                `json:"access_token,omitempty"`
	SnapshotID     *uuid.UUID            `json:"snapshot_id,omitempty"`
	CreatedAt      time.Time             `json:"created_at"`
	TimeoutSeconds *int32                `json:"timeout_seconds,omitempty"`
	Network        *networkConfigRequest `json:"network,omitempty"`
	Metadata       map[string]string     `json:"metadata"`
}

func (h *Handlers) sandboxToResponse(s db.Sandbox) sandboxResponse {
	resp := sandboxResponse{
		ID:        s.ID,
		Name:      s.Name,
		Status:    string(s.Status),
		VcpuCount: s.VcpuCount,
		MemoryMib: s.MemoryMib,
		CreatedAt: s.CreatedAt,
		Metadata:  decodeMetadata(s.Metadata),
	}
	if h.Config != nil && h.Config.SandboxAccessTokenSeed != nil {
		resp.AccessToken = auth.ComputeAccessToken(h.Config.SandboxAccessTokenSeed, s.ID.String())
	}
	if s.SnapshotID.Valid {
		id := uuid.UUID(s.SnapshotID.Bytes)
		resp.SnapshotID = &id
	}
	if s.TimeoutSeconds != nil {
		resp.TimeoutSeconds = s.TimeoutSeconds
	}
	if len(s.NetworkConfig) > 0 {
		var stored struct {
			Egress struct {
				AllowedCIDRs   []string `json:"allowed_cidrs"`
				DeniedCIDRs    []string `json:"denied_cidrs"`
				AllowedDomains []string `json:"allowed_domains"`
			} `json:"egress"`
		}
		if err := json.Unmarshal(s.NetworkConfig, &stored); err == nil {
			e := stored.Egress
			allowOut := append(e.AllowedCIDRs, e.AllowedDomains...)
			if len(allowOut) > 0 || len(e.DeniedCIDRs) > 0 {
				resp.Network = &networkConfigRequest{
					AllowOut: allowOut,
					DenyOut:  e.DeniedCIDRs,
				}
			}
		}
	}
	return resp
}

// decodeMetadata unmarshals the jsonb bytes column into a string→string map.
// On any decode error (which should be impossible because the column is
// constrained to objects we wrote ourselves) we return an empty map rather
// than panicking — losing the tags is bad, but failing the whole list/get
// response would be worse. Callers always get a non-nil map so the JSON
// response renders `"metadata": {}` instead of `null` for sandboxes that
// were created without any tags.
func decodeMetadata(raw []byte) map[string]string {
	out := map[string]string{}
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		log.Error().Err(err).Msg("decode sandbox metadata jsonb")
		return map[string]string{}
	}
	return out
}

// ---------------------------------------------------------------------------
// Sandbox List + Get
// ---------------------------------------------------------------------------

func (h *Handlers) ListSandboxes(c *gin.Context) {
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}

	// Parse metadata filters from the query string. Any query param that
	// starts with `metadata.` is treated as a filter clause:
	//
	//   GET /sandboxes?metadata.env=prod&metadata.owner=agent-7
	//
	// Multiple filters AND together (jsonb @> containment semantics): a
	// sandbox matches only if all key/value pairs are present in its
	// metadata. Values are always strings — there's no type coercion,
	// because the storage shape is flat string→string and we want url
	// filters to be unambiguous (`metadata.count=42` matches the string
	// "42", not the number 42).
	filter, err := parseMetadataFilter(c.Request.URL.Query())
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}

	var sandboxes []db.Sandbox
	if len(filter) == 0 {
		sandboxes, err = h.DB.ListSandboxesByTeam(c.Request.Context(), teamID)
	} else {
		filterJSON, _ := json.Marshal(filter) // map[string]string never fails
		sandboxes, err = h.DB.ListSandboxesByTeamWithFilter(c.Request.Context(), db.ListSandboxesByTeamWithFilterParams{
			TeamID:   teamID,
			Metadata: filterJSON,
		})
	}
	if err != nil {
		log.Error().Err(err).Msg("DB ListSandboxesByTeam failed")
		respondError(c, ErrInternal)
		return
	}

	out := make([]sandboxResponse, len(sandboxes))
	for i, s := range sandboxes {
		out[i] = h.sandboxToResponse(s)
	}
	c.JSON(http.StatusOK, out)
}

// parseMetadataFilter walks query params and extracts the metadata.* filter
// pairs into a flat string→string map. Returns an empty map (not nil) when
// the user didn't supply any metadata filters.
//
// The validation cap on the *filter* is the same as on stored metadata
// (validateMetadata), because we marshal the filter to jsonb and pass it
// through @> — a 16 KB filter would be a denial-of-service vector if
// allowed. We reuse validateMetadata so the rules can never drift apart.
func parseMetadataFilter(query map[string][]string) (map[string]string, error) {
	const prefix = "metadata."
	out := map[string]string{}
	for key, values := range query {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		mdKey := strings.TrimPrefix(key, prefix)
		if mdKey == "" {
			return nil, fmt.Errorf("metadata filter key cannot be empty")
		}
		// Repeated `?metadata.k=a&metadata.k=b` is meaningless under
		// containment semantics (a sandbox can have only one value per
		// key), so we reject it loudly instead of picking last-wins.
		if len(values) > 1 {
			return nil, fmt.Errorf("metadata filter %q has multiple values; only one allowed", mdKey)
		}
		out[mdKey] = values[0]
	}
	if err := validateMetadata(out); err != nil {
		return nil, err
	}
	return out, nil
}

func (h *Handlers) GetSandboxByID(c *gin.Context) {
	sandboxID, err := parseSandboxID(c)
	if err != nil {
		return
	}

	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}

	sandbox, err := h.DB.GetSandbox(c.Request.Context(), db.GetSandboxParams{
		ID:     sandboxID,
		TeamID: teamID,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			respondError(c, ErrSandboxNotFound)
			return
		}
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB GetSandbox failed")
		respondError(c, ErrInternal)
		return
	}

	c.JSON(http.StatusOK, h.sandboxToResponse(sandbox))
}

func (h *Handlers) CreateSandbox(c *gin.Context) {
	var req createSandboxRequest
	if err := bindJSONStrict(c, &req); err != nil {
		respondErrorMsg(c, "bad_request", fmt.Sprintf("Validation failed: %v", err), http.StatusBadRequest)
		return
	}
	// Manual field validation — bindJSONStrict uses encoding/json which does
	// not honor gin's `binding:"required,..."` struct tags.
	if req.Name == "" || len(req.Name) > 64 {
		respondErrorMsg(c, "bad_request", "name is required and must be 1-64 characters", http.StatusBadRequest)
		return
	}

	// timeout_seconds validation — 1 second to 7 days. Must be positive
	// (zero would mean "destroy immediately" which makes no sense). The
	// 7-day cap is a safety ceiling so runaway "I set timeout=huge and
	// forgot" sandboxes cannot live forever, while still supporting
	// genuinely long-running workloads. Per-team overrides can come later.
	const maxTimeoutSeconds int32 = 7 * 24 * 3600 // 7 days
	if req.TimeoutSeconds != nil {
		if *req.TimeoutSeconds < 1 || *req.TimeoutSeconds > maxTimeoutSeconds {
			respondErrorMsg(c, "bad_request",
				fmt.Sprintf("timeout_seconds must be between 1 and %d (7 days)", maxTimeoutSeconds),
				http.StatusBadRequest)
			return
		}
	}

	// Validate network rules up front so we fail before doing any DB or VMD work.
	if req.Network != nil {
		if err := validateEgressRules(req.Network.AllowOut, req.Network.DenyOut); err != nil {
			respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Validate metadata before any DB or VMD work for the same reason —
	// reject oversized / reserved-prefix tags with a 400 instead of writing
	// a row we'd need to roll back.
	if err := validateMetadata(req.Metadata); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateEnvVars(req.EnvVars); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	// Marshal once into the canonical jsonb shape. Empty / nil maps are
	// stored as the empty object so the column is never NULL.
	metadataJSON, err := json.Marshal(req.Metadata)
	if err != nil {
		// json.Marshal of map[string]string cannot actually fail, but the
		// linter doesn't know that and the cost of the check is zero.
		log.Error().Err(err).Msg("marshal sandbox metadata")
		respondError(c, ErrInternal)
		return
	}
	if len(req.Metadata) == 0 {
		metadataJSON = []byte(`{}`)
	}

	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}

	// If from_snapshot is provided, look up the snapshot and verify team ownership.
	var snapshotID pgtype.UUID
	var snapshotPath, snapshotMemPath string
	if req.FromSnapshot != nil {
		snapUUID, err := uuid.Parse(*req.FromSnapshot)
		if err != nil {
			respondErrorMsg(c, "bad_request", "Invalid from_snapshot: not a valid UUID", http.StatusBadRequest)
			return
		}

		snapshot, err := h.DB.GetSnapshot(c.Request.Context(), db.GetSnapshotParams{
			ID:     snapUUID,
			TeamID: teamID,
		})
		if err != nil {
			respondErrorMsg(c, "not_found", "Snapshot not found", http.StatusNotFound)
			return
		}

		snapshotID = pgtype.UUID{Bytes: snapUUID, Valid: true}
		snapshotPath = snapshot.Path
		snapshotMemPath = filepath.Join(filepath.Dir(snapshotPath), "mem.snap")
	}

	// Select a host for this sandbox.
	var hostID string
	if h.Scheduler != nil {
		hostID, err = h.Scheduler.SelectHost(c.Request.Context())
		if err != nil {
			log.Error().Err(err).Msg("scheduler SelectHost failed")
			respondErrorMsg(c, "service_unavailable", "No hosts available", http.StatusServiceUnavailable)
			return
		}
	} else if h.Config != nil && h.Config.DefaultHostID != "" {
		hostID = h.Config.DefaultHostID
	} else {
		hostID = "default"
	}

	// Resolve the VMD client up front so we don't waste a DB INSERT on
	// a host we can't reach.
	vmd, vmdLookupErr := h.vmdForHost(c.Request.Context(), hostID)
	if vmdLookupErr != nil {
		log.Error().Err(vmdLookupErr).Msg("resolve VMD for create failed")
		respondError(c, ErrInternal)
		return
	}

	// Generate the sandbox ID in Go so the DB INSERT and the VMD call
	// can run in parallel — both need the same ID and neither needs to
	// wait on the other. This hides the ~10-20ms INSERT roundtrip behind
	// VMD's ~100-200ms create latency, shaving that much off the p50.
	sandboxID := uuid.New()

	insertCtx := c.Request.Context()
	type insertResult struct {
		sandbox db.Sandbox
		err     error
	}
	insertCh := make(chan insertResult, 1)
	go func() {
		sb, insertErr := h.DB.CreateSandbox(insertCtx, db.CreateSandboxParams{
			ID:             sandboxID,
			TeamID:         teamID,
			Name:           req.Name,
			Status:         db.SandboxStatusStarting,
			VcpuCount:      1, // placeholders; real values land via ActivateSandbox
			MemoryMib:      1,
			HostID:         hostID,
			SnapshotID:     snapshotID,
			TimeoutSeconds: req.TimeoutSeconds,
			Metadata:       metadataJSON,
		})
		insertCh <- insertResult{sandbox: sb, err: insertErr}
	}()

	// Boot the VM synchronously — the client gets a response only after
	// the sandbox is fully running and ready to use. This call is still
	// scoped to the request context so that if the client hangs up, the
	// boot is cancelled and VMD cleans up.
	vmdCtx, vmdCancel := context.WithTimeout(c.Request.Context(), vmdTimeout)
	defer vmdCancel()

	var ipAddress string
	var actualVcpu, actualMemMiB uint32
	var vmdErr error
	if req.FromSnapshot != nil {
		ipAddress, actualVcpu, actualMemMiB, vmdErr = vmd.ResumeInstance(vmdCtx, sandboxID.String(), snapshotPath, snapshotMemPath, req.EnvVars)
	} else {
		ipAddress, actualVcpu, actualMemMiB, vmdErr = vmd.CreateInstance(vmdCtx, sandboxID.String(),
			0, 0, 0, nil, req.EnvVars)
	}

	// Wait for the parallel INSERT to complete — its result determines
	// how we handle a VMD failure (mark row failed vs. nothing to mark).
	insertRes := <-insertCh
	sandbox := insertRes.sandbox
	dbErr := insertRes.err

	switch {
	case dbErr != nil && vmdErr != nil:
		// Both failed — nothing persisted, nothing to clean up.
		log.Error().Err(dbErr).AnErr("vmd_err", vmdErr).Msg("CreateSandbox: DB and VMD both failed")
		respondError(c, ErrInternal)
		return
	case dbErr != nil:
		// DB insert failed but VMD succeeded — destroy the orphan VM so
		// it doesn't linger on the host. Use a detached context so client
		// disconnect doesn't leak the VM.
		log.Error().Err(dbErr).Str("sandbox_id", sandboxID.String()).Msg("CreateSandbox: INSERT failed, destroying orphan VM")
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), vmdTimeout)
		_ = vmd.DestroyInstance(cleanupCtx, sandboxID.String(), true)
		cleanupCancel()
		respondError(c, ErrInternal)
		return
	case vmdErr != nil:
		// VMD failed but DB row exists — mark it failed so the reaper
		// doesn't leave it stuck in "starting".
		log.Error().Err(vmdErr).Str("sandbox_id", sandbox.ID.String()).Msg("VMD create/resume failed")
		failCtx, failCancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), asyncTimeout)
		defer failCancel()
		_ = h.DB.UpdateSandboxStatus(failCtx, db.UpdateSandboxStatusParams{
			ID:     sandbox.ID,
			Status: db.SandboxStatusFailed,
			TeamID: teamID,
		})
		respondError(c, ErrInternal)
		return
	}

	// Past this point the VM is running. Detach from cancellation so a
	// client disconnect cannot lose the state transition, but preserve
	// the trace/span context so post-VMD writes stay in the request trace.
	postCtx, postCancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), vmdTimeout)
	defer postCancel()

	// Single atomic transition: starting → active with real resources
	// and IP. VMD's response is the source of truth for vcpu/memory
	// (they come from the template snapshot, not from what the control
	// plane requested).
	var ipAddr *netip.Addr
	if ipAddress != "" {
		if addr, parseErr := netip.ParseAddr(ipAddress); parseErr == nil {
			ipAddr = &addr
		}
	}
	sandbox.Status = db.SandboxStatusActive
	sandbox.VcpuCount = int32(actualVcpu)
	sandbox.MemoryMib = int32(actualMemMiB)
	sandbox.IpAddress = ipAddr

	if err := h.DB.ActivateSandbox(postCtx, db.ActivateSandboxParams{
		ID:        sandbox.ID,
		VcpuCount: int32(actualVcpu),
		MemoryMib: int32(actualMemMiB),
		IpAddress: ipAddr,
		TeamID:    teamID,
	}); err != nil {
		log.Error().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("DB ActivateSandbox failed")
	}

	// Apply network rules if provided at creation.
	if req.Network != nil && (len(req.Network.AllowOut) > 0 || len(req.Network.DenyOut) > 0) {
		var allowedCIDRs, allowedDomains []string
		for _, entry := range req.Network.AllowOut {
			if isIPOrCIDR(entry) {
				allowedCIDRs = append(allowedCIDRs, entry)
			} else {
				allowedDomains = append(allowedDomains, entry)
			}
		}

		if err := vmd.UpdateSandboxNetwork(postCtx, sandbox.ID.String(), allowedCIDRs, req.Network.DenyOut, allowedDomains); err != nil {
			log.Error().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("failed to apply network rules at creation")
		} else {
			networkConfig, _ := json.Marshal(map[string]any{
				"egress": map[string]any{
					"allowed_cidrs":   allowedCIDRs,
					"denied_cidrs":    req.Network.DenyOut,
					"allowed_domains": allowedDomains,
				},
			})
			_ = h.DB.UpdateSandboxNetworkConfig(postCtx, db.UpdateSandboxNetworkConfigParams{
				ID:            sandbox.ID,
				NetworkConfig: networkConfig,
				TeamID:        teamID,
			})
		}
	}

	h.logActivityAsync(c.Request.Context(), sandbox.ID, teamID, "sandbox", "started", "success", &sandbox.Name, nil, nil)

	sandbox.Status = db.SandboxStatusActive
	resp := h.sandboxToResponse(sandbox)
	if req.Network != nil && (len(req.Network.AllowOut) > 0 || len(req.Network.DenyOut) > 0) {
		resp.Network = req.Network
	}
	c.JSON(http.StatusCreated, resp)
}

// ---------------------------------------------------------------------------
// Sandbox Pause
// ---------------------------------------------------------------------------

func (h *Handlers) PauseSandbox(c *gin.Context) {
	sandboxID, err := parseSandboxID(c)
	if err != nil {
		return
	}

	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}

	// Verify sandbox exists and belongs to this team.
	sandbox, err := h.DB.GetSandbox(c.Request.Context(), db.GetSandboxParams{
		ID:     sandboxID,
		TeamID: teamID,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			respondError(c, ErrSandboxNotFound)
			return
		}
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB GetSandbox failed")
		respondError(c, ErrInternal)
		return
	}

	// Only active sandboxes can be paused.
	if sandbox.Status != db.SandboxStatusActive {
		respondError(c, ErrInvalidState)
		return
	}

	// Mark as pausing before calling VMD.
	if err := h.DB.UpdateSandboxStatus(c.Request.Context(), db.UpdateSandboxStatusParams{
		ID:     sandboxID,
		Status: db.SandboxStatusPausing,
		TeamID: teamID,
	}); err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB UpdateSandboxStatus(pausing) failed")
		respondError(c, ErrInternal)
		return
	}

	// Resolve the VMD client for this sandbox's host.
	vmd, vmdLookupErr := h.vmdForHost(c.Request.Context(), sandbox.HostID)
	if vmdLookupErr != nil {
		log.Error().Err(vmdLookupErr).Str("sandbox_id", sandboxID.String()).Msg("resolve VMD for pause failed")
		respondError(c, ErrInternal)
		return
	}

	// Call VMD to pause and snapshot the VM.
	vmdCtx, vmdCancel := context.WithTimeout(c.Request.Context(), vmdTimeout)
	defer vmdCancel()
	snapshotPath, memPath, err := vmd.PauseInstance(vmdCtx, sandboxID.String(), "")
	if err != nil {
		// VMD says the VM doesn't exist — it crashed or was removed out-of-band.
		// Mark the sandbox failed and return 410 Gone. No revert — the VM is
		// already dead, "active" was a lie.
		if isVMDNotFound(err) {
			log.Warn().Err(err).Str("sandbox_id", sandboxID.String()).Msg("VMD PauseInstance: VM not found, marking sandbox failed")
			h.markSandboxFailedAsync(c.Request.Context(), sandboxID, teamID)
			respondError(c, ErrSandboxGone)
			return
		}

		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("VMD PauseInstance failed")
		// Revert status to active asynchronously. Detach cancellation so
		// the revert survives client disconnect, but keep trace context
		// so the revert is linked to the original pause request.
		revertCtx := context.WithoutCancel(c.Request.Context())
		go func() {
			ctx, cancel := context.WithTimeout(revertCtx, asyncTimeout)
			defer cancel()
			if revertErr := h.DB.UpdateSandboxStatus(ctx, db.UpdateSandboxStatusParams{
				ID:     sandboxID,
				Status: db.SandboxStatusActive,
				TeamID: teamID,
			}); revertErr != nil {
				log.Error().Err(revertErr).Str("sandbox_id", sandboxID.String()).Msg("async revert to active failed")
			}
		}()
		respondError(c, ErrInternal)
		return
	}

	// TODO: store memPath in snapshot table (requires adding a mem_path column to the
	// snapshot schema). For now, ResumeSandbox derives it via
	// filepath.Join(filepath.Dir(snapshotPath), "mem.snap") by convention.
	log.Debug().
		Str("sandbox_id", sandboxID.String()).
		Str("snapshot_path", snapshotPath).
		Str("mem_path", memPath).
		Msg("VMD pause complete")

	// Past this point the snapshot already exists on disk. Detach from
	// cancellation so a client disconnect cannot orphan the snapshot
	// files, but preserve the trace/span context so the snapshot row
	// creation stays linked to the original pause request trace.
	postCtx, postCancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), vmdTimeout)
	defer postCancel()

	// Create snapshot record in DB.
	triggerName := "pause"
	snapshot, err := h.DB.CreateSnapshot(postCtx, db.CreateSnapshotParams{
		SandboxID: sandboxID,
		TeamID:    teamID,
		Path:      snapshotPath,
		SizeBytes: 0,
		Saved:     false,
		Name:      &triggerName,
		Trigger:   triggerName,
	})
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB CreateSnapshot failed")
		respondError(c, ErrInternal)
		return
	}

	// Link snapshot to sandbox and mark as idle.
	if err := h.DB.SetSandboxSnapshot(postCtx, db.SetSandboxSnapshotParams{
		ID:         sandboxID,
		SnapshotID: pgtype.UUID{Bytes: snapshot.ID, Valid: true},
		TeamID:     teamID,
	}); err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB SetSandboxSnapshot failed")
		respondError(c, ErrInternal)
		return
	}

	if err := h.DB.UpdateSandboxStatus(postCtx, db.UpdateSandboxStatusParams{
		ID:     sandboxID,
		Status: db.SandboxStatusIdle,
		TeamID: teamID,
	}); err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB UpdateSandboxStatus(idle) failed")
		respondError(c, ErrInternal)
		return
	}

	// Async observability.
	h.logActivityAsync(c.Request.Context(), sandboxID, teamID, "sandbox", "paused", "success", &sandbox.Name, nil, nil)

	c.JSON(http.StatusOK, gin.H{
		"id":          sandboxID.String(),
		"name":        sandbox.Name,
		"status":      "idle",
		"snapshot_id": snapshot.ID.String(),
	})
}

// ---------------------------------------------------------------------------
// Sandbox Exec
// ---------------------------------------------------------------------------

type sandboxExecRequest struct {
	Command    string            `json:"command" binding:"required,min=1"`
	Args       []string          `json:"args"`
	Env        map[string]string `json:"env"`
	WorkingDir string            `json:"working_dir"`
	TimeoutS   int               `json:"timeout_s"`
}

// ExecSandbox runs a command inside a sandbox and returns the result.
// The sandbox is loaded and auto-woken by the AutoWake middleware.
func (h *Handlers) ExecSandbox(c *gin.Context) {
	sandbox := sandboxFromContext(c)
	if sandbox == nil {
		respondError(c, ErrInternal)
		return
	}

	var req sandboxExecRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondErrorMsg(c, "bad_request", fmt.Sprintf("Validation failed: %v", err), http.StatusBadRequest)
		return
	}

	if req.TimeoutS <= 0 {
		req.TimeoutS = 30
	}

	vmd, vmdLookupErr := h.vmdForHost(c.Request.Context(), sandbox.HostID)
	if vmdLookupErr != nil {
		log.Error().Err(vmdLookupErr).Str("sandbox_id", sandbox.ID.String()).Msg("resolve VMD for exec failed")
		respondError(c, ErrInternal)
		return
	}

	start := time.Now()
	stdout, stderr, exitCode, err := vmd.ExecCommand(c.Request.Context(), sandbox.ID.String(),
		req.Command, req.Args, req.Env, req.WorkingDir, uint32(req.TimeoutS))
	durationMs := int32(time.Since(start).Milliseconds())
	if err != nil {
		if isVMDNotFound(err) {
			log.Warn().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("VMD ExecCommand: VM not found, marking sandbox failed")
			h.markSandboxFailedAsync(c.Request.Context(), sandbox.ID, sandbox.TeamID)
			respondError(c, ErrSandboxGone)
			return
		}
		log.Error().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("VMD ExecCommand failed")
		respondError(c, ErrInternal)
		return
	}

	// Async observability writes.
	h.updateLastActivityAsync(c.Request.Context(), sandbox.ID, sandbox.TeamID)
	metadata, _ := json.Marshal(map[string]any{
		"command":     req.Command,
		"exit_code":   exitCode,
		"duration_ms": durationMs,
	})
	h.logActivityAsync(c.Request.Context(), sandbox.ID, sandbox.TeamID, "exec", "executed", "success", &sandbox.Name, &durationMs, metadata)

	c.JSON(http.StatusOK, gin.H{
		"stdout":    stdout,
		"stderr":    stderr,
		"exit_code": exitCode,
	})
}

// ---------------------------------------------------------------------------
// Sandbox Patch
// ---------------------------------------------------------------------------

// patchSandboxRequest is the body for PATCH /sandboxes/:id. Each top-level
// field is optional; only fields that are present in the request body are
// applied. Nested objects (like Network) are full replacements when present —
// to clear deny_out, send {"network": {"allow_out": [...], "deny_out": []}},
// not {"network": {"allow_out": [...]}} (which would replace deny_out with
// nil and effectively clear it anyway, but be explicit).
//
// At least one top-level field must be set, otherwise the request is rejected
// with 400. This guards against clients sending empty bodies by mistake and
// silently no-opping.
//
// Patchable fields: `network` and `metadata`. Adding more in the future is
// additive — declare a new pointer field and dispatch on its non-nil-ness.
type patchSandboxRequest struct {
	Network  *networkConfigRequest `json:"network,omitempty"`
	Metadata map[string]string     `json:"metadata,omitempty"`
}

// PatchSandbox applies a partial update to a sandbox.
// - network: replaces egress rules; sandbox must be active.
// - metadata: replaces metadata tags; can be patched in any non-deleted state.
func (h *Handlers) PatchSandbox(c *gin.Context) {
	sandboxID, err := parseSandboxID(c)
	if err != nil {
		return
	}

	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}

	var body patchSandboxRequest
	if err := bindJSONStrict(c, &body); err != nil {
		respondErrorMsg(c, "bad_request", "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Reject empty patches.
	if body.Network == nil && body.Metadata == nil {
		respondErrorMsg(c, "bad_request", "patch body must include at least one field (network, metadata)", http.StatusBadRequest)
		return
	}

	if body.Network != nil {
		if err := validateEgressRules(body.Network.AllowOut, body.Network.DenyOut); err != nil {
			respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
			return
		}
	}

	if body.Metadata != nil {
		if err := validateMetadata(body.Metadata); err != nil {
			respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Verify sandbox exists, belongs to this team, and is active.
	sandbox, err := h.DB.GetSandbox(c.Request.Context(), db.GetSandboxParams{
		ID:     sandboxID,
		TeamID: teamID,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			respondError(c, ErrSandboxNotFound)
			return
		}
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB GetSandbox failed")
		respondError(c, ErrInternal)
		return
	}

	// Network updates require an active sandbox (rules are applied live to the VM).
	if body.Network != nil && sandbox.Status != db.SandboxStatusActive {
		respondErrorMsg(c, "conflict", "Sandbox must be active to update network config", http.StatusConflict)
		return
	}

	if body.Network != nil {
		// Separate CIDRs and domains from allow_out.
		var allowedCIDRs, allowedDomains []string
		for _, entry := range body.Network.AllowOut {
			if isIPOrCIDR(entry) {
				allowedCIDRs = append(allowedCIDRs, entry)
			} else {
				allowedDomains = append(allowedDomains, entry)
			}
		}

		// Resolve the VMD client for this sandbox's host.
		vmd, vmdLookupErr := h.vmdForHost(c.Request.Context(), sandbox.HostID)
		if vmdLookupErr != nil {
			log.Error().Err(vmdLookupErr).Str("sandbox_id", sandboxID.String()).Msg("resolve VMD for patch failed")
			respondError(c, ErrInternal)
			return
		}

		// Apply rules to the running VM via VMD.
		vmdCtx, vmdCancel := context.WithTimeout(c.Request.Context(), vmdTimeout)
		defer vmdCancel()
		if err := vmd.UpdateSandboxNetwork(vmdCtx, sandboxID.String(), allowedCIDRs, body.Network.DenyOut, allowedDomains); err != nil {
			log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("VMD UpdateSandboxNetwork failed")
			respondError(c, ErrInternal)
			return
		}

		// Persist config to DB so it survives pause/resume.
		networkConfig, _ := json.Marshal(map[string]any{
			"egress": map[string]any{
				"allowed_cidrs":   allowedCIDRs,
				"denied_cidrs":    body.Network.DenyOut,
				"allowed_domains": allowedDomains,
			},
		})
		if err := h.DB.UpdateSandboxNetworkConfig(c.Request.Context(), db.UpdateSandboxNetworkConfigParams{
			ID:            sandboxID,
			NetworkConfig: networkConfig,
			TeamID:        teamID,
		}); err != nil {
			log.Warn().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB UpdateSandboxNetworkConfig failed (rules applied, persistence failed)")
		}

		h.logActivityAsync(c.Request.Context(), sandbox.ID, teamID, "network", "updated", "success", &sandbox.Name, nil, networkConfig)
	}

	if body.Metadata != nil {
		metadataJSON, err := json.Marshal(body.Metadata)
		if err != nil {
			log.Error().Err(err).Msg("marshal patch metadata")
			respondError(c, ErrInternal)
			return
		}
		if err := h.DB.UpdateSandboxMetadata(c.Request.Context(), db.UpdateSandboxMetadataParams{
			ID:       sandboxID,
			Metadata: metadataJSON,
			TeamID:   teamID,
		}); err != nil {
			log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB UpdateSandboxMetadata failed")
			respondError(c, ErrInternal)
			return
		}

		h.logActivityAsync(c.Request.Context(), sandbox.ID, teamID, "sandbox", "metadata_updated", "success", &sandbox.Name, nil, nil)
	}

	c.Status(http.StatusNoContent)
}

// bindJSONStrict decodes the request body into v and rejects unknown fields.
//
// This is stricter than gin's c.ShouldBindJSON which silently ignores fields
// not present in the target struct. Strict binding is important for fields
// we intentionally removed (e.g. vcpu_count, memory_mib) so old clients get
// a clear 400 error instead of silently losing their request data.
//
// Returns nil on success, or an error suitable for a 400 Bad Request.
func bindJSONStrict(c *gin.Context, v any) error {
	if c.Request.Body == nil {
		return fmt.Errorf("request body is empty")
	}
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	// Reject trailing garbage / multiple JSON objects.
	if dec.More() {
		return fmt.Errorf("unexpected trailing data after JSON object")
	}
	return nil
}

// isIPOrCIDR returns true if s is a valid IP address or CIDR prefix.
// Used to distinguish CIDR entries from domain names in allow/deny lists.
func isIPOrCIDR(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	return false
}

// validateEgressRules enforces the rules shared between CreateSandbox and
// PatchSandbox:
//
//   - deny_out entries MUST be valid IPv4 CIDRs or IP addresses (domains
//     are not supported in deny lists — there's no way to enforce a domain
//     deny at the IP layer, and mixing silently fails).
//   - allow_out entries can be either IPv4 CIDRs/IPs or domain names.
//   - IPv6 entries are rejected everywhere. Sandboxes are IPv4-only and
//     all IPv6 egress is dropped wholesale by the nftables firewall; we
//     reject v6 in the API instead of silently ignoring it so users get
//     a clear error.
//
// Limits on user-supplied metadata. These are deliberately conservative —
// metadata is meant for tags ("env=prod", "owner=agent-7"), not for shipping
// arbitrary blobs through the sandbox API. Tighter limits also keep the
// jsonb @> filter cheap and bound the cost of the GIN index.
const (
	metadataMaxKeys       = 64    // distinct key/value pairs per sandbox
	metadataMaxKeyLen     = 256   // bytes per key
	metadataMaxValueLen   = 2048  // bytes per value (2 KB)
	metadataMaxTotalBytes = 16384 // total serialized jsonb size (16 KB)
)

// metadataReservedPrefixes are key prefixes the platform reserves for its
// own use. Today nothing actually emits these, but reserving them now means
// we can introduce internal tags later (e.g., `superserve.billing.tier`)
// without having to migrate user data out of the way. The check is
// case-insensitive so users can't sneak through with `Superserve.foo`.
var metadataReservedPrefixes = []string{"superserve.", "_superserve"}

// validateMetadata enforces all the size and naming rules on a user-supplied
// metadata map. Returns nil on success or a 400-appropriate error.
//
// nil and empty maps are both fine — they yield an empty jsonb object in
// the database. The caller is responsible for marshalling.
//
// Important: this validation is the *only* place where reserved prefixes
// are enforced, so any new code that writes to sandbox.metadata must route
// through here (or add its own check). Today the only writer is
// CreateSandbox.
func validateMetadata(md map[string]string) error {
	if len(md) == 0 {
		return nil
	}
	if len(md) > metadataMaxKeys {
		return fmt.Errorf("metadata has %d keys, max is %d", len(md), metadataMaxKeys)
	}

	totalBytes := 0
	for k, v := range md {
		if k == "" {
			return fmt.Errorf("metadata keys cannot be empty")
		}
		if len(k) > metadataMaxKeyLen {
			return fmt.Errorf("metadata key %q is %d bytes, max is %d", k, len(k), metadataMaxKeyLen)
		}
		if len(v) > metadataMaxValueLen {
			return fmt.Errorf("metadata value for key %q is %d bytes, max is %d", k, len(v), metadataMaxValueLen)
		}
		lower := strings.ToLower(k)
		for _, prefix := range metadataReservedPrefixes {
			if strings.HasPrefix(lower, prefix) {
				return fmt.Errorf("metadata key %q uses reserved prefix %q", k, prefix)
			}
		}
		totalBytes += len(k) + len(v)
		if totalBytes > metadataMaxTotalBytes {
			return fmt.Errorf("metadata exceeds %d bytes total", metadataMaxTotalBytes)
		}
	}
	return nil
}

// Env var validation limits. Same key count cap as metadata; values are
// larger (API keys, connection strings) so 8 KB per value, 64 KB total.
const (
	envVarsMaxKeys       = 64
	envVarsMaxKeyLen     = 256
	envVarsMaxValueLen   = 8192  // 8 KB — API keys, tokens, DSNs
	envVarsMaxTotalBytes = 65536 // 64 KB
)

func validateEnvVars(env map[string]string) error {
	if len(env) == 0 {
		return nil
	}
	if len(env) > envVarsMaxKeys {
		return fmt.Errorf("env_vars has %d keys, max is %d", len(env), envVarsMaxKeys)
	}
	totalBytes := 0
	for k, v := range env {
		if k == "" {
			return fmt.Errorf("env_vars keys cannot be empty")
		}
		if len(k) > envVarsMaxKeyLen {
			return fmt.Errorf("env_vars key %q is %d bytes, max is %d", k, len(k), envVarsMaxKeyLen)
		}
		if len(v) > envVarsMaxValueLen {
			return fmt.Errorf("env_vars value for key %q is %d bytes, max is %d", k, len(v), envVarsMaxValueLen)
		}
		totalBytes += len(k) + len(v)
		if totalBytes > envVarsMaxTotalBytes {
			return fmt.Errorf("env_vars exceeds %d bytes total", envVarsMaxTotalBytes)
		}
	}
	return nil
}

// Returns nil on success or a 400-appropriate error message.
func validateEgressRules(allowOut, denyOut []string) error {
	for _, entry := range denyOut {
		if !isIPOrCIDR(entry) {
			return fmt.Errorf("deny_out only supports CIDRs, got %q", entry)
		}
		if isIPv6(entry) {
			return fmt.Errorf("IPv6 is not supported, got %q in deny_out", entry)
		}
	}
	for _, entry := range allowOut {
		if isIPOrCIDR(entry) && isIPv6(entry) {
			return fmt.Errorf("IPv6 is not supported, got %q in allow_out", entry)
		}
	}
	return nil
}

// isIPv6 returns true if s is a valid IPv6 address or IPv6 CIDR.
// Assumes the caller has already confirmed via isIPOrCIDR that s parses.
func isIPv6(s string) bool {
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Is6() && !addr.Is4In6()
	}
	if prefix, err := netip.ParsePrefix(s); err == nil {
		return prefix.Addr().Is6() && !prefix.Addr().Is4In6()
	}
	return false
}
