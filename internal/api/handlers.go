package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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

	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

// VMDClient defines the subset of the VM daemon gRPC interface used by the
// control plane. This is satisfied by the gRPC adapter in cmd/controlplane.
type VMDClient interface {
	CreateInstance(ctx context.Context, instanceID string, vcpu, memMiB, diskMiB uint32, metadata map[string]string) (ipAddress string, err error)
	DestroyInstance(ctx context.Context, instanceID string, force bool) error
	PauseInstance(ctx context.Context, instanceID, snapshotDir string) (snapshotPath, memPath string, err error)
	ResumeInstance(ctx context.Context, instanceID, snapshotPath, memPath string) (ipAddress string, err error)
	ExecCommand(ctx context.Context, instanceID, command string, args []string, env map[string]string, workingDir string, timeoutS uint32) (stdout, stderr string, exitCode int32, err error)
	ExecCommandStream(ctx context.Context, instanceID, command string, args []string, env map[string]string, workingDir string, timeoutS uint32, onChunk func(stdout, stderr []byte, exitCode int32, finished bool)) error
	UploadFile(ctx context.Context, instanceID, path string, content io.Reader) (int64, error)
	DownloadFile(ctx context.Context, instanceID, path string) (io.ReadCloser, error)
	UpdateSandboxNetwork(ctx context.Context, instanceID string, allowedCIDRs, deniedCIDRs, allowedDomains []string) error
}

// Handlers holds shared dependencies for all route handlers.
type Handlers struct {
	VMD    VMDClient
	DB     *db.Queries
	Config *config.Config
}

// NewHandlers creates a new Handlers instance.
func NewHandlers(vmd VMDClient, queries *db.Queries, cfg *config.Config) *Handlers {
	return &Handlers{
		VMD:    vmd,
		DB:     queries,
		Config: cfg,
	}
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
			vmdCtx, vmdCancel := context.WithTimeout(c.Request.Context(), vmdTimeout)
			defer vmdCancel()
			if _, err := h.VMD.ResumeInstance(vmdCtx, sandboxID.String(), "", ""); err != nil {
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
			if err := h.reapplyNetworkConfig(postCtx, sandboxID.String(), sandbox.NetworkConfig); err != nil {
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
func (h *Handlers) reapplyNetworkConfig(ctx context.Context, sandboxID string, raw []byte) error {
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

	return h.VMD.UpdateSandboxNetwork(ctx, sandboxID,
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
// Instance CRUD
// ---------------------------------------------------------------------------

type createInstanceRequest struct {
	Name string `json:"name" binding:"required,min=1,max=64"`
}

func (h *Handlers) CreateInstance(c *gin.Context) {
	var req createInstanceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondErrorMsg(c, "bad_request", fmt.Sprintf("Validation failed: %v", err), http.StatusBadRequest)
		return
	}

	instanceID := uuid.New().String()

	vmdCtx, vmdCancel := context.WithTimeout(c.Request.Context(), vmdTimeout)
	defer vmdCancel()
	_, err := h.VMD.CreateInstance(vmdCtx, instanceID, 0, 0, 0, nil)
	if err != nil {
		log.Error().Err(err).Str("instance_id", instanceID).Msg("VMD CreateInstance failed")
		respondError(c, ErrInternal)
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":     instanceID,
		"name":   req.Name,
		"status": "RUNNING",
	})
}

func (h *Handlers) GetInstance(c *gin.Context) {
	instanceID, err := parseInstanceID(c)
	if err != nil {
		return
	}

	// TODO: when DB is added, look up instance state from DB.
	// For now, query VMD directly.
	respondErrorMsg(c, "not_implemented", fmt.Sprintf("GetInstance %s — requires DB (not yet connected)", instanceID), http.StatusNotImplemented)
}

func (h *Handlers) ListInstances(c *gin.Context) {
	// TODO: when DB is added, list from DB.
	respondErrorMsg(c, "not_implemented", "ListInstances — requires DB (not yet connected)", http.StatusNotImplemented)
}

func (h *Handlers) DeleteInstance(c *gin.Context) {
	instanceID, err := parseInstanceID(c)
	if err != nil {
		return
	}

	vmdCtx, vmdCancel := context.WithTimeout(c.Request.Context(), vmdTimeout)
	defer vmdCancel()
	if err := h.VMD.DestroyInstance(vmdCtx, instanceID.String(), true); err != nil {
		log.Error().Err(err).Str("instance_id", instanceID.String()).Msg("VMD DestroyInstance failed")
		respondError(c, ErrInternal)
		return
	}

	c.Status(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Pause / Resume
// ---------------------------------------------------------------------------

func (h *Handlers) PauseInstance(c *gin.Context) {
	instanceID, err := parseInstanceID(c)
	if err != nil {
		return
	}

	vmdCtx, vmdCancel := context.WithTimeout(c.Request.Context(), vmdTimeout)
	defer vmdCancel()
	_, _, err = h.VMD.PauseInstance(vmdCtx, instanceID.String(), "")
	if err != nil {
		log.Error().Err(err).Str("instance_id", instanceID.String()).Msg("VMD PauseInstance failed")
		respondError(c, ErrInternal)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":     instanceID.String(),
		"status": "PAUSED",
	})
}

func (h *Handlers) ResumeInstance(c *gin.Context) {
	instanceID, err := parseInstanceID(c)
	if err != nil {
		return
	}

	// TODO: when DB is added, read snapshot paths from DB.
	// For now, pass empty paths — VMD uses its default.
	vmdCtx, vmdCancel := context.WithTimeout(c.Request.Context(), vmdTimeout)
	defer vmdCancel()
	ipAddress, err := h.VMD.ResumeInstance(vmdCtx, instanceID.String(), "", "")
	if err != nil {
		log.Error().Err(err).Str("instance_id", instanceID.String()).Msg("VMD ResumeInstance failed")
		respondError(c, ErrInternal)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":         instanceID.String(),
		"status":     "RUNNING",
		"ip_address": ipAddress,
	})
}

// ---------------------------------------------------------------------------
// Exec
// ---------------------------------------------------------------------------

type execRequest struct {
	Command    string            `json:"command" binding:"required,min=1"`
	Args       []string          `json:"args"`
	Env        map[string]string `json:"env"`
	WorkingDir string            `json:"working_dir"`
	TimeoutS   int               `json:"timeout_s"`
}

func (h *Handlers) ExecCommand(c *gin.Context) {
	instanceID, err := parseInstanceID(c)
	if err != nil {
		return
	}

	var req execRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondErrorMsg(c, "bad_request", fmt.Sprintf("Validation failed: %v", err), http.StatusBadRequest)
		return
	}

	if req.TimeoutS <= 0 {
		req.TimeoutS = 30
	}

	stdout, stderr, exitCode, err := h.VMD.ExecCommand(c.Request.Context(), instanceID.String(),
		req.Command, req.Args, req.Env, req.WorkingDir, uint32(req.TimeoutS))
	if err != nil {
		log.Error().Err(err).Str("instance_id", instanceID.String()).Msg("VMD ExecCommand failed")
		respondError(c, ErrInternal)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"stdout":    stdout,
		"stderr":    stderr,
		"exit_code": exitCode,
	})
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

func (h *Handlers) UploadFile(c *gin.Context) {
	instanceID, err := parseInstanceID(c)
	if err != nil {
		return
	}

	filePath, err := cleanFilePath(c.Param("path"))
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}

	bytesWritten, err := h.VMD.UploadFile(c.Request.Context(), instanceID.String(), filePath, c.Request.Body)
	if err != nil {
		log.Error().Err(err).Str("instance_id", instanceID.String()).Msg("file upload failed")
		respondError(c, ErrInternal)
		return
	}

	c.JSON(http.StatusOK, gin.H{"path": filePath, "size": bytesWritten})
}

func (h *Handlers) DownloadFile(c *gin.Context) {
	instanceID, err := parseInstanceID(c)
	if err != nil {
		return
	}

	filePath, err := cleanFilePath(c.Param("path"))
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}

	reader, err := h.VMD.DownloadFile(c.Request.Context(), instanceID.String(), filePath)
	if err != nil {
		log.Error().Err(err).Str("instance_id", instanceID.String()).Msg("file download failed")
		errMsg := err.Error()
		if strings.Contains(errMsg, "404") || strings.Contains(errMsg, "not found") {
			respondErrorMsg(c, "not_found",
				fmt.Sprintf("File not found: %s", filePath),
				http.StatusNotFound)
		} else {
			respondError(c, ErrInternal)
		}
		return
	}
	defer reader.Close()

	c.Header("Content-Type", "application/octet-stream")
	c.Status(http.StatusOK)
	io.Copy(c.Writer, reader)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func cleanFilePath(raw string) (string, error) {
	raw = strings.TrimPrefix(raw, "/")
	if raw == "" {
		return "", fmt.Errorf("file path is required")
	}
	if strings.Contains(raw, "..") {
		return "", fmt.Errorf("path traversal not allowed")
	}
	cleaned := filepath.Clean("/" + raw)
	return cleaned, nil
}

func parseInstanceID(c *gin.Context) (uuid.UUID, error) {
	raw := c.Param("instance_id")
	id, err := uuid.Parse(raw)
	if err != nil {
		respondErrorMsg(c, "bad_request",
			fmt.Sprintf("Invalid instance_id: %q is not a valid UUID", raw),
			http.StatusBadRequest)
		return uuid.Nil, err
	}
	return id, nil
}

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

	snapshot, err := h.DB.GetSnapshot(c.Request.Context(), sandbox.SnapshotID.Bytes)
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB GetSnapshot failed")
		respondError(c, ErrInternal)
		return
	}

	snapshotPath := snapshot.Path
	memPath := filepath.Join(filepath.Dir(snapshotPath), "mem.snap")

	// Resume the VM. Cancellation of this call still follows the request
	// context — if the client hangs up mid-resume, abort the VMD call.
	vmdCtx, vmdCancel := context.WithTimeout(c.Request.Context(), vmdTimeout)
	defer vmdCancel()
	ipAddress, err := h.VMD.ResumeInstance(vmdCtx, sandboxID.String(), snapshotPath, memPath)
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("VMD ResumeInstance failed")
		respondError(c, ErrInternal)
		return
	}

	// Past this point the VM is running. Detach from cancellation so a
	// client disconnect cannot leave the sandbox stuck in "idle" while
	// the VM is actually up, but preserve the trace/span context so
	// these DB writes still appear in the request trace.
	postCtx, postCancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), vmdTimeout)
	defer postCancel()

	// Update sandbox status to active.
	if err := h.DB.UpdateSandboxStatus(postCtx, db.UpdateSandboxStatusParams{
		ID:     sandboxID,
		Status: db.SandboxStatusActive,
		TeamID: teamID,
	}); err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB UpdateSandboxStatus failed")
		respondError(c, ErrInternal)
		return
	}

	// Update host runtime info.
	ipAddr, _ := netip.ParseAddr(ipAddress)
	if err := h.DB.UpdateSandboxHost(postCtx, db.UpdateSandboxHostParams{
		ID:        sandboxID,
		HostID:    sandbox.HostID,
		IpAddress: &ipAddr,
		TeamID:    teamID,
	}); err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB UpdateSandboxHost failed")
		respondError(c, ErrInternal)
		return
	}

	// Reapply persisted egress rules — the nftables rules and proxy state
	// are fresh after a snapshot restore, so user rules must be re-pushed.
	if err := h.reapplyNetworkConfig(postCtx, sandboxID.String(), sandbox.NetworkConfig); err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("reapply network config on resume failed")
		respondError(c, ErrInternal)
		return
	}

	// Async observability writes.
	h.updateLastActivityAsync(c.Request.Context(), sandboxID, teamID)
	h.logActivityAsync(c.Request.Context(), sandboxID, teamID, "sandbox", "resumed", "success", &sandbox.Name, nil, nil)

	c.JSON(http.StatusOK, gin.H{
		"id":         sandboxID.String(),
		"name":       sandbox.Name,
		"status":     "active",
		"ip_address": ipAddress,
	})
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
		vmdCtx, vmdCancel := context.WithTimeout(c.Request.Context(), vmdTimeout)
		defer vmdCancel()
		if err := h.VMD.DestroyInstance(vmdCtx, sandboxID.String(), true); err != nil {
			log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("VMD DestroyInstance failed")
			respondError(c, ErrInternal)
			return
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

	// AllowInternetAccess is syntactic sugar for a network config. If set
	// to false and Network is not provided (or Network.DenyOut is empty),
	// we inject "0.0.0.0/0" into deny_out so the sandbox cannot reach any
	// public IP. An explicit Network config takes precedence — we only
	// apply this shortcut when the user has not already expressed deny
	// intent.
	//
	// Pointer so we can distinguish unset (nil → default allow) from
	// explicitly false.
	AllowInternetAccess *bool `json:"allow_internet_access,omitempty"`
}

type sandboxResponse struct {
	ID         uuid.UUID  `json:"id"`
	Name       string     `json:"name"`
	Status     string     `json:"status"`
	VcpuCount  int32      `json:"vcpu_count"`
	MemoryMib  int32      `json:"memory_mib"`
	IPAddress  string     `json:"ip_address,omitempty"`
	SnapshotID *uuid.UUID `json:"snapshot_id,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

func sandboxToResponse(s db.Sandbox) sandboxResponse {
	resp := sandboxResponse{
		ID:        s.ID,
		Name:      s.Name,
		Status:    string(s.Status),
		VcpuCount: s.VcpuCount,
		MemoryMib: s.MemoryMib,
		CreatedAt: s.CreatedAt,
	}
	if s.IpAddress != nil {
		resp.IPAddress = s.IpAddress.String()
	}
	if s.SnapshotID.Valid {
		id := uuid.UUID(s.SnapshotID.Bytes)
		resp.SnapshotID = &id
	}
	return resp
}

// ---------------------------------------------------------------------------
// Sandbox List + Get
// ---------------------------------------------------------------------------

func (h *Handlers) ListSandboxes(c *gin.Context) {
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}

	sandboxes, err := h.DB.ListSandboxesByTeam(c.Request.Context(), teamID)
	if err != nil {
		log.Error().Err(err).Msg("DB ListSandboxesByTeam failed")
		respondError(c, ErrInternal)
		return
	}

	out := make([]sandboxResponse, len(sandboxes))
	for i, s := range sandboxes {
		out[i] = sandboxToResponse(s)
	}
	c.JSON(http.StatusOK, out)
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

	c.JSON(http.StatusOK, sandboxToResponse(sandbox))
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

	// Translate allow_internet_access: false into an equivalent deny rule
	// so the rest of the flow treats it like any other egress config.
	// An explicit Network config wins — we only inject a deny when the
	// user has not already expressed intent for deny_out. This makes the
	// boolean a pure convenience sugar over the granular network field.
	if req.AllowInternetAccess != nil && !*req.AllowInternetAccess {
		if req.Network == nil {
			req.Network = &networkConfigRequest{DenyOut: []string{"0.0.0.0/0"}}
		} else if len(req.Network.DenyOut) == 0 {
			req.Network.DenyOut = []string{"0.0.0.0/0"}
		}
	}

	// Validate network rules up front so we fail before doing any DB or VMD work.
	if req.Network != nil {
		if err := validateEgressRules(req.Network.AllowOut, req.Network.DenyOut); err != nil {
			respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
			return
		}
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

		snapshot, err := h.DB.GetSnapshot(c.Request.Context(), snapUUID)
		if err != nil {
			respondErrorMsg(c, "not_found", "Snapshot not found", http.StatusNotFound)
			return
		}
		if snapshot.TeamID != teamID {
			respondErrorMsg(c, "not_found", "Snapshot not found", http.StatusNotFound)
			return
		}

		snapshotID = pgtype.UUID{Bytes: snapUUID, Valid: true}
		snapshotPath = snapshot.Path
		snapshotMemPath = filepath.Join(filepath.Dir(snapshotPath), "mem.snap")
	}

	// Default template resources (1 vCPU, 512 MiB).
	const defaultVcpu int32 = 1
	const defaultMemoryMib int32 = 512

	// Insert sandbox with status=starting.
	sandbox, err := h.DB.CreateSandbox(c.Request.Context(), db.CreateSandboxParams{
		TeamID:     teamID,
		Name:       req.Name,
		Status:     db.SandboxStatusStarting,
		VcpuCount:  defaultVcpu,
		MemoryMib:  defaultMemoryMib,
		SnapshotID: snapshotID,
	})
	if err != nil {
		log.Error().Err(err).Msg("failed to create sandbox record")
		respondError(c, ErrInternal)
		return
	}

	// Boot the VM synchronously — the client gets a response only after
	// the sandbox is fully running and ready to use. This call is still
	// scoped to the request context so that if the client hangs up, the
	// boot is cancelled and VMD cleans up.
	vmdCtx, vmdCancel := context.WithTimeout(c.Request.Context(), vmdTimeout)
	defer vmdCancel()

	var ipAddress string
	var vmdErr error
	if req.FromSnapshot != nil {
		ipAddress, vmdErr = h.VMD.ResumeInstance(vmdCtx, sandbox.ID.String(), snapshotPath, snapshotMemPath)
	} else {
		ipAddress, vmdErr = h.VMD.CreateInstance(vmdCtx, sandbox.ID.String(),
			uint32(defaultVcpu), uint32(defaultMemoryMib), 0, nil)
	}
	if vmdErr != nil {
		log.Error().Err(vmdErr).Str("sandbox_id", sandbox.ID.String()).Msg("VMD create/resume failed")
		// Mark the row failed using a cancellation-detached context so a
		// disconnected client does not leave the sandbox stuck in
		// "starting", but keep trace context so the failure write shows
		// up in the same request span.
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

	// Mark active in DB.
	if err := h.DB.UpdateSandboxStatus(postCtx, db.UpdateSandboxStatusParams{
		ID:     sandbox.ID,
		Status: db.SandboxStatusActive,
		TeamID: teamID,
	}); err != nil {
		log.Error().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("DB UpdateSandboxStatus(active) failed")
	}

	// Persist the VM's assigned IP. host_id and pid are not tracked yet.
	if ipAddress != "" {
		if addr, parseErr := netip.ParseAddr(ipAddress); parseErr == nil {
			if err := h.DB.UpdateSandboxHost(postCtx, db.UpdateSandboxHostParams{
				ID:        sandbox.ID,
				IpAddress: &addr,
				TeamID:    teamID,
			}); err != nil {
				log.Error().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("DB UpdateSandboxHost failed")
			}
		}
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

		if err := h.VMD.UpdateSandboxNetwork(postCtx, sandbox.ID.String(), allowedCIDRs, req.Network.DenyOut, allowedDomains); err != nil {
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

	c.JSON(http.StatusCreated, sandboxResponse{
		ID:        sandbox.ID,
		Name:      sandbox.Name,
		Status:    string(db.SandboxStatusActive),
		VcpuCount: sandbox.VcpuCount,
		MemoryMib: sandbox.MemoryMib,
		CreatedAt: sandbox.CreatedAt,
	})
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

	// Call VMD to pause and snapshot the VM.
	vmdCtx, vmdCancel := context.WithTimeout(c.Request.Context(), vmdTimeout)
	defer vmdCancel()
	snapshotPath, memPath, err := h.VMD.PauseInstance(vmdCtx, sandboxID.String(), "")
	if err != nil {
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
// Sandbox Files
// ---------------------------------------------------------------------------

// UploadSandboxFile uploads a file to a sandbox. The sandbox is loaded and
// auto-woken by the AutoWake middleware.
func (h *Handlers) UploadSandboxFile(c *gin.Context) {
	sandbox := sandboxFromContext(c)
	if sandbox == nil {
		respondError(c, ErrInternal)
		return
	}

	filePath, err := cleanFilePath(c.Param("path"))
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}

	bytesWritten, err := h.VMD.UploadFile(c.Request.Context(), sandbox.ID.String(), filePath, c.Request.Body)
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("sandbox file upload failed")
		respondError(c, ErrInternal)
		return
	}

	h.updateLastActivityAsync(c.Request.Context(), sandbox.ID, sandbox.TeamID)

	c.JSON(http.StatusOK, gin.H{"path": filePath, "size": bytesWritten})
}

// DownloadSandboxFile downloads a file from a sandbox. The sandbox is loaded
// and auto-woken by the AutoWake middleware.
func (h *Handlers) DownloadSandboxFile(c *gin.Context) {
	sandbox := sandboxFromContext(c)
	if sandbox == nil {
		respondError(c, ErrInternal)
		return
	}

	filePath, err := cleanFilePath(c.Param("path"))
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}

	reader, err := h.VMD.DownloadFile(c.Request.Context(), sandbox.ID.String(), filePath)
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("sandbox file download failed")
		errMsg := err.Error()
		if strings.Contains(errMsg, "404") || strings.Contains(errMsg, "not found") {
			respondErrorMsg(c, "not_found",
				fmt.Sprintf("File not found: %s", filePath),
				http.StatusNotFound)
		} else {
			respondError(c, ErrInternal)
		}
		return
	}
	defer reader.Close()

	h.updateLastActivityAsync(c.Request.Context(), sandbox.ID, sandbox.TeamID)

	c.Header("Content-Type", "application/octet-stream")
	c.Status(http.StatusOK)
	io.Copy(c.Writer, reader)
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

	start := time.Now()
	stdout, stderr, exitCode, err := h.VMD.ExecCommand(c.Request.Context(), sandbox.ID.String(),
		req.Command, req.Args, req.Env, req.WorkingDir, uint32(req.TimeoutS))
	durationMs := int32(time.Since(start).Milliseconds())
	if err != nil {
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
// Today the only patchable field is `network`. Adding more in the future is
// additive — declare a new pointer field and dispatch on its non-nil-ness.
type patchSandboxRequest struct {
	Network *networkConfigRequest `json:"network,omitempty"`
}

// PatchSandbox applies a partial update to a running sandbox. Currently the
// only patchable field is `network`, which replaces the egress rules for the
// sandbox. The sandbox must be in the active state — patching a paused or
// idle sandbox returns 409.
//
// Replaces the previous PUT /sandboxes/:id/network endpoint. The wrapping
// under a top-level field name leaves room to patch additional fields later
// without breaking the route shape.
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

	// Reject empty patches. We use a strict decoder so unknown fields are
	// already a 400; this catches the legitimate-shape-but-empty case
	// (e.g. `{}` or `{"network": null}`) which would otherwise silently
	// succeed as a no-op.
	if body.Network == nil {
		respondErrorMsg(c, "bad_request", "patch body must include at least one field (network)", http.StatusBadRequest)
		return
	}

	// Validate the egress rules before doing any DB or VMD work so we can
	// fail fast with a clean 400 instead of writing a row we'd need to
	// roll back.
	if err := validateEgressRules(body.Network.AllowOut, body.Network.DenyOut); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
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

	if sandbox.Status != db.SandboxStatusActive {
		respondErrorMsg(c, "conflict", "Sandbox must be active to update network config", http.StatusConflict)
		return
	}

	// Separate CIDRs and domains from allow_out.
	var allowedCIDRs, allowedDomains []string
	for _, entry := range body.Network.AllowOut {
		if isIPOrCIDR(entry) {
			allowedCIDRs = append(allowedCIDRs, entry)
		} else {
			allowedDomains = append(allowedDomains, entry)
		}
	}

	// Apply rules to the running VM via VMD.
	vmdCtx, vmdCancel := context.WithTimeout(c.Request.Context(), vmdTimeout)
	defer vmdCancel()
	if err := h.VMD.UpdateSandboxNetwork(vmdCtx, sandboxID.String(), allowedCIDRs, body.Network.DenyOut, allowedDomains); err != nil {
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
