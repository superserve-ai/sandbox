package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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

	// Destroy the VM.
	vmdCtx, vmdCancel := context.WithTimeout(c.Request.Context(), vmdTimeout)
	defer vmdCancel()
	if err := h.VMD.DestroyInstance(vmdCtx, sandboxID.String(), true); err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("VMD DestroyInstance failed")
		respondError(c, ErrInternal)
		return
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

	// Log activity.
	status := "success"
	_, err = h.DB.CreateActivity(c.Request.Context(), db.CreateActivityParams{
		SandboxID:   sandboxID,
		TeamID:      teamID,
		Category:    "sandbox",
		Action:      "deleted",
		Status:      &status,
		SandboxName: &sandbox.Name,
	})
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("failed to log delete activity")
	}

	c.Status(http.StatusNoContent)
}
