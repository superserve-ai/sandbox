package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/state"
)

// Versioned-/state endpoints (Epic 4.3): checkpoint / branch / rollback over a
// sandbox's durable state, addressed by the sandbox id. These map the
// state.Provider's git-like surface onto the API and back the Actor `fork`
// semantics (a branch is a fork of an Actor's state). Enabled only when a State
// provider is configured (the LocalProvider in dev/tests; Archil/Mesa in prod).

func (h *Handlers) stateEnabled(c *gin.Context) bool {
	if h.State == nil {
		respondErrorMsg(c, "not_implemented", "durable /state versioning is not enabled on this deployment", http.StatusNotImplemented)
		return false
	}
	return true
}

// requireSandbox parses the path id and confirms the caller's team owns it.
func (h *Handlers) requireSandbox(c *gin.Context) (uuid.UUID, bool) {
	sandboxID, err := parseSandboxID(c)
	if err != nil {
		return uuid.Nil, false
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return uuid.Nil, false
	}
	if _, err := h.DB.GetSandbox(c.Request.Context(), db.GetSandboxParams{ID: sandboxID, TeamID: teamID}); err != nil {
		respondErrorMsg(c, "not_found", "Sandbox not found", http.StatusNotFound)
		return uuid.Nil, false
	}
	return sandboxID, true
}

type checkpointRequest struct {
	Name string `json:"name"`
}

// CreateCheckpoint records a named, immutable snapshot of the sandbox's state.
func (h *Handlers) CreateCheckpoint(c *gin.Context) {
	if !h.stateEnabled(c) {
		return
	}
	sid, ok := h.requireSandbox(c)
	if !ok {
		return
	}
	var req checkpointRequest
	if err := bindJSONStrict(c, &req); err != nil || req.Name == "" {
		respondErrorMsg(c, "bad_request", "name is required", http.StatusBadRequest)
		return
	}
	cp, err := h.State.Checkpoint(c.Request.Context(), sid.String(), req.Name)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"name": cp.Name, "id": cp.ID, "created_at": cp.CreatedAt})
}

// ListCheckpoints returns the sandbox's checkpoints, oldest-first.
func (h *Handlers) ListCheckpoints(c *gin.Context) {
	if !h.stateEnabled(c) {
		return
	}
	sid, ok := h.requireSandbox(c)
	if !ok {
		return
	}
	cps, err := h.State.ListCheckpoints(c.Request.Context(), sid.String())
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	out := make([]gin.H, 0, len(cps))
	for _, cp := range cps {
		out = append(out, gin.H{"name": cp.Name, "id": cp.ID, "created_at": cp.CreatedAt})
	}
	c.JSON(http.StatusOK, gin.H{"checkpoints": out})
}

type branchRequest struct {
	Name           string `json:"name"`
	FromCheckpoint string `json:"from_checkpoint"`
}

// CreateBranch forks the sandbox's state into an independent writable branch
// from a checkpoint (the Actor `fork` primitive).
func (h *Handlers) CreateBranch(c *gin.Context) {
	if !h.stateEnabled(c) {
		return
	}
	sid, ok := h.requireSandbox(c)
	if !ok {
		return
	}
	var req branchRequest
	if err := bindJSONStrict(c, &req); err != nil || req.Name == "" || req.FromCheckpoint == "" {
		respondErrorMsg(c, "bad_request", "name and from_checkpoint are required", http.StatusBadRequest)
		return
	}
	if err := h.State.Branch(c.Request.Context(), sid.String(), req.FromCheckpoint, req.Name); err != nil {
		if errors.Is(err, state.ErrCheckpointNotFound) {
			respondErrorMsg(c, "not_found", "checkpoint not found", http.StatusNotFound)
			return
		}
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"branch": req.Name, "from_checkpoint": req.FromCheckpoint})
}

type rollbackRequest struct {
	Checkpoint string `json:"checkpoint"`
}

// RollbackState re-homes the sandbox's current state onto a checkpoint.
func (h *Handlers) RollbackState(c *gin.Context) {
	if !h.stateEnabled(c) {
		return
	}
	sid, ok := h.requireSandbox(c)
	if !ok {
		return
	}
	var req rollbackRequest
	if err := bindJSONStrict(c, &req); err != nil || req.Checkpoint == "" {
		respondErrorMsg(c, "bad_request", "checkpoint is required", http.StatusBadRequest)
		return
	}
	if err := h.State.Rollback(c.Request.Context(), sid.String(), req.Checkpoint); err != nil {
		if errors.Is(err, state.ErrCheckpointNotFound) {
			respondErrorMsg(c, "not_found", "checkpoint not found", http.StatusNotFound)
			return
		}
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusOK, gin.H{"rolled_back_to": req.Checkpoint})
}
