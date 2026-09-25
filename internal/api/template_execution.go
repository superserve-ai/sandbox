package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/backup"
	"github.com/superserve-ai/sandbox/internal/db"
)

// AdmitTemplateAttempt shares the host row lock with drain and heartbeat.
// The VMD calls it only after checking its installed incarnation identity.
func (h *Handlers) AdmitTemplateAttempt(c *gin.Context) {
	var req struct {
		AttemptID     uuid.UUID `json:"attempt_id"`
		IncarnationID uuid.UUID `json:"incarnation_id"`
	}
	if err := bindJSONStrict(c, &req); err != nil || req.AttemptID == uuid.Nil || req.IncarnationID == uuid.Nil {
		respondErrorMsg(c, "bad_request", "attempt and incarnation are required", http.StatusBadRequest)
		return
	}
	ok, err := h.DB.AdmitBuildAttempt(c.Request.Context(), req.AttemptID, c.Param("host_id"), req.IncarnationID)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	if !ok {
		respondErrorMsg(c, "admission_rejected", "attempt fenced or host not eligible", http.StatusConflict)
		return
	}
	c.JSON(http.StatusOK, gin.H{"admitted": true})
}

func (h *Handlers) reportTemplatePublication(c *gin.Context, req backupReport) {
	ctx := c.Request.Context()
	id, err := uuid.Parse(strings.TrimPrefix(req.BuildID, "build-"))
	var a db.BuildAttempt
	if err == nil {
		a, err = h.DB.GetBuildAttempt(ctx, id)
	} else {
		err = pgx.ErrNoRows
	}
	if errors.Is(err, pgx.ErrNoRows) {
		// Legacy completed builds still contribute backup coverage, but never
		// receive an accepted publication or new durable-readiness claim.
		tpl, parseErr := uuid.Parse(req.TemplateID)
		if parseErr != nil {
			respondErrorMsg(c, "bad_request", "invalid template", http.StatusBadRequest)
			return
		}
		files, _ := json.Marshal(req.Files)
		rows, recordErr := h.DB.RecordTemplateBackupGeneration(ctx, db.RecordTemplateBackupGenerationParams{
			TemplateID: pgtype.UUID{Bytes: tpl, Valid: true}, BuildID: &req.BuildID, Generation: req.Generation,
			Bucket: req.Bucket, Files: files, CompletedAt: req.CompletedAt})
		if recordErr != nil {
			respondError(c, ErrInternal)
			return
		}
		c.JSON(http.StatusOK, gin.H{"recorded": rows > 0})
		return
	}
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	if a.TemplateID.String() != req.TemplateID || a.VMID != req.BuildID || a.HostID != c.Param("host_id") || a.IncarnationID.String() != req.BuildIncarnation {
		respondErrorMsg(c, "bad_request", "publication owner mismatch", http.StatusBadRequest)
		return
	}
	if h.Config == nil || h.Config.TemplateBackupBucket == "" || req.Bucket != h.Config.TemplateBackupBucket {
		respondErrorMsg(c, "publication_configuration", "cell backup bucket mismatch or missing configuration", http.StatusServiceUnavailable)
		return
	}
	files := make([]backup.PublicationFile, 0, len(req.Files))
	keyFiles := make([]backup.TaskFile, 0, len(req.Files))
	for _, f := range req.Files {
		files = append(files, backup.PublicationFile{Name: f.Name, RuntimePath: f.RuntimePath, SizeBytes: f.SizeBytes, AllocatedBytes: f.AllocatedBytes, SHA256: f.SHA256, Object: f.Object})
		keyFiles = append(keyFiles, backup.TaskFile{Name: f.Name, Size: f.SizeBytes, SHA256: f.SHA256, BaseSHA256: f.BaseSHA256})
	}
	if err := backup.ValidateTemplatePublication(*req.TemplateRuntime, files); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	if backup.GenerationKey(keyFiles) != req.Generation {
		respondErrorMsg(c, "bad_request", "generation does not match manifest", http.StatusBadRequest)
		return
	}
	manifest, err := backup.TemplateObject(req.TemplateID, req.BuildID, req.Generation, backup.ManifestObject)
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	data, _ := json.Marshal(files)
	runtime, _ := json.Marshal(req.TemplateRuntime)
	ok, err := h.DB.RecordBuildPublication(ctx, id, a.HostID, req.Bucket, req.Generation, manifest, data, runtime, req.CompletedAt)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusOK, gin.H{"recorded": ok, "publication_recorded": ok})
}
