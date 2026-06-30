package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/authz"
)

// Keep support sandbox access explicit and read-only. This intentionally uses
// the existing platform:teams:read permission so Phase 4 can ship without a
// schema/seed migration. If you want a narrower grant later, add and seed
// platform:sandboxes:read, then change this constant.
const platformSandboxReadPermission = "platform:teams:read"

type platformSandboxResponse struct {
	ID             string          `json:"id"`
	TeamID         string          `json:"team_id"`
	Name           string          `json:"name"`
	Status         string          `json:"status"`
	VCPUCount      int64           `json:"vcpu_count"`
	MemoryMiB      int64           `json:"memory_mib"`
	SnapshotID     *string         `json:"snapshot_id,omitempty"`
	TimeoutSeconds *int64          `json:"timeout_seconds,omitempty"`
	Network        json.RawMessage `json:"network"`
	Metadata       json.RawMessage `json:"metadata"`
	CreatedAt      time.Time       `json:"created_at"`
}

func rawJSON(raw []byte) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage(`{}`)
	}
	return json.RawMessage(raw)
}

func uuidPGPtrString(id pgtype.UUID) *string {
	if !id.Valid {
		return nil
	}
	s := uuid.UUID(id.Bytes).String()
	return &s
}

func nullIntPtr(v sql.NullInt64) *int64 {
	if !v.Valid {
		return nil
	}
	return &v.Int64
}

func (h *Handlers) requirePlatformSandboxRead(c *gin.Context, teamID uuid.UUID) (uuid.UUID, bool) {
	actorID, err := internalActorID(c)
	if err != nil {
		return uuid.Nil, false
	}
	if err := h.requirePlatformAdminGoogleSession(c.Request.Context(), h.Pool, actorID); err != nil {
		if errors.Is(err, authz.ErrSessionNotEligible) || errors.Is(err, pgx.ErrNoRows) {
			respondError(c, ErrForbidden)
			return uuid.Nil, false
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("platform sandbox read session validation failed")
		respondError(c, ErrInternal)
		return uuid.Nil, false
	}
	svc := h.rbacService()
	if svc == nil {
		respondError(c, ErrInternal)
		return uuid.Nil, false
	}
	if err := svc.RequirePlatformPermission(c.Request.Context(), actorID, platformSandboxReadPermission); err != nil {
		if errors.Is(err, authz.ErrPermissionDenied) || errors.Is(err, authz.ErrScopeMismatch) {
			respondError(c, ErrForbidden)
			return uuid.Nil, false
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("platform sandbox read authorization failed")
		respondError(c, ErrInternal)
		return uuid.Nil, false
	}
	return actorID, true
}

func scanPlatformSandbox(scan func(dest ...any) error) (platformSandboxResponse, error) {
	var row platformSandboxResponse
	var id, teamID uuid.UUID
	var snapshotID pgtype.UUID
	var timeoutSeconds sql.NullInt64
	var networkRaw, metadataRaw []byte
	if err := scan(
		&id,
		&teamID,
		&row.Name,
		&row.Status,
		&row.VCPUCount,
		&row.MemoryMiB,
		&snapshotID,
		&timeoutSeconds,
		&networkRaw,
		&metadataRaw,
		&row.CreatedAt,
	); err != nil {
		return platformSandboxResponse{}, err
	}
	row.ID = id.String()
	row.TeamID = teamID.String()
	row.SnapshotID = uuidPGPtrString(snapshotID)
	row.TimeoutSeconds = nullIntPtr(timeoutSeconds)
	row.Network = rawJSON(networkRaw)
	row.Metadata = rawJSON(metadataRaw)
	return row, nil
}

func (h *Handlers) ListPlatformTeamSandboxes(c *gin.Context) {
	teamID, err := internalTeamID(c)
	if err != nil {
		return
	}
	if _, ok := h.requirePlatformSandboxRead(c, teamID); !ok {
		return
	}
	if h.Pool == nil {
		respondError(c, ErrInternal)
		return
	}

	rows, err := h.Pool.Query(c.Request.Context(), `
		SELECT id, team_id, name, status, vcpu_count, memory_mib,
		       snapshot_id, timeout_seconds,
		       COALESCE(network_config, '{}'::jsonb),
		       COALESCE(metadata, '{}'::jsonb),
		       created_at
		FROM sandbox
		WHERE team_id = $1
		ORDER BY created_at DESC
		LIMIT 500
	`, teamID)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("platform sandbox list query failed")
		respondError(c, ErrInternal)
		return
	}
	defer rows.Close()

	out := make([]platformSandboxResponse, 0)
	for rows.Next() {
		row, err := scanPlatformSandbox(rows.Scan)
		if err != nil {
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("platform sandbox list scan failed")
			respondError(c, ErrInternal)
			return
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("platform sandbox list rows failed")
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusOK, out)
}

func (h *Handlers) GetPlatformTeamSandbox(c *gin.Context) {
	teamID, err := internalTeamID(c)
	if err != nil {
		return
	}
	if _, ok := h.requirePlatformSandboxRead(c, teamID); !ok {
		return
	}
	sandboxID, err := parseUUIDParam(c, "sandbox_id")
	if err != nil {
		return
	}
	if h.Pool == nil {
		respondError(c, ErrInternal)
		return
	}

	row, err := scanPlatformSandbox(func(dest ...any) error {
		return h.Pool.QueryRow(c.Request.Context(), `
			SELECT id, team_id, name, status, vcpu_count, memory_mib,
			       snapshot_id, timeout_seconds,
			       COALESCE(network_config, '{}'::jsonb),
			       COALESCE(metadata, '{}'::jsonb),
			       created_at
			FROM sandbox
			WHERE team_id = $1
			  AND id = $2
			LIMIT 1
		`, teamID, sandboxID).Scan(dest...)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "not_found", "sandbox not found", http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Str("sandbox_id", sandboxID.String()).Msg("platform sandbox get query failed")
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusOK, row)
}
