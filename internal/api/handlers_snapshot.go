package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

const snapshotsFeatureKey = "sandbox_snapshots_v1"

const savedSnapshotVMDTimeout = 2 * time.Minute

const savedSnapshotMetadataReserve = int64(64 << 20)

type createSnapshotRequest struct {
	Name *string `json:"name,omitempty"`
}

// UnmarshalJSON keeps the wire contract unambiguous: omission means an
// unnamed snapshot, while JSON null is not a second spelling for omission.
// The custom decoder is deliberately tiny because this request has one field;
// it also preserves strict unknown-field rejection when invoked by encoding/json.
func (r *createSnapshotRequest) UnmarshalJSON(data []byte) error {
	if strings.TrimSpace(string(data)) == "null" {
		return errors.New("snapshot request body must be an object")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for field := range raw {
		if field != "name" {
			return fmt.Errorf("unknown field %q", field)
		}
	}
	value, present := raw["name"]
	if !present {
		r.Name = nil
		return nil
	}
	if strings.TrimSpace(string(value)) == "null" {
		return errors.New("name must not be null")
	}
	var name string
	if err := json.Unmarshal(value, &name); err != nil {
		return fmt.Errorf("name must be a string: %w", err)
	}
	r.Name = &name
	return nil
}

// savedSnapshotSecretBinding is the durable, non-secret identity of one
// snapshot-time binding. A fork resolves SecretID again and mints a new proxy
// token/JWT; source tokens and cleartext are never stored in the snapshot.
type savedSnapshotSecretBinding struct {
	EnvKey     string    `json:"env_key"`
	SecretID   uuid.UUID `json:"secret_id"`
	SecretName string    `json:"secret_name"`
}

type snapshotResponse struct {
	ID                 uuid.UUID  `json:"id"`
	Name               *string    `json:"name,omitempty"`
	Status             string     `json:"status"`
	SandboxID          string     `json:"sandbox_id"`
	ParentSnapshotID   *uuid.UUID `json:"parent_snapshot_id,omitempty"`
	VcpuCount          int32      `json:"vcpu_count"`
	MemoryMib          int32      `json:"memory_mib"`
	DiskMib            int32      `json:"disk_mib"`
	LogicalSizeBytes   int64      `json:"logical_size_bytes"`
	ExclusiveSizeBytes int64      `json:"exclusive_size_bytes"`
	ChildSandboxCount  int64      `json:"child_sandbox_count"`
	ChildSnapshotCount int64      `json:"child_snapshot_count"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

type snapshotArtifactMetadata struct {
	SchemaVersion            uint32 `json:"schema_version"`
	MemoryBasePath           string `json:"memory_base_path,omitempty"`
	DiskBasePath             string `json:"disk_base_path,omitempty"`
	DiskDeltaPath            string `json:"disk_delta_path,omitempty"`
	DiskOverlayPath          string `json:"disk_overlay_path,omitempty"`
	DiskFullPath             string `json:"disk_full_path,omitempty"`
	SourceLogicalSizeBytes   int64  `json:"source_logical_size_bytes"`
	SourceExclusiveSizeBytes int64  `json:"source_exclusive_size_bytes"`
}

type snapshotVMDClient interface {
	vmdclient.Client
	vmdclient.SavedSnapshotClient
}

func snapshotToResponse(s db.Snapshot, deps db.GetSavedSnapshotDependencyCountsRow) snapshotResponse {
	resp := snapshotResponse{
		ID:                 s.ID,
		Name:               s.Name,
		Status:             string(s.Status),
		SandboxID:          formatSandboxID(s.SandboxID),
		LogicalSizeBytes:   s.LogicalSizeBytes,
		ExclusiveSizeBytes: s.ExclusiveSizeBytes,
		ChildSandboxCount:  deps.ChildSandboxCount,
		ChildSnapshotCount: deps.ChildSnapshotCount,
		CreatedAt:          s.CreatedAt,
		UpdatedAt:          s.UpdatedAt,
	}
	if s.ParentSnapshotID.Valid {
		id := uuid.UUID(s.ParentSnapshotID.Bytes)
		resp.ParentSnapshotID = &id
	}
	if s.VcpuCount != nil {
		resp.VcpuCount = *s.VcpuCount
	}
	if s.MemoryMib != nil {
		resp.MemoryMib = *s.MemoryMib
	}
	if s.DiskMib != nil {
		resp.DiskMib = *s.DiskMib
	}
	return resp
}

func savedSnapshotHostID(snapshot db.Snapshot) string {
	if snapshot.HostID == nil {
		return ""
	}
	return *snapshot.HostID
}

func validateSnapshotName(name *string) error {
	if name == nil {
		return nil
	}
	if n := utf8.RuneCountInString(*name); n < 1 || n > 64 {
		return fmt.Errorf("name must be 1-64 characters")
	}
	return nil
}

func parseSnapshotID(c *gin.Context) (uuid.UUID, error) {
	raw := strings.TrimSpace(c.Param("snapshot_id"))
	id, err := uuid.Parse(raw)
	if err != nil {
		respondErrorMsg(c, "bad_request",
			fmt.Sprintf("Invalid snapshot_id: %q is not a valid snapshot ID", raw),
			http.StatusBadRequest)
		return uuid.Nil, err
	}
	return id, nil
}

func parseFromSnapshotID(raw string) (uuid.UUID, *AppError) {
	id, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil {
		return uuid.Nil, NewAppError("bad_request", "from_snapshot is not a valid snapshot ID", http.StatusBadRequest)
	}
	return id, nil
}

// requireSnapshotsFeature is intentionally team-scoped. A global default can
// remain off while selected pilot teams receive an explicit override.
func (h *Handlers) requireSnapshotsFeature(c *gin.Context, teamID uuid.UUID) bool {
	enabled, err := h.DB.IsFeatureEnabledForTeam(c.Request.Context(), db.IsFeatureEnabledForTeamParams{
		Key:    snapshotsFeatureKey,
		TeamID: pgtype.UUID{Bytes: teamID, Valid: true},
	})
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("DB snapshot feature check failed")
		respondError(c, ErrInternal)
		return false
	}
	if !enabled {
		respondErrorMsg(c, "feature_disabled", "Saved snapshots are not enabled for this team", http.StatusForbidden)
		return false
	}
	return true
}

// snapshotVMDForHost deliberately does not use vmdForHost's legacy
// unknown-host fallback. Saved artifacts are host-local in V1; routing a fork
// to the default host could restore an unrelated path or misreport corruption.
func (h *Handlers) snapshotVMDForHost(c *gin.Context, hostID string, requireActive bool) (snapshotVMDClient, bool) {
	var base vmdclient.Client
	var err error
	if h.Hosts == nil {
		base = h.VMD
	} else if activeHosts, ok := h.Hosts.(activeHostRegistry); requireActive && ok {
		base, err = activeHosts.ActiveClientFor(c.Request.Context(), hostID)
	} else {
		base, err = h.Hosts.ClientFor(c.Request.Context(), hostID)
	}
	if err != nil || base == nil {
		log.Warn().Err(vmdclient.SanitizeSavedSnapshotError(vmdclient.SavedSnapshotOperationHostResolution, err)).Str("host_id", hostID).Msg("saved snapshot host unavailable")
		c.Header("Retry-After", "5")
		respondErrorMsg(c, "snapshot_host_unavailable", "The snapshot host is temporarily unavailable", http.StatusServiceUnavailable)
		return nil, false
	}
	client, ok := base.(snapshotVMDClient)
	if !ok {
		log.Warn().Str("host_id", hostID).Msg("VMD does not support immutable saved snapshots")
		c.Header("Retry-After", "5")
		respondErrorMsg(c, "snapshot_host_unavailable", "The snapshot host does not yet support saved snapshots", http.StatusServiceUnavailable)
		return nil, false
	}
	// Creation and restore require the complete writer/loader capability. Host
	// cleanup deliberately does not: rolling back a writer prerequisite must
	// never strand already-committed artifacts that the delete RPC can remove.
	if requireActive {
		capabilityCtx, cancel := context.WithTimeout(c.Request.Context(), vmdTimeout)
		err = client.CheckSavedSnapshotSupport(capabilityCtx)
		cancel()
		if err != nil {
			log.Warn().Err(vmdclient.SanitizeSavedSnapshotError(vmdclient.SavedSnapshotOperationCapabilityCheck, err)).Str("host_id", hostID).Msg("saved snapshot capability check failed")
			c.Header("Retry-After", "5")
			respondErrorMsg(c, "snapshot_host_unavailable", "The snapshot host does not yet support saved snapshots", http.StatusServiceUnavailable)
			return nil, false
		}
	}
	return client, true
}

func decodeSavedSnapshotBindings(raw []byte) ([]savedSnapshotSecretBinding, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var out []savedSnapshotSecretBinding
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode snapshot secret bindings: %w", err)
	}
	return out, nil
}

func decodeSavedSnapshotSecretEnvKeys(raw []byte) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var keys []string
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, fmt.Errorf("decode snapshot secret env-key history: %w", err)
	}
	if len(keys) > 256 {
		return nil, errors.New("snapshot secret env-key history exceeds 256 keys")
	}
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if !envKeyRE.MatchString(key) {
			return nil, fmt.Errorf("snapshot secret env-key history contains invalid key %q", key)
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("snapshot secret env-key history contains duplicate key %q", key)
		}
		seen[key] = struct{}{}
	}
	return keys, nil
}

// resolveSavedSnapshotBindingsForCreate resolves captured stable secret IDs
// against the team's current, non-revoked secret rows and mints fresh child
// proxy tokens. Missing/revoked credentials fail the whole fork; silently
// dropping one would turn a reproducible snapshot into a partially configured
// sandbox. Callers can deliberately replace all bindings with `secrets: {}`.
func (h *Handlers) resolveSavedSnapshotBindingsForCreate(
	ctx context.Context,
	teamID uuid.UUID,
	captured []savedSnapshotSecretBinding,
) (bindings []db.AddSandboxSecretParams, meta []SecretBindingMeta, appErr *AppError) {
	if len(captured) == 0 {
		return nil, nil, nil
	}
	bindings = make([]db.AddSandboxSecretParams, 0, len(captured))
	meta = make([]SecretBindingMeta, 0, len(captured))
	unavailable := make([]string, 0)
	seenEnv := make(map[string]struct{}, len(captured))
	for _, capturedBinding := range captured {
		if _, duplicate := seenEnv[capturedBinding.EnvKey]; duplicate {
			log.Error().Str("env_key", capturedBinding.EnvKey).Msg("duplicate env key in saved snapshot secret manifest")
			return nil, nil, ErrInternal
		}
		seenEnv[capturedBinding.EnvKey] = struct{}{}

		row, err := h.DB.GetSecretByID(ctx, db.GetSecretByIDParams{
			ID: capturedBinding.SecretID, TeamID: teamID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			unavailable = append(unavailable, capturedBinding.EnvKey)
			continue
		}
		if err != nil {
			log.Error().Err(err).Str("secret_id", capturedBinding.SecretID.String()).Msg("DB GetSecretByID during snapshot fork")
			return nil, nil, ErrInternal
		}
		token, err := mintProxyToken(row.ProviderShortcut)
		if err != nil {
			log.Error().Err(err).Str("secret_id", row.ID.String()).Msg("mint proxy token during snapshot fork")
			return nil, nil, ErrInternal
		}
		bindings = append(bindings, db.AddSandboxSecretParams{
			SecretID: row.ID,
			EnvKey:   capturedBinding.EnvKey,
		})
		meta = append(meta, SecretBindingMeta{
			SecretID:         row.ID,
			EnvKey:           capturedBinding.EnvKey,
			AuthType:         row.AuthType,
			AuthConfig:       row.AuthConfig,
			ProviderShortcut: row.ProviderShortcut,
			Hosts:            row.Hosts,
			ProxyToken:       token,
		})
	}
	if len(unavailable) > 0 {
		sort.Strings(unavailable)
		return nil, nil, NewAppError(
			"snapshot_secret_unavailable",
			fmt.Sprintf("Captured secret bindings are unavailable for env keys: %s; supply a complete secrets replacement to continue", strings.Join(unavailable, ", ")),
			http.StatusConflict,
		)
	}
	return bindings, meta, nil
}

func savedSnapshotNetworkFromJSON(raw []byte) (vmdclient.SavedSnapshotNetwork, error) {
	if len(raw) == 0 {
		return vmdclient.SavedSnapshotNetwork{}, nil
	}
	var cfg persistedEgressConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return vmdclient.SavedSnapshotNetwork{}, fmt.Errorf("decode snapshot network policy: %w", err)
	}
	return vmdclient.SavedSnapshotNetwork{
		AllowedCIDRs:   cfg.Egress.AllowedCIDRs,
		DeniedCIDRs:    cfg.Egress.DeniedCIDRs,
		AllowedDomains: cfg.Egress.AllowedDomains,
	}, nil
}

func savedSnapshotNetworkFromRequest(req *networkConfigRequest) (vmdclient.SavedSnapshotNetwork, []byte) {
	if req == nil {
		return vmdclient.SavedSnapshotNetwork{}, nil
	}
	allowedCIDRs, allowedDomains, raw := egressConfigJSON(req)
	return vmdclient.SavedSnapshotNetwork{
		AllowedCIDRs:   allowedCIDRs,
		DeniedCIDRs:    req.DenyOut,
		AllowedDomains: allowedDomains,
	}, raw
}

func (h *Handlers) CreateSnapshot(c *gin.Context) {
	sandboxID, err := parseSandboxID(c)
	if err != nil {
		return
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSandboxWrite(c, teamID) || !h.requireSnapshotsFeature(c, teamID) {
		return
	}

	var req createSnapshotRequest
	if c.Request.Body != nil {
		if err := bindJSONStrict(c, &req); err != nil && !errors.Is(err, io.EOF) {
			respondErrorMsg(c, "bad_request", "Request body is not valid JSON or contains unknown fields.", http.StatusBadRequest)
			return
		}
	}
	if err := validateSnapshotName(req.Name); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}

	idempotencyKey, appErr := snapshotIdempotencyKey(c)
	if appErr != nil {
		respondError(c, appErr)
		return
	}

	source, err := h.DB.GetSandbox(c.Request.Context(), db.GetSandboxParams{ID: sandboxID, TeamID: teamID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondError(c, ErrSandboxNotFound)
			return
		}
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB GetSandbox for saved snapshot")
		respondError(c, ErrInternal)
		return
	}

	var saved db.Snapshot
	if idempotencyKey != nil {
		saved, err = h.DB.GetSavedSnapshotByIdempotencyKey(c.Request.Context(), db.GetSavedSnapshotByIdempotencyKeyParams{
			TeamID: teamID, SandboxID: sandboxID, IdempotencyKey: *idempotencyKey,
		})
		if err == nil {
			if h.respondForExistingSnapshotCreate(c, saved) {
				return
			}
			// A creating row is an adoptable retry only while it still owns the
			// source operation claim. Refresh the source because a concurrent
			// request may have committed the intent after our first source read.
			currentSource, claimOwned, sourceErr := h.savedSnapshotCreateClaimOwner(c.Request.Context(), teamID, sandboxID, saved.ID)
			if sourceErr != nil {
				if errors.Is(sourceErr, pgx.ErrNoRows) {
					respondErrorMsg(c, "snapshot_not_ready", "Snapshot capture is awaiting reconciliation", http.StatusConflict)
					return
				}
				log.Error().Err(sourceErr).Str("sandbox_id", sandboxID.String()).Msg("DB refresh source for idempotent saved snapshot")
				respondError(c, ErrInternal)
				return
			}
			if !claimOwned {
				respondErrorMsg(c, "snapshot_not_ready", "Snapshot capture is awaiting reconciliation", http.StatusConflict)
				return
			}
			source = currentSource
		} else if !errors.Is(err, pgx.ErrNoRows) {
			log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB idempotent saved snapshot lookup")
			respondError(c, ErrInternal)
			return
		}
	}

	if saved.ID == uuid.Nil && ((source.Status != db.SandboxStatusActive && source.Status != db.SandboxStatusPaused) || source.SnapshotOperationID.Valid) {
		respondErrorMsg(c, "snapshot_source_state_invalid", "Sandbox must be active or paused and have no lifecycle operation in progress", http.StatusConflict)
		return
	}

	// Exact allocated bytes are only known after VMD captures sparse artifacts.
	// Reserve the maximum memory+disk footprint before any host work so a team
	// that cannot possibly admit the result fails without producing artifacts.
	// Finalization still enforces VMD's authoritative allocated-byte result.
	if saved.ID == uuid.Nil {
		usage, usageErr := h.DB.GetSavedSnapshotQuotaUsage(c.Request.Context(), teamID)
		if usageErr != nil {
			log.Error().Err(usageErr).Str("team_id", teamID.String()).Msg("DB GetSavedSnapshotQuotaUsage preflight")
			respondError(c, ErrInternal)
			return
		}
		required := savedSnapshotWorstCaseExclusiveBytes(source.MemoryMib, source.DiskMib)
		if usage.SnapshotStorageQuotaBytes == nil ||
			required > *usage.SnapshotStorageQuotaBytes ||
			usage.SnapshotStorageBytes > *usage.SnapshotStorageQuotaBytes-required {
			h.respondSavedSnapshotQuota(c, teamID, sandboxID, "snapshot_storage_quota_exceeded")
			return
		}
	}

	hostID := source.HostID
	if saved.ID != uuid.Nil {
		if saved.HostID == nil || *saved.HostID == "" {
			log.Error().Str("snapshot_id", saved.ID.String()).Msg("creating saved snapshot has no host")
			respondError(c, ErrInternal)
			return
		}
		hostID = *saved.HostID
	}
	if hostID == "" {
		log.Error().Str("sandbox_id", sandboxID.String()).Msg("snapshot source sandbox has no host")
		respondError(c, ErrInternal)
		return
	}
	SetTelemetryHostID(c, hostID)
	vmd, ok := h.snapshotVMDForHost(c, hostID, true)
	if !ok {
		return
	}

	if saved.ID == uuid.Nil {
		saved, err = h.beginSavedSnapshot(c.Request.Context(), db.BeginSavedSnapshotParams{
			SnapshotID:     uuid.New(),
			Trigger:        "api",
			Name:           req.Name,
			IdempotencyKey: idempotencyKey,
			SandboxID:      sandboxID,
			TeamID:         teamID,
		})
		if err != nil {
			// Two same-key requests can both miss the initial lookup. The loser may
			// observe either a uniqueness violation or zero rows after waiting for
			// the winner's source claim. In both cases, re-read and adopt the winner.
			if idempotencyKey != nil && (isUniqueViolation(err) || errors.Is(err, pgx.ErrNoRows)) {
				existing, lookupErr := h.DB.GetSavedSnapshotByIdempotencyKey(c.Request.Context(), db.GetSavedSnapshotByIdempotencyKeyParams{
					TeamID: teamID, SandboxID: sandboxID, IdempotencyKey: *idempotencyKey,
				})
				if lookupErr == nil {
					if h.respondForExistingSnapshotCreate(c, existing) {
						return
					}
					currentSource, claimOwned, sourceErr := h.savedSnapshotCreateClaimOwner(c.Request.Context(), teamID, sandboxID, existing.ID)
					if sourceErr != nil {
						if errors.Is(sourceErr, pgx.ErrNoRows) {
							respondErrorMsg(c, "snapshot_not_ready", "Snapshot capture is awaiting reconciliation", http.StatusConflict)
							return
						}
						log.Error().Err(sourceErr).Str("sandbox_id", sandboxID.String()).Msg("DB refresh source after saved snapshot admission race")
						respondError(c, ErrInternal)
						return
					}
					if !claimOwned {
						respondErrorMsg(c, "snapshot_not_ready", "Snapshot capture is awaiting reconciliation", http.StatusConflict)
						return
					}
					source = currentSource
					saved = existing
					err = nil
				} else if !errors.Is(lookupErr, pgx.ErrNoRows) {
					err = lookupErr
				}
			}
			if err != nil {
				if quotaCode := savedSnapshotQuotaCode(err); quotaCode != "" {
					h.respondSavedSnapshotQuota(c, teamID, sandboxID, quotaCode)
					return
				}
				if errors.Is(err, pgx.ErrNoRows) {
					respondErrorMsg(c, "snapshot_source_state_invalid", "Sandbox state changed before snapshot capture could start", http.StatusConflict)
					return
				}
				log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB BeginSavedSnapshot")
				respondError(c, ErrInternal)
				return
			}
		}
	}

	if saved.HostID == nil || *saved.HostID == "" {
		log.Error().Str("snapshot_id", saved.ID.String()).Msg("creating saved snapshot has no host")
		h.failSavedSnapshot(c.Request.Context(), saved.ID, teamID, "source_host_missing")
		respondError(c, ErrInternal)
		return
	}
	if *saved.HostID != hostID {
		log.Error().Str("snapshot_id", saved.ID.String()).Str("source_host", hostID).Str("saved_host", *saved.HostID).Msg("saved snapshot host changed during admission")
		h.failSavedSnapshot(c.Request.Context(), saved.ID, teamID, "source_host_changed")
		respondError(c, ErrInternal)
		return
	}

	vmdCtx, cancel := context.WithTimeout(c.Request.Context(), savedSnapshotVMDTimeout)
	artifacts, err := vmd.CreateSavedSnapshot(vmdCtx, sandboxID.String(), saved.ID.String())
	cancel()
	if err != nil {
		h.respondSavedSnapshotCaptureError(c, saved, vmd, err)
		return
	}
	artifactJSON, err := json.Marshal(snapshotArtifactMetadata{
		SchemaVersion:            artifacts.SchemaVersion,
		MemoryBasePath:           artifacts.MemoryBasePath,
		DiskBasePath:             artifacts.DiskBasePath,
		DiskDeltaPath:            artifacts.DiskDeltaPath,
		DiskOverlayPath:          artifacts.DiskOverlayPath,
		DiskFullPath:             artifacts.DiskFullPath,
		SourceLogicalSizeBytes:   artifacts.SourceLogicalSizeBytes,
		SourceExclusiveSizeBytes: artifacts.SourceExclusiveSizeBytes,
	})
	if err != nil {
		log.Error().Err(err).Str("snapshot_id", saved.ID.String()).Msg("marshal saved snapshot artifact metadata")
		respondError(c, ErrInternal)
		return
	}
	if err := validateSavedSnapshotArtifacts(saved, artifacts); err != nil {
		log.Error().Err(err).Str("snapshot_id", saved.ID.String()).Msg("VMD returned invalid saved snapshot manifest")
		h.capture(c, "snapshot_artifact_corrupt", map[string]any{
			"snapshot_id": saved.ID.String(),
			"sandbox_id":  saved.SandboxID.String(),
			"phase":       "capture",
		})
		if cleanupErr := h.deleteCapturedSnapshotBestEffort(c.Request.Context(), vmd, saved); cleanupErr == nil {
			h.failSavedSnapshot(c.Request.Context(), saved.ID, teamID, "artifact_validation_failed")
		} else if queueErr := h.queueSavedSnapshotCleanup(c.Request.Context(), saved, artifacts, artifactJSON, "artifact_validation_failed"); queueErr != nil {
			// Keep the creating intent and its source claim intact. The stale
			// capture reconciler can rediscover the idempotent host artifact and
			// retry cleanup without losing its durable owner.
			log.Error().Err(queueErr).Str("snapshot_id", saved.ID.String()).Msg("queue invalid saved snapshot artifact cleanup")
		}
		respondErrorMsg(c, "snapshot_chain_invalid", "Snapshot artifacts failed integrity validation", http.StatusInternalServerError)
		return
	}
	finalized, err := h.DB.FinalizeSavedSnapshot(c.Request.Context(), db.FinalizeSavedSnapshotParams{
		Path:               artifacts.SnapshotPath,
		MemPath:            artifacts.MemPath,
		LogicalSizeBytes:   artifacts.LogicalSizeBytes,
		ManifestPath:       artifacts.ManifestPath,
		ManifestDigest:     &artifacts.ManifestDigest,
		ArtifactMetadata:   artifactJSON,
		ExclusiveSizeBytes: artifacts.ExclusiveSizeBytes,
		SnapshotID:         saved.ID,
		TeamID:             teamID,
	})
	if err != nil {
		if quotaCode := savedSnapshotQuotaCode(err); quotaCode != "" {
			if cleanupErr := h.deleteCapturedSnapshotBestEffort(c.Request.Context(), vmd, saved); cleanupErr == nil {
				h.failSavedSnapshot(c.Request.Context(), saved.ID, teamID, quotaCode)
			} else if queueErr := h.queueSavedSnapshotCleanup(c.Request.Context(), saved, artifacts, artifactJSON, quotaCode); queueErr != nil {
				log.Error().Err(queueErr).Str("snapshot_id", saved.ID.String()).Msg("queue over-quota saved snapshot artifact cleanup")
			}
			h.respondSavedSnapshotQuota(c, teamID, sandboxID, quotaCode)
			return
		}
		// A concurrent idempotent retry may have finalized first.
		if errors.Is(err, pgx.ErrNoRows) {
			current, getErr := h.DB.GetSavedSnapshot(c.Request.Context(), db.GetSavedSnapshotParams{SnapshotID: saved.ID, TeamID: teamID})
			if getErr == nil {
				switch current.Status {
				case db.SnapshotStatusReady:
					h.respondSnapshotCreated(c, current)
					return
				case db.SnapshotStatusUnavailable:
					// This is a committed artifact set. A concurrent health
					// check won the race, so never treat our idempotent VMD
					// response as an orphan and delete it.
					respondErrorMsg(c, "snapshot_unavailable", "Snapshot artifacts are unavailable", http.StatusGone)
					return
				case db.SnapshotStatusCreating:
					if cleanupErr := h.deleteCapturedSnapshotBestEffort(c.Request.Context(), vmd, saved); cleanupErr == nil {
						h.failSavedSnapshot(c.Request.Context(), saved.ID, teamID, "capture_commit_lost")
					} else if queueErr := h.queueSavedSnapshotCleanup(c.Request.Context(), saved, artifacts, artifactJSON, "capture_commit_lost"); queueErr != nil {
						log.Error().Err(queueErr).Str("snapshot_id", saved.ID.String()).Msg("queue uncommitted saved snapshot artifact cleanup")
					}
				case db.SnapshotStatusDeleting:
					if cleanupErr := h.deleteCapturedSnapshotBestEffort(c.Request.Context(), vmd, saved); cleanupErr == nil {
						if _, finalizeErr := h.DB.FinalizeSavedSnapshotDelete(context.WithoutCancel(c.Request.Context()), db.FinalizeSavedSnapshotDeleteParams{SnapshotID: saved.ID, TeamID: teamID}); finalizeErr != nil && !errors.Is(finalizeErr, pgx.ErrNoRows) {
							log.Error().Err(finalizeErr).Str("snapshot_id", saved.ID.String()).Msg("finalize concurrently cancelled saved snapshot")
						}
					}
				case db.SnapshotStatusFailed:
					_ = h.deleteCapturedSnapshotBestEffort(c.Request.Context(), vmd, saved)
				}
				respondErrorMsg(c, "snapshot_not_ready", "Snapshot capture was concurrently cancelled or failed", http.StatusConflict)
				return
			}
			if errors.Is(getErr, pgx.ErrNoRows) {
				_ = h.deleteCapturedSnapshotBestEffort(c.Request.Context(), vmd, saved)
				respondErrorMsg(c, "snapshot_not_ready", "Snapshot capture was concurrently deleted", http.StatusConflict)
				return
			}
		}
		// Leave the durable artifact + creating intent for reconciliation. Do
		// not downgrade it to failed merely because the DB finalize write had
		// a transient outage.
		log.Error().Err(err).Str("snapshot_id", saved.ID.String()).Msg("DB FinalizeSavedSnapshot")
		respondError(c, ErrInternal)
		return
	}

	current, err := h.DB.GetSavedSnapshot(c.Request.Context(), db.GetSavedSnapshotParams{SnapshotID: finalized.ID, TeamID: teamID})
	if err != nil {
		log.Error().Err(err).Str("snapshot_id", finalized.ID.String()).Msg("DB read finalized saved snapshot")
		respondError(c, ErrInternal)
		return
	}
	h.respondSnapshotCreated(c, current)
	h.capture(c, "snapshot_created", map[string]any{"snapshot_id": current.ID.String(), "sandbox_id": sandboxID.String()})
}

func savedSnapshotWorstCaseExclusiveBytes(memoryMiB, diskMiB int32) int64 {
	if memoryMiB < 0 || diskMiB < 0 {
		return math.MaxInt64
	}
	const mib = int64(1 << 20)
	shapeMiB := int64(memoryMiB) + int64(diskMiB)
	if shapeMiB > (math.MaxInt64-savedSnapshotMetadataReserve)/mib {
		return math.MaxInt64
	}
	return shapeMiB*mib + savedSnapshotMetadataReserve
}

func snapshotIdempotencyKey(c *gin.Context) (*string, *AppError) {
	values := c.Request.Header.Values("Idempotency-Key")
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) != 1 || values[0] == "" || utf8.RuneCountInString(values[0]) > 255 {
		return nil, NewAppError("bad_request", "Idempotency-Key must be a single non-empty value of at most 255 characters", http.StatusBadRequest)
	}
	return &values[0], nil
}

func (h *Handlers) beginSavedSnapshot(ctx context.Context, params db.BeginSavedSnapshotParams) (db.Snapshot, error) {
	if h.Pool == nil {
		return h.DB.BeginSavedSnapshot(ctx, params)
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return db.Snapshot{}, err
	}
	defer tx.Rollback(ctx)
	q := h.DB.WithTx(tx)
	// These must be the first locks in saved-snapshot admission, in global ->
	// team order. The global fence covers a capture whose system template is
	// owned by another team being migrated; the team fence covers the source
	// team's own migration. Trying both before the sandbox-secret advisory lock
	// avoids waiting behind migrate-team while holding host/sandbox/team rows.
	// BeginSavedSnapshot repeats this ordered gate for non-Pool/direct callers.
	admitted, err := q.TryAcquireSavedSnapshotGlobalMigrationFence(ctx)
	if err != nil {
		return db.Snapshot{}, err
	}
	if !admitted {
		return db.Snapshot{}, pgx.ErrNoRows
	}
	admitted, err = q.TryAcquireSavedSnapshotTeamMigrationFence(ctx, params.TeamID)
	if err != nil {
		return db.Snapshot{}, err
	}
	if !admitted {
		return db.Snapshot{}, pgx.ErrNoRows
	}
	if err := q.LockSandboxForSecretWrites(ctx, params.SandboxID.String()); err != nil {
		return db.Snapshot{}, err
	}
	snapshot, err := q.BeginSavedSnapshot(ctx, params)
	if err != nil {
		return db.Snapshot{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return db.Snapshot{}, err
	}
	return snapshot, nil
}

func (h *Handlers) savedSnapshotCreateClaimOwner(ctx context.Context, teamID, sandboxID, snapshotID uuid.UUID) (db.Sandbox, bool, error) {
	source, err := h.DB.GetSandbox(ctx, db.GetSandboxParams{ID: sandboxID, TeamID: teamID})
	if err != nil {
		return db.Sandbox{}, false, err
	}
	owned := source.SnapshotOperationID.Valid && uuid.UUID(source.SnapshotOperationID.Bytes) == snapshotID
	return source, owned, nil
}

func (h *Handlers) respondForExistingSnapshotCreate(c *gin.Context, snapshot db.Snapshot) bool {
	switch snapshot.Status {
	case db.SnapshotStatusReady:
		h.respondSnapshotCreated(c, snapshot)
		return true
	case db.SnapshotStatusCreating:
		return false
	case db.SnapshotStatusUnavailable:
		respondErrorMsg(c, "snapshot_unavailable", "The idempotent snapshot exists but its artifacts are unavailable", http.StatusGone)
	case db.SnapshotStatusFailed:
		respondErrorMsg(c, "snapshot_not_ready", "The idempotent snapshot capture previously failed", http.StatusConflict)
	default:
		respondErrorMsg(c, "snapshot_not_ready", "The idempotent snapshot is being deleted", http.StatusConflict)
	}
	return true
}

func validateSavedSnapshotArtifacts(saved db.Snapshot, artifacts vmdclient.SavedSnapshotArtifacts) error {
	if artifacts.SchemaVersion == 0 || artifacts.ManifestPath == "" || artifacts.SnapshotPath == "" || artifacts.MemPath == "" {
		return errors.New("committed artifact paths are incomplete")
	}
	if len(artifacts.ManifestDigest) != 64 {
		return errors.New("manifest digest is missing or malformed")
	}
	if _, err := hex.DecodeString(artifacts.ManifestDigest); err != nil {
		return errors.New("manifest digest is not hex encoded")
	}
	if artifacts.ManifestDigest != strings.ToLower(artifacts.ManifestDigest) {
		return errors.New("manifest digest is not canonical lowercase hex")
	}
	if artifacts.LogicalSizeBytes < 0 || artifacts.ExclusiveSizeBytes < 0 || artifacts.SourceLogicalSizeBytes < 0 || artifacts.SourceExclusiveSizeBytes < 0 {
		return errors.New("artifact sizes must be non-negative")
	}
	if artifacts.DiskDeltaPath == "" && artifacts.DiskOverlayPath == "" && artifacts.DiskFullPath == "" {
		return errors.New("disk artifact is missing")
	}
	if saved.VcpuCount == nil || saved.MemoryMib == nil || saved.DiskMib == nil {
		return errors.New("persisted resource shape is incomplete")
	}
	if artifacts.VCPU != uint32(*saved.VcpuCount) || artifacts.MemoryMiB != uint32(*saved.MemoryMib) || artifacts.DiskMiB != uint32(*saved.DiskMib) {
		return fmt.Errorf("resource shape mismatch")
	}
	expectedState := "running"
	if saved.SourceStatus.Valid && saved.SourceStatus.SandboxStatus == db.SandboxStatusPaused {
		expectedState = "paused"
	}
	if artifacts.SourceState != expectedState {
		return fmt.Errorf("source state mismatch")
	}
	return nil
}

func (h *Handlers) respondSavedSnapshotCaptureError(c *gin.Context, saved db.Snapshot, vmd snapshotVMDClient, err error) {
	if vmdclient.GRPCErrorHasReason(err, vmdclient.SavedSnapshotSourceResumeFailureReason) {
		h.failSavedSnapshotAndSource(c.Request.Context(), saved, vmd, "source_resume_failed")
		respondErrorMsg(c, "snapshot_source_failed", "The source sandbox could not be resumed after capture and was marked failed", http.StatusInternalServerError)
		return
	}
	grpcCode := status.Code(err)
	if grpcCode == codes.NotFound || grpcCode == codes.DataLoss {
		h.capture(c, "snapshot_artifact_corrupt", map[string]any{
			"snapshot_id": saved.ID.String(),
			"sandbox_id":  saved.SandboxID.String(),
			"phase":       "capture",
		})
	}
	switch grpcCode {
	case codes.Canceled, codes.DeadlineExceeded, codes.Unavailable, codes.Aborted, codes.ResourceExhausted, codes.Unimplemented:
		c.Header("Retry-After", "5")
		respondErrorMsg(c, "snapshot_host_unavailable", "Snapshot capture did not complete; retry with the same Idempotency-Key", http.StatusServiceUnavailable)
		return
	case codes.FailedPrecondition:
		if cleanupErr := h.deleteCapturedSnapshotBestEffort(c.Request.Context(), vmd, saved); cleanupErr != nil {
			c.Header("Retry-After", "5")
			respondErrorMsg(c, "snapshot_host_unavailable", "Snapshot cleanup did not complete; retry with the same Idempotency-Key", http.StatusServiceUnavailable)
			return
		}
		h.failSavedSnapshot(c.Request.Context(), saved.ID, saved.TeamID, "source_state_invalid")
		respondErrorMsg(c, "snapshot_source_state_invalid", "The sandbox cannot be captured in its current VM state", http.StatusConflict)
		return
	case codes.NotFound:
		if cleanupErr := h.deleteCapturedSnapshotBestEffort(c.Request.Context(), vmd, saved); cleanupErr != nil {
			c.Header("Retry-After", "5")
			respondErrorMsg(c, "snapshot_host_unavailable", "Snapshot cleanup did not complete; retry with the same Idempotency-Key", http.StatusServiceUnavailable)
			return
		}
		h.failSavedSnapshotAndSource(c.Request.Context(), saved, vmd, "source_artifacts_missing")
		respondErrorMsg(c, "snapshot_artifacts_missing", "The source VM artifacts are missing or corrupt", http.StatusGone)
		return
	case codes.DataLoss:
		if cleanupErr := h.deleteCapturedSnapshotBestEffort(c.Request.Context(), vmd, saved); cleanupErr != nil {
			c.Header("Retry-After", "5")
			respondErrorMsg(c, "snapshot_host_unavailable", "Snapshot cleanup did not complete; retry with the same Idempotency-Key", http.StatusServiceUnavailable)
			return
		}
		if saved.SourceStatus.Valid && saved.SourceStatus.SandboxStatus == db.SandboxStatusPaused {
			h.failSavedSnapshotAndSource(c.Request.Context(), saved, vmd, "source_artifacts_missing")
		} else {
			h.failSavedSnapshot(c.Request.Context(), saved.ID, saved.TeamID, "source_artifacts_missing")
		}
		respondErrorMsg(c, "snapshot_artifacts_missing", "The source VM artifacts are missing or corrupt", http.StatusGone)
		return
	default:
		if cleanupErr := h.deleteCapturedSnapshotBestEffort(c.Request.Context(), vmd, saved); cleanupErr != nil {
			c.Header("Retry-After", "5")
			respondErrorMsg(c, "snapshot_host_unavailable", "Snapshot cleanup did not complete; retry with the same Idempotency-Key", http.StatusServiceUnavailable)
			return
		}
		h.failSavedSnapshot(c.Request.Context(), saved.ID, saved.TeamID, "capture_failed")
		log.Error().Err(vmdclient.SanitizeSavedSnapshotError(vmdclient.SavedSnapshotOperationCapture, err)).Str("snapshot_id", saved.ID.String()).Msg("VMD CreateSavedSnapshot")
		respondError(c, ErrInternal)
	}
}

func (h *Handlers) failSavedSnapshot(reqCtx context.Context, snapshotID, teamID uuid.UUID, reason string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(reqCtx), asyncTimeout)
	defer cancel()
	if _, err := h.DB.FailSavedSnapshot(ctx, db.FailSavedSnapshotParams{
		FailureReason: &reason, SnapshotID: snapshotID, TeamID: teamID,
	}); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		log.Error().Err(err).Str("snapshot_id", snapshotID.String()).Msg("DB FailSavedSnapshot")
	}
}

func (h *Handlers) failSavedSnapshotAndSource(reqCtx context.Context, saved db.Snapshot, vmd snapshotVMDClient, reason string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(reqCtx), asyncTimeout)
	defer cancel()
	expiresAt := time.Now().Add(SecretsJWTLifetime)
	_, transitionErr := h.DB.FailSavedSnapshotAndSource(ctx, db.FailSavedSnapshotAndSourceParams{
		SnapshotID: saved.ID, TeamID: saved.TeamID, RevocationExpiresAt: expiresAt, FailureReason: &reason,
	})
	sourceFailureDurable := transitionErr == nil
	if transitionErr != nil {
		if !errors.Is(transitionErr, pgx.ErrNoRows) {
			log.Error().Err(transitionErr).Str("snapshot_id", saved.ID.String()).Msg("atomically fail saved snapshot and source sandbox")
		}
		// The capture claim may have been concurrently cancelled, or the
		// compound write may have failed ambiguously. Establish revocation on
		// its own before the fallback failure transition. Direct revocation is
		// still attempted below, but host teardown waits for durable DB proof.
		if revokeErr := h.DB.UpsertSandboxRevocation(ctx, db.UpsertSandboxRevocationParams{
			SandboxID: saved.SandboxID, ExpiresAt: expiresAt,
		}); revokeErr != nil {
			log.Error().Err(revokeErr).Str("sandbox_id", saved.SandboxID.String()).Msg("persist saved-snapshot source revocation fallback")
		} else {
			_, fallbackErr := h.DB.FailSavedSnapshotSourceAfterRevocation(ctx, db.FailSavedSnapshotSourceAfterRevocationParams{
				SnapshotID: saved.ID, TeamID: saved.TeamID, FailureReason: &reason,
			})
			if fallbackErr != nil {
				log.Error().Err(fallbackErr).Str("sandbox_id", saved.SandboxID.String()).Msg("fail saved snapshot source after durable revocation")
			} else {
				sourceFailureDurable = true
			}
		}
	}
	h.containFailedSavedSnapshotSource(reqCtx, saved, vmd, sourceFailureDurable)
}

func (h *Handlers) containFailedSavedSnapshotSource(reqCtx context.Context, saved db.Snapshot, vmd snapshotVMDClient, sourceFailureDurable bool) {
	revokeCtx, revokeCancel := context.WithTimeout(context.WithoutCancel(reqCtx), vmdTimeout)
	if err := vmd.RevokeSandbox(revokeCtx, saved.SandboxID.String()); err != nil {
		log.Warn().Err(vmdclient.SanitizeSavedSnapshotError(vmdclient.SavedSnapshotOperationCapture, err)).Str("sandbox_id", saved.SandboxID.String()).Msg("directly revoke failed saved-snapshot source")
	}
	revokeCancel()
	if !sourceFailureDurable {
		// Do not free the source IP until the failed row, interval closures, and
		// credential revocation are durably proven. Otherwise teardown could make
		// an active/billed source disappear without a retryable control-plane fact.
		log.Error().Str("sandbox_id", saved.SandboxID.String()).Msg("retain failed saved-snapshot source because its durable failure transition was not proven")
		return
	}

	destroyCtx, destroyCancel := context.WithTimeout(context.WithoutCancel(reqCtx), vmdTimeout)
	if err := vmd.DestroyInstance(destroyCtx, saved.SandboxID.String(), true); err != nil && !isVMDNotFound(err) {
		// The durable failed row and revocation are the retry intent consumed by
		// the exact-host VM reconciler. Never report this as a healthy source.
		log.Error().Err(vmdclient.SanitizeSavedSnapshotError(vmdclient.SavedSnapshotOperationCapture, err)).Str("sandbox_id", saved.SandboxID.String()).Msg("destroy failed saved-snapshot source; reconciler will retry")
	}
	destroyCancel()
}

func (h *Handlers) deleteCapturedSnapshotBestEffort(reqCtx context.Context, vmd vmdclient.SavedSnapshotClient, saved db.Snapshot) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(reqCtx), vmdTimeout)
	defer cancel()
	if err := vmd.DeleteSavedSnapshot(ctx, saved.SandboxID.String(), saved.ID.String()); err != nil && !isVMDNotFound(err) {
		log.Warn().Err(vmdclient.SanitizeSavedSnapshotError(vmdclient.SavedSnapshotOperationDelete, err)).Str("snapshot_id", saved.ID.String()).Msg("cleanup captured saved snapshot")
		return err
	}
	return nil
}

func (h *Handlers) queueSavedSnapshotCleanup(reqCtx context.Context, saved db.Snapshot, artifacts vmdclient.SavedSnapshotArtifacts, artifactJSON []byte, reason string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(reqCtx), asyncTimeout)
	defer cancel()
	logicalSize := artifacts.LogicalSizeBytes
	if logicalSize < 0 {
		logicalSize = 0
	}
	exclusiveSize := artifacts.ExclusiveSizeBytes
	if exclusiveSize < 0 {
		exclusiveSize = 0
	}
	_, err := h.DB.QueueSavedSnapshotCleanup(ctx, db.QueueSavedSnapshotCleanupParams{
		SnapshotID:         saved.ID,
		TeamID:             saved.TeamID,
		Path:               artifacts.SnapshotPath,
		MemPath:            artifacts.MemPath,
		LogicalSizeBytes:   logicalSize,
		ManifestPath:       artifacts.ManifestPath,
		ArtifactMetadata:   artifactJSON,
		ExclusiveSizeBytes: exclusiveSize,
		FailureReason:      &reason,
	})
	return err
}

func savedSnapshotQuotaCode(err error) string {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return ""
	}
	switch pgErr.Code {
	case "SS002", "SS003":
		return "too_many_snapshots"
	case "SS004", "SS005":
		return "snapshot_storage_quota_exceeded"
	default:
		return ""
	}
}

func (h *Handlers) respondSavedSnapshotQuota(c *gin.Context, teamID, sourceID uuid.UUID, code string) {
	message := "Team or source sandbox has reached its saved snapshot count limit"
	if code == "snapshot_storage_quota_exceeded" {
		message = "Team has reached its saved snapshot storage limit"
	}
	errorBody := gin.H{"code": code, "message": message}
	usage, err := h.DB.GetSavedSnapshotQuotaUsage(c.Request.Context(), teamID)
	if err == nil {
		sourceCount, countErr := h.DB.CountSavedSnapshotsBySource(c.Request.Context(), db.CountSavedSnapshotsBySourceParams{
			SandboxID: sourceID, TeamID: teamID,
		})
		if countErr == nil {
			errorBody["quota"] = gin.H{
				"snapshot_count":            usage.SnapshotCount,
				"max_snapshots":             usage.MaxSnapshots,
				"source_snapshot_count":     sourceCount,
				"max_snapshots_per_sandbox": usage.MaxSnapshotsPerSandbox,
				"storage_bytes":             usage.SnapshotStorageBytes,
				"storage_quota_bytes":       usage.SnapshotStorageQuotaBytes,
			}
		}
	}
	c.JSON(http.StatusTooManyRequests, gin.H{"error": errorBody})
}

func (h *Handlers) respondSnapshotCreated(c *gin.Context, snapshot db.Snapshot) {
	deps, err := h.DB.GetSavedSnapshotDependencyCounts(c.Request.Context(), db.GetSavedSnapshotDependencyCountsParams{
		SnapshotID: snapshot.ID, TeamID: snapshot.TeamID,
	})
	if err != nil {
		log.Error().Err(err).Str("snapshot_id", snapshot.ID.String()).Msg("DB saved snapshot dependency counts")
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusCreated, snapshotToResponse(snapshot, deps))
}

func (h *Handlers) ListSnapshots(c *gin.Context) {
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSandboxRead(c, teamID) {
		return
	}
	pg, err := parsePageParams(c, []string{"created_at"}, "created_at")
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	if c.Query("sort") != "" || c.Query("order") != "" {
		respondErrorMsg(c, "bad_request", "snapshot lists are ordered by created_at descending", http.StatusBadRequest)
		return
	}
	var sourceID pgtype.UUID
	if raw := c.Query("sandbox_id"); raw != "" {
		id, err := parsePublicSandboxID(raw)
		if err != nil {
			respondErrorMsg(c, "bad_request", "sandbox_id is not a valid sandbox ID", http.StatusBadRequest)
			return
		}
		sourceID = pgtype.UUID{Bytes: id, Valid: true}
	}
	ctx := c.Request.Context()
	rows, err := h.DB.ListSavedSnapshotsByTeam(ctx, db.ListSavedSnapshotsByTeamParams{
		TeamID: teamID, SourceSandboxID: sourceID, RowOffset: pg.Offset, RowLimit: pg.Limit,
	})
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("DB ListSavedSnapshotsByTeam")
		respondError(c, ErrInternal)
		return
	}
	total, err := resolveTotal(pg, len(rows), func() (int64, error) {
		return h.DB.CountSavedSnapshotsByTeam(ctx, db.CountSavedSnapshotsByTeamParams{
			TeamID: teamID, SourceSandboxID: sourceID,
		})
	})
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("DB CountSavedSnapshotsByTeam")
		respondError(c, ErrInternal)
		return
	}

	out := make([]snapshotResponse, len(rows))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex
	for i := range rows {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			deps, depErr := h.DB.GetSavedSnapshotDependencyCounts(ctx, db.GetSavedSnapshotDependencyCountsParams{
				SnapshotID: rows[i].ID, TeamID: teamID,
			})
			if depErr != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = depErr
				}
				errMu.Unlock()
				return
			}
			out[i] = snapshotToResponse(rows[i], deps)
		}()
	}
	wg.Wait()
	if firstErr != nil {
		log.Error().Err(firstErr).Str("team_id", teamID.String()).Msg("DB snapshot dependency counts for list")
		respondError(c, ErrInternal)
		return
	}
	c.Header("X-Total-Count", strconv.FormatInt(total, 10))
	c.JSON(http.StatusOK, out)
}

func (h *Handlers) GetSnapshot(c *gin.Context) {
	snapshotID, err := parseSnapshotID(c)
	if err != nil {
		return
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSandboxRead(c, teamID) {
		return
	}
	snapshot, err := h.DB.GetSavedSnapshot(c.Request.Context(), db.GetSavedSnapshotParams{SnapshotID: snapshotID, TeamID: teamID})
	if err != nil {
		if snapshotNotFound(c, err) {
			return
		}
		log.Error().Err(err).Str("snapshot_id", snapshotID.String()).Msg("DB GetSavedSnapshot")
		respondError(c, ErrInternal)
		return
	}
	deps, err := h.DB.GetSavedSnapshotDependencyCounts(c.Request.Context(), db.GetSavedSnapshotDependencyCountsParams{SnapshotID: snapshotID, TeamID: teamID})
	if err != nil {
		log.Error().Err(err).Str("snapshot_id", snapshotID.String()).Msg("DB GetSavedSnapshotDependencyCounts")
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusOK, snapshotToResponse(snapshot, deps))
}

func (h *Handlers) DeleteSavedSnapshot(c *gin.Context) {
	snapshotID, err := parseSnapshotID(c)
	if err != nil {
		return
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSandboxWrite(c, teamID) {
		return
	}
	ctx := c.Request.Context()
	snapshot, err := h.DB.GetSavedSnapshotForDelete(ctx, db.GetSavedSnapshotForDeleteParams{SnapshotID: snapshotID, TeamID: teamID})
	if err != nil {
		if snapshotNotFound(c, err) {
			return
		}
		log.Error().Err(err).Str("snapshot_id", snapshotID.String()).Msg("DB GetSavedSnapshotForDelete")
		respondError(c, ErrInternal)
		return
	}
	if snapshot.DeletedAt.Valid {
		c.Status(http.StatusNoContent)
		return
	}
	if snapshot.Status != db.SnapshotStatusDeleting {
		snapshot, err = h.DB.ClaimDeleteSavedSnapshotIfLeaf(ctx, db.ClaimDeleteSavedSnapshotIfLeafParams{SnapshotID: snapshotID, TeamID: teamID})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				// Another DELETE may have won the row lock while this request was
				// waiting. Adopt its deleting state (or completed tombstone) rather
				// than misreporting a dependency conflict.
				current, getErr := h.DB.GetSavedSnapshotForDelete(ctx, db.GetSavedSnapshotForDeleteParams{SnapshotID: snapshotID, TeamID: teamID})
				switch {
				case errors.Is(getErr, pgx.ErrNoRows):
					snapshotNotFound(c, getErr)
					return
				case getErr != nil:
					log.Error().Err(getErr).Str("snapshot_id", snapshotID.String()).Msg("DB re-read saved snapshot after delete claim race")
					respondError(c, ErrInternal)
					return
				case current.DeletedAt.Valid:
					c.Status(http.StatusNoContent)
					return
				case current.Status == db.SnapshotStatusDeleting:
					snapshot = current
				default:
					h.respondSnapshotDependencyConflict(c, snapshotID, teamID)
					return
				}
			} else {
				log.Error().Err(err).Str("snapshot_id", snapshotID.String()).Msg("DB ClaimDeleteSavedSnapshotIfLeaf")
				respondError(c, ErrInternal)
				return
			}
		}
	}
	if snapshot.HostID == nil || *snapshot.HostID == "" {
		log.Error().Str("snapshot_id", snapshotID.String()).Msg("saved snapshot has no host")
		respondError(c, ErrInternal)
		return
	}
	SetTelemetryHostID(c, *snapshot.HostID)
	vmd, ok := h.snapshotVMDForHost(c, *snapshot.HostID, false)
	if !ok {
		return
	}
	vmdCtx, cancel := context.WithTimeout(ctx, vmdTimeout)
	err = vmd.DeleteSavedSnapshot(vmdCtx, snapshot.SandboxID.String(), snapshot.ID.String())
	cancel()
	if err != nil && !isVMDNotFound(err) {
		switch status.Code(err) {
		case codes.Canceled, codes.DeadlineExceeded, codes.Unavailable, codes.Aborted, codes.ResourceExhausted, codes.Unimplemented:
			c.Header("Retry-After", "5")
			respondErrorMsg(c, "snapshot_host_unavailable", "The snapshot host is temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		log.Error().Err(vmdclient.SanitizeSavedSnapshotError(vmdclient.SavedSnapshotOperationDelete, err)).Str("snapshot_id", snapshotID.String()).Msg("VMD DeleteSavedSnapshot")
		respondError(c, ErrInternal)
		return
	}
	if _, err := h.DB.FinalizeSavedSnapshotDelete(ctx, db.FinalizeSavedSnapshotDeleteParams{SnapshotID: snapshotID, TeamID: teamID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			current, getErr := h.DB.GetSavedSnapshotForDelete(ctx, db.GetSavedSnapshotForDeleteParams{SnapshotID: snapshotID, TeamID: teamID})
			switch {
			case errors.Is(getErr, pgx.ErrNoRows):
				snapshotNotFound(c, getErr)
				return
			case getErr != nil:
				log.Error().Err(getErr).Str("snapshot_id", snapshotID.String()).Msg("DB re-read saved snapshot after delete finalize race")
				respondError(c, ErrInternal)
				return
			case current.DeletedAt.Valid:
				c.Status(http.StatusNoContent)
				return
			default:
				log.Error().Str("snapshot_id", snapshotID.String()).Str("status", string(current.Status)).Msg("saved snapshot delete finalize returned no row without a tombstone")
				respondError(c, ErrInternal)
				return
			}
		}
		log.Error().Err(err).Str("snapshot_id", snapshotID.String()).Msg("DB FinalizeSavedSnapshotDelete")
		respondError(c, ErrInternal)
		return
	}
	h.capture(c, "snapshot_deleted", map[string]any{"snapshot_id": snapshotID.String()})
	c.Status(http.StatusNoContent)
}

func (h *Handlers) respondSnapshotDependencyConflict(c *gin.Context, snapshotID, teamID uuid.UUID) {
	deps, err := h.DB.GetSavedSnapshotDependencyCounts(c.Request.Context(), db.GetSavedSnapshotDependencyCountsParams{SnapshotID: snapshotID, TeamID: teamID})
	if err != nil {
		if snapshotNotFound(c, err) {
			return
		}
		respondError(c, ErrInternal)
		return
	}
	if deps.ChildSandboxCount == 0 && deps.ChildSnapshotCount == 0 {
		respondErrorMsg(c, "snapshot_not_ready", "Snapshot cannot be deleted in its current state", http.StatusConflict)
		return
	}
	h.capture(c, "snapshot_delete_blocked", map[string]any{
		"snapshot_id":    snapshotID.String(),
		"sandbox_count":  deps.ChildSandboxCount,
		"snapshot_count": deps.ChildSnapshotCount,
	})
	body := gin.H{
		"sandbox_count":  deps.ChildSandboxCount,
		"snapshot_count": deps.ChildSnapshotCount,
	}
	if ids, listErr := h.DB.ListSavedSnapshotChildSandboxIDs(c.Request.Context(), db.ListSavedSnapshotChildSandboxIDsParams{
		SnapshotID: pgtype.UUID{Bytes: snapshotID, Valid: true}, TeamID: teamID,
	}); listErr == nil && len(ids) > 0 {
		body["sandbox_ids"] = capSandboxIDs(ids, 100)
	}
	if ids, listErr := h.DB.ListSavedSnapshotChildSnapshotIDs(c.Request.Context(), db.ListSavedSnapshotChildSnapshotIDsParams{
		SnapshotID: pgtype.UUID{Bytes: snapshotID, Valid: true}, TeamID: teamID,
	}); listErr == nil && len(ids) > 0 {
		body["snapshot_ids"] = capUUIDs(ids, 100)
	}
	c.JSON(http.StatusConflict, gin.H{"error": gin.H{
		"code":         "snapshot_has_dependents",
		"message":      "Delete dependent sandboxes and snapshots before deleting this snapshot",
		"dependencies": body,
	}})
}

func capUUIDs(ids []uuid.UUID, max int) []uuid.UUID {
	if len(ids) <= max {
		return ids
	}
	return ids[:max]
}

func capSandboxIDs(ids []uuid.UUID, max int) []string {
	if len(ids) > max {
		ids = ids[:max]
	}
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = formatSandboxID(id)
	}
	return out
}

func snapshotNotFound(c *gin.Context, err error) bool {
	if errors.Is(err, pgx.ErrNoRows) {
		respondErrorMsg(c, "snapshot_not_found", "Snapshot not found", http.StatusNotFound)
		return true
	}
	return false
}
