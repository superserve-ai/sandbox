package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/telemetry"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// capturedSecretProxyEnvKeys are source-specific defaults injected whenever a
// sandbox has secret bindings. They must be blanked together with captured
// proxy tokens before a restored child is exposed. A later InjectSandboxEnv
// call replaces them with the child's freshly signed values when bindings are
// inherited or replaced.
var capturedSecretProxyEnvKeys = []string{
	"CURL_CA_BUNDLE",
	"HTTPS_PROXY",
	"NODE_EXTRA_CA_CERTS",
	"REQUESTS_CA_BUNDLE",
	"SSL_CERT_DIR",
	"SSL_CERT_FILE",
}

func (h *Handlers) createSandboxFromSavedSnapshot(
	c *gin.Context,
	req createSandboxRequest,
	teamID uuid.UUID,
	metadataJSON []byte,
) {
	snapshotID, appErr := parseFromSnapshotID(*req.FromSnapshot)
	if appErr != nil {
		respondError(c, appErr)
		return
	}
	if !h.requireSnapshotsFeature(c, teamID) {
		return
	}

	ctx := c.Request.Context()
	saved, err := h.DB.GetSavedSnapshot(ctx, db.GetSavedSnapshotParams{
		SnapshotID: snapshotID,
		TeamID:     teamID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "snapshot_not_found", "Snapshot not found", http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("snapshot_id", snapshotID.String()).Msg("DB GetSavedSnapshot for fork")
		respondError(c, ErrInternal)
		return
	}
	if !savedSnapshotReadyForFork(c, saved) {
		return
	}
	if err := validateSavedSnapshotForFork(saved); err != nil {
		log.Error().Err(err).Str("snapshot_id", snapshotID.String()).Msg("saved snapshot metadata is incomplete")
		h.markSavedSnapshotUnavailable(c, saved, "snapshot_metadata_invalid")
		respondErrorMsg(c, "snapshot_unavailable", "Snapshot artifacts are missing or corrupt", http.StatusGone)
		return
	}

	capturedBindings, err := decodeSavedSnapshotBindings(saved.SecretBindings)
	if err != nil {
		log.Error().Err(err).Str("snapshot_id", snapshotID.String()).Msg("decode saved snapshot secret manifest")
		h.markSavedSnapshotUnavailable(c, saved, "secret_manifest_invalid")
		respondErrorMsg(c, "snapshot_unavailable", "Snapshot configuration is corrupt", http.StatusGone)
		return
	}
	if err := validateCapturedSnapshotBindings(capturedBindings); err != nil {
		log.Error().Err(err).Str("snapshot_id", snapshotID.String()).Msg("validate saved snapshot secret manifest")
		h.markSavedSnapshotUnavailable(c, saved, "secret_manifest_invalid")
		respondErrorMsg(c, "snapshot_unavailable", "Snapshot configuration is corrupt", http.StatusGone)
		return
	}
	capturedSecretEnvKeys, err := decodeSavedSnapshotSecretEnvKeys(saved.SecretEnvKeys)
	if err != nil {
		log.Error().Err(err).Str("snapshot_id", snapshotID.String()).Msg("decode saved snapshot secret env-key history")
		h.markSavedSnapshotUnavailable(c, saved, "secret_env_key_history_invalid")
		respondErrorMsg(c, "snapshot_unavailable", "Snapshot configuration is corrupt", http.StatusGone)
		return
	}

	// A present secrets object is a complete replacement. A non-nil empty map
	// deliberately clears all captured bindings; omission inherits identities
	// and resolves them against the team's current, non-revoked secrets.
	var secretBindings []db.AddSandboxSecretParams
	var secretMeta []SecretBindingMeta
	if req.Secrets != nil {
		secretBindings, secretMeta, appErr = h.resolveSecretBindingsForCreate(ctx, teamID, req.Secrets)
	} else {
		secretBindings, secretMeta, appErr = h.resolveSavedSnapshotBindingsForCreate(ctx, teamID, capturedBindings)
	}
	if appErr != nil {
		respondError(c, appErr)
		return
	}
	for _, binding := range secretMeta {
		if _, collides := req.EnvVars[binding.EnvKey]; collides {
			respondErrorMsg(c, "bad_request",
				fmt.Sprintf("env-var key %q appears in both env_vars and effective secrets; pick one", binding.EnvKey),
				http.StatusBadRequest)
			return
		}
	}
	if len(secretMeta) > 0 && h.Signer == nil {
		log.Error().Str("snapshot_id", snapshotID.String()).Msg("snapshot fork has secrets but signer is not configured")
		respondError(c, ErrInternal)
		return
	}

	// Network is also a full replacement when present. The effective policy is
	// sent in the restore RPC so VMD installs it before Firecracker starts.
	inheritNetwork := req.Network == nil
	var effectiveNetwork vmdclient.SavedSnapshotNetwork
	var networkJSON []byte
	if inheritNetwork {
		effectiveNetwork, err = savedSnapshotNetworkFromJSON(saved.NetworkConfig)
		if err != nil {
			log.Error().Err(err).Str("snapshot_id", snapshotID.String()).Msg("decode saved snapshot network policy")
			h.markSavedSnapshotUnavailable(c, saved, "network_policy_invalid")
			respondErrorMsg(c, "snapshot_unavailable", "Snapshot configuration is corrupt", http.StatusGone)
			return
		}
	} else {
		effectiveNetwork, networkJSON = savedSnapshotNetworkFromRequest(req.Network)
	}

	hostID := *saved.HostID
	SetTelemetryHostID(c, hostID)
	vmd, ok := h.snapshotVMDForHost(c, hostID, true)
	if !ok {
		return
	}

	sandboxID := uuid.New()
	sandbox, err := h.insertSandboxFromSavedSnapshot(ctx, db.CreateSandboxFromSnapshotParams{
		ID:                       sandboxID,
		TeamID:                   teamID,
		Name:                     req.Name,
		Status:                   db.SandboxStatusStarting,
		InheritTimeoutSeconds:    !req.TimeoutSeconds.Set,
		TimeoutSeconds:           req.TimeoutSeconds.Value,
		Metadata:                 metadataJSON,
		InheritAutoDeleteSeconds: !req.AutoDeleteSeconds.Set,
		AutoDeleteSeconds:        req.AutoDeleteSeconds.Value,
		InheritNetworkConfig:     inheritNetwork,
		NetworkConfig:            networkJSON,
		SourceSnapshotID:         snapshotID,
	}, secretBindings, secretMeta)
	if err != nil {
		h.respondSavedSnapshotForkInsertError(c, saved, err)
		return
	}

	clearEnvKeys := capturedSnapshotSecretEnvKeys(capturedBindings, capturedSecretEnvKeys)
	vmdCtx, vmdCancel := context.WithTimeout(ctx, savedSnapshotVMDTimeout)
	ipAddress, actualVCPU, actualMemoryMiB, restoreErr := vmd.RestoreSavedSnapshot(
		vmdCtx,
		sandboxID.String(),
		*saved.ManifestPath,
		*saved.ManifestDigest,
		teamID.String(),
		ownerIDFromContext(c),
		effectiveNetwork,
		clearEnvKeys,
	)
	vmdCancel()
	if restoreErr != nil {
		h.cleanupFailedSavedSnapshotFork(ctx, vmd, sandbox)
		if h.respondSavedSnapshotRestoreError(c, saved, restoreErr) {
			return
		}
		log.Error().Err(vmdclient.SanitizeSavedSnapshotError(vmdclient.SavedSnapshotOperationRestore, restoreErr)).Str("snapshot_id", snapshotID.String()).Str("sandbox_id", sandboxID.String()).Msg("VMD RestoreSavedSnapshot")
		respondError(c, ErrInternal)
		return
	}

	postCtx, postCancel := context.WithTimeout(context.WithoutCancel(ctx), vmdTimeout)
	defer postCancel()
	var secretsJWT string
	if len(secretMeta) > 0 {
		secretsJWT, err = h.mintSecretsJWT(sandboxID.String(), teamID.String(), ipAddress, secretMeta)
		if err != nil {
			log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("mint secrets JWT for snapshot fork")
			h.cleanupFailedSavedSnapshotFork(postCtx, vmd, sandbox)
			respondError(c, ErrInternal)
			return
		}
	}
	if err := vmd.InjectSandboxEnv(postCtx, sandboxID.String(), mergeEnvVarsWithSecrets(req.EnvVars, secretMeta), secretsJWT); err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("inject env into saved-snapshot fork")
		h.cleanupFailedSavedSnapshotFork(postCtx, vmd, sandbox)
		respondError(c, ErrInternal)
		return
	}

	if len(secretMeta) > 0 {
		go func() {
			primeCtx, cancel := context.WithTimeout(context.Background(), vmdTimeout)
			defer cancel()
			if err := vmd.InvalidateSandboxRules(primeCtx, sandboxID.String()); err != nil {
				log.Warn().Err(err).Str("sandbox_id", sandboxID.String()).Msg("prime fork egress rules cache failed")
			}
		}()
	}

	if actualVCPU == 0 {
		actualVCPU = uint32(*saved.VcpuCount)
	}
	if actualMemoryMiB == 0 {
		actualMemoryMiB = uint32(*saved.MemoryMib)
	}
	var ipAddr *netip.Addr
	if ipAddress != "" {
		addr, parseErr := netip.ParseAddr(ipAddress)
		if parseErr != nil {
			log.Error().Err(parseErr).Str("sandbox_id", sandboxID.String()).Str("ip_address", ipAddress).Msg("VMD returned invalid fork IP")
			h.cleanupFailedSavedSnapshotFork(postCtx, vmd, sandbox)
			respondError(c, ErrInternal)
			return
		}
		ipAddr = &addr
	}

	actorID := actorIDFromContext(c)
	activateCtx, activateCancel := context.WithTimeout(context.WithoutCancel(ctx), asyncTimeout)
	err = h.DB.ActivateSandbox(activateCtx, db.ActivateSandboxParams{
		ID:        sandboxID,
		VcpuCount: int32(actualVCPU),
		MemoryMib: int32(actualMemoryMiB),
		IpAddress: ipAddr,
		TeamID:    teamID,
		ActorID:   actorUUID(actorID),
	})
	if err != nil {
		activateCancel()
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("activate saved-snapshot fork")
		h.cleanupFailedSavedSnapshotFork(postCtx, vmd, sandbox)
		respondError(c, ErrInternal)
		return
	}
	activatedSandbox, err := h.DB.GetSandbox(activateCtx, db.GetSandboxParams{ID: sandboxID, TeamID: teamID})
	activateCancel()
	if err != nil || activatedSandbox.Status != db.SandboxStatusActive ||
		!activatedSandbox.SourceSnapshotID.Valid || uuid.UUID(activatedSandbox.SourceSnapshotID.Bytes) != snapshotID {
		if err == nil {
			err = fmt.Errorf("activation verification returned status=%s source_snapshot_id=%v", activatedSandbox.Status, activatedSandbox.SourceSnapshotID)
		}
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("verify saved-snapshot fork activation")
		h.cleanupFailedSavedSnapshotFork(postCtx, vmd, sandbox)
		respondError(c, ErrInternal)
		return
	}

	// A fork is not externally visible until its durable row, compute interval,
	// and shadow-billing interval are active. Only now is it safe to mint the
	// response token and return 201.
	sandbox = activatedSandbox

	activityMeta, _ := json.Marshal(map[string]string{"from_snapshot": snapshotID.String()})
	h.logSandboxActivity(ctx, sandboxID, teamID, actorID, "sandbox", "started", "success", &sandbox.Name, nil, activityMeta)
	h.capture(c, "sandbox_created", map[string]any{
		"sandbox_id":         sandboxID.String(),
		"source_snapshot_id": snapshotID.String(),
	})

	resp := h.sandboxToResponseWithToken(sandbox)
	if network := savedSnapshotNetworkResponse(effectiveNetwork); network != nil {
		resp.Network = network
	}
	c.JSON(http.StatusCreated, resp)
}

func savedSnapshotReadyForFork(c *gin.Context, saved db.Snapshot) bool {
	switch saved.Status {
	case db.SnapshotStatusReady:
		return true
	case db.SnapshotStatusUnavailable:
		respondErrorMsg(c, "snapshot_unavailable", "Snapshot artifacts are missing or corrupt", http.StatusGone)
	case db.SnapshotStatusCreating, db.SnapshotStatusFailed, db.SnapshotStatusDeleting:
		respondErrorMsg(c, "snapshot_not_ready", fmt.Sprintf("Snapshot is not ready (status=%s)", saved.Status), http.StatusConflict)
	default:
		respondErrorMsg(c, "snapshot_not_ready", "Snapshot is not ready", http.StatusConflict)
	}
	return false
}

func validateSavedSnapshotForFork(saved db.Snapshot) error {
	if saved.HostID == nil || *saved.HostID == "" {
		return errors.New("host is missing")
	}
	if saved.ManifestPath == nil || *saved.ManifestPath == "" {
		return errors.New("manifest path is missing")
	}
	if saved.ManifestDigest == nil || len(*saved.ManifestDigest) != 64 {
		return errors.New("manifest digest is missing or malformed")
	}
	if _, err := hex.DecodeString(*saved.ManifestDigest); err != nil {
		return errors.New("manifest digest is malformed")
	}
	if saved.VcpuCount == nil || *saved.VcpuCount <= 0 || saved.MemoryMib == nil || *saved.MemoryMib <= 0 || saved.DiskMib == nil || *saved.DiskMib <= 0 {
		return errors.New("resource shape is incomplete")
	}
	return nil
}

func validateCapturedSnapshotBindings(bindings []savedSnapshotSecretBinding) error {
	if len(bindings) > SecretsBindingsCap {
		return fmt.Errorf("captured secret binding count exceeds %d", SecretsBindingsCap)
	}
	seen := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		if binding.SecretID == uuid.Nil || binding.EnvKey == "" || !envKeyRE.MatchString(binding.EnvKey) {
			return errors.New("captured secret binding identity is invalid")
		}
		if _, duplicate := seen[binding.EnvKey]; duplicate {
			return fmt.Errorf("duplicate captured secret env key %q", binding.EnvKey)
		}
		seen[binding.EnvKey] = struct{}{}
	}
	return nil
}

func capturedSnapshotSecretEnvKeys(bindings []savedSnapshotSecretBinding, historicKeys []string) []string {
	proxyDefaultsWereInstalled := len(bindings) > 0 || len(historicKeys) > 0
	capacity := len(bindings) + len(historicKeys)
	if proxyDefaultsWereInstalled {
		capacity += len(capturedSecretProxyEnvKeys)
	}
	set := make(map[string]struct{}, capacity)
	for _, binding := range bindings {
		set[binding.EnvKey] = struct{}{}
	}
	for _, key := range historicKeys {
		set[key] = struct{}{}
	}
	if proxyDefaultsWereInstalled {
		for _, key := range capturedSecretProxyEnvKeys {
			set[key] = struct{}{}
		}
	}
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func savedSnapshotNetworkResponse(network vmdclient.SavedSnapshotNetwork) *networkConfigRequest {
	if len(network.AllowedCIDRs) == 0 && len(network.AllowedDomains) == 0 && len(network.DeniedCIDRs) == 0 {
		return nil
	}
	allow := make([]string, 0, len(network.AllowedCIDRs)+len(network.AllowedDomains))
	allow = append(allow, network.AllowedCIDRs...)
	allow = append(allow, network.AllowedDomains...)
	return &networkConfigRequest{
		AllowOut: allow,
		DenyOut:  append([]string(nil), network.DeniedCIDRs...),
	}
}

func (h *Handlers) insertSandboxFromSavedSnapshot(
	ctx context.Context,
	params db.CreateSandboxFromSnapshotParams,
	bindings []db.AddSandboxSecretParams,
	meta []SecretBindingMeta,
) (db.Sandbox, error) {
	insert := func(q *db.Queries, lockSecrets bool) (db.Sandbox, error) {
		if len(bindings) > 0 {
			if len(meta) != len(bindings) {
				return db.Sandbox{}, errors.New("secret binding metadata is not aligned")
			}
			if lockSecrets {
				if err := lockSavedSnapshotForkSecrets(ctx, q, params.TeamID, bindings, meta); err != nil {
					return db.Sandbox{}, err
				}
			}
		}
		sandbox, err := q.CreateSandboxFromSnapshot(ctx, params)
		if err != nil {
			return db.Sandbox{}, err
		}
		if len(bindings) == 0 {
			return sandbox, nil
		}
		secretIDs := make([]uuid.UUID, len(bindings))
		envKeys := make([]string, len(bindings))
		proxyTokens := make([]string, len(bindings))
		for i := range bindings {
			secretIDs[i] = bindings[i].SecretID
			envKeys[i] = bindings[i].EnvKey
			proxyTokens[i] = meta[i].ProxyToken
		}
		if err := q.AddSandboxSecrets(ctx, db.AddSandboxSecretsParams{
			SandboxID:   params.ID,
			SecretIds:   secretIDs,
			EnvKeys:     envKeys,
			ProxyTokens: proxyTokens,
		}); err != nil {
			return db.Sandbox{}, fmt.Errorf("insert fork secret bindings: %w", err)
		}
		return sandbox, nil
	}

	if len(bindings) == 0 || h.Pool == nil {
		return insert(h.DB, false)
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return db.Sandbox{}, err
	}
	defer tx.Rollback(ctx)
	sandbox, err := insert(h.DB.WithTx(tx), true)
	if err != nil {
		return db.Sandbox{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return db.Sandbox{}, err
	}
	return sandbox, nil
}

type savedSnapshotSecretUnavailableError struct {
	EnvKeys []string
}

func (e *savedSnapshotSecretUnavailableError) Error() string {
	return "saved snapshot fork secret unavailable: " + strings.Join(e.EnvKeys, ", ")
}

func lockSavedSnapshotForkSecrets(
	ctx context.Context,
	q *db.Queries,
	teamID uuid.UUID,
	bindings []db.AddSandboxSecretParams,
	meta []SecretBindingMeta,
) error {
	requested := make(map[uuid.UUID][]string, len(bindings))
	for i := range bindings {
		requested[bindings[i].SecretID] = append(requested[bindings[i].SecretID], meta[i].EnvKey)
	}
	secretIDs := make([]uuid.UUID, 0, len(requested))
	for secretID := range requested {
		secretIDs = append(secretIDs, secretID)
	}
	sort.Slice(secretIDs, func(i, j int) bool { return secretIDs[i].String() < secretIDs[j].String() })

	locked, err := q.LockActiveTeamSecretIDs(ctx, db.LockActiveTeamSecretIDsParams{
		TeamID: teamID, SecretIds: secretIDs,
	})
	if err != nil {
		return fmt.Errorf("lock fork secret identities: %w", err)
	}
	lockedSet := make(map[uuid.UUID]struct{}, len(locked))
	for _, secretID := range locked {
		lockedSet[secretID] = struct{}{}
	}
	var missingEnvKeys []string
	for _, secretID := range secretIDs {
		if _, ok := lockedSet[secretID]; !ok {
			missingEnvKeys = append(missingEnvKeys, requested[secretID]...)
		}
	}
	if len(missingEnvKeys) > 0 {
		sort.Strings(missingEnvKeys)
		return &savedSnapshotSecretUnavailableError{EnvKeys: missingEnvKeys}
	}
	return nil
}

func (h *Handlers) respondSavedSnapshotForkInsertError(c *gin.Context, saved db.Snapshot, err error) {
	var unavailable *savedSnapshotSecretUnavailableError
	if errors.As(err, &unavailable) {
		respondErrorMsg(c, "snapshot_secret_unavailable",
			fmt.Sprintf("Effective secrets are no longer available for: %s", strings.Join(unavailable.EnvKeys, ", ")),
			http.StatusConflict)
		return
	}
	if isSandboxQuotaErr(err) {
		h.respondQuotaExceeded(c, saved.TeamID)
		return
	}
	if isSavedSnapshotHostCapacityErr(err) {
		c.Header("Retry-After", "5")
		respondErrorMsg(c, "snapshot_host_unavailable", "The snapshot host has insufficient capacity", http.StatusServiceUnavailable)
		return
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		log.Error().Err(err).Str("snapshot_id", saved.ID.String()).Msg("DB CreateSandboxFromSnapshot")
		respondError(c, ErrInternal)
		return
	}

	current, getErr := h.DB.GetSavedSnapshot(c.Request.Context(), db.GetSavedSnapshotParams{
		SnapshotID: saved.ID,
		TeamID:     saved.TeamID,
	})
	if errors.Is(getErr, pgx.ErrNoRows) {
		respondErrorMsg(c, "snapshot_not_found", "Snapshot not found", http.StatusNotFound)
		return
	}
	if getErr != nil {
		log.Error().Err(getErr).Str("snapshot_id", saved.ID.String()).Msg("DB re-read snapshot after fork admission race")
		respondError(c, ErrInternal)
		return
	}
	if !savedSnapshotReadyForFork(c, current) {
		return
	}
	// A ready row that did not admit a fork means its team-scoped feature flag
	// was disabled between the explicit gate and the atomic insert.
	if enabled, featureErr := h.DB.IsFeatureEnabledForTeam(c.Request.Context(), db.IsFeatureEnabledForTeamParams{
		Key: snapshotsFeatureKey, TeamID: pgtype.UUID{Bytes: saved.TeamID, Valid: true},
	}); featureErr == nil && !enabled {
		respondErrorMsg(c, "feature_disabled", "Saved snapshots are not enabled for this team", http.StatusForbidden)
		return
	}
	log.Error().Str("snapshot_id", saved.ID.String()).Msg("ready snapshot fork admission returned no row")
	respondError(c, ErrInternal)
}

// cleanupFailedSavedSnapshotFork compensates an admission that never returned
// a sandbox ID to the caller. Revocation is persisted before any host or
// binding cleanup: even an ambiguous teardown can never leave a hidden VM with
// a valid long-lived secrets JWT.
func (h *Handlers) cleanupFailedSavedSnapshotFork(reqCtx context.Context, vmd snapshotVMDClient, sandbox db.Sandbox) {
	dbCtx, dbCancel := context.WithTimeout(context.WithoutCancel(reqCtx), asyncTimeout)
	defer dbCancel()
	expiresAt := time.Now().Add(SecretsJWTLifetime)
	if err := h.DB.UpsertSandboxRevocation(dbCtx, db.UpsertSandboxRevocationParams{
		SandboxID: sandbox.ID,
		ExpiresAt: expiresAt,
	}); err != nil {
		log.Error().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("persist failed-fork sandbox revocation")
		// Fail closed. A direct daemon revoke may still protect this process,
		// but without durable revocation we must not free its VM, IP, bindings,
		// or parent pin: a crash could otherwise resurrect the credentials.
		revokeCtx, revokeCancel := context.WithTimeout(context.WithoutCancel(reqCtx), vmdTimeout)
		if revokeErr := vmd.RevokeSandbox(revokeCtx, sandbox.ID.String()); revokeErr != nil {
			log.Warn().Err(revokeErr).Str("sandbox_id", sandbox.ID.String()).Msg("direct failed-fork revoke after persistence failure")
		}
		revokeCancel()
		h.markFailedSnapshotFork(dbCtx, sandbox)
		RecordSavedSnapshotOutcome(dbCtx, telemetry.SavedSnapshotOperationCleanup, telemetry.SavedSnapshotOutcomeError, sandbox.HostID)
		return
	}

	revokeCtx, revokeCancel := context.WithTimeout(context.WithoutCancel(reqCtx), vmdTimeout)
	if err := vmd.RevokeSandbox(revokeCtx, sandbox.ID.String()); err != nil {
		log.Warn().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("direct failed-fork sandbox revoke")
	}
	revokeCancel()

	hostCtx, hostCancel := context.WithTimeout(context.WithoutCancel(reqCtx), vmdTimeout)
	destroyErr := vmd.DestroyInstance(hostCtx, sandbox.ID.String(), true)
	hostCancel()
	if destroyErr != nil && !isVMDNotFound(destroyErr) {
		log.Warn().Err(vmdclient.SanitizeSavedSnapshotError(vmdclient.SavedSnapshotOperationRestore, destroyErr)).Str("sandbox_id", sandbox.ID.String()).Msg("cleanup failed saved-snapshot restore")
		// Keep the durable child reference while an orphan VM may still be
		// reading the saved layers. Marking the row failed makes it visible and
		// user-deletable; soft-deleting it here would let the parent snapshot be
		// reclaimed underneath a VM whose teardown outcome is unknown.
		h.markFailedSnapshotFork(dbCtx, sandbox)
		outcome := telemetry.SavedSnapshotOutcomeError
		if transientSavedSnapshotAPIError(destroyErr) {
			outcome = telemetry.SavedSnapshotOutcomeRetry
		}
		RecordSavedSnapshotOutcome(dbCtx, telemetry.SavedSnapshotOperationCleanup, outcome, sandbox.HostID)
		return
	}
	_, err := h.DB.DestroySandbox(dbCtx, db.DestroySandboxParams{
		ID:     sandbox.ID,
		TeamID: sandbox.TeamID,
		// This handler owns the starting transition and the VMD operation has
		// ended, so it is safe to claim it immediately rather than waiting for
		// the general stale-transition grace period.
		StaleTransitionalBefore: time.Now().Add(time.Second),
		RevocationExpiresAt:     expiresAt,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// A concurrent lifecycle owner won the claim. Its cleanup path owns
			// bindings and the pin; both remain protected by durable revocation.
			RecordSavedSnapshotOutcome(dbCtx, telemetry.SavedSnapshotOperationCleanup, telemetry.SavedSnapshotOutcomeRetry, sandbox.HostID)
			return
		}
		log.Error().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("soft-delete failed saved-snapshot fork")
		h.markFailedSnapshotFork(dbCtx, sandbox)
		RecordSavedSnapshotOutcome(dbCtx, telemetry.SavedSnapshotOperationCleanup, telemetry.SavedSnapshotOutcomeRetry, sandbox.HostID)
		return
	}
	if err := h.DB.DeleteSandboxSecrets(dbCtx, sandbox.ID); err != nil {
		log.Warn().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("clear bindings after failed snapshot fork")
	}
	if sandbox.SourceSnapshotID.Valid {
		if _, err := h.DB.ReleaseDestroyedSandboxSnapshotPin(dbCtx, db.ReleaseDestroyedSandboxSnapshotPinParams{
			SandboxID:        sandbox.ID,
			TeamID:           sandbox.TeamID,
			SourceSnapshotID: sandbox.SourceSnapshotID,
		}); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			log.Warn().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("release compensated fork snapshot pin")
		}
	}
	RecordSavedSnapshotOutcome(dbCtx, telemetry.SavedSnapshotOperationCleanup, telemetry.SavedSnapshotOutcomeSuccess, sandbox.HostID)
}

func (h *Handlers) markFailedSnapshotFork(ctx context.Context, sandbox db.Sandbox) {
	if err := h.DB.MarkSandboxFailedInTeam(ctx, db.MarkSandboxFailedInTeamParams{
		ID: sandbox.ID, TeamID: sandbox.TeamID,
	}); err != nil {
		log.Error().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("mark failed snapshot fork")
	}
}

func (h *Handlers) respondSavedSnapshotRestoreError(c *gin.Context, saved db.Snapshot, err error) bool {
	switch status.Code(err) {
	case codes.Canceled, codes.DeadlineExceeded, codes.Unavailable, codes.Aborted, codes.ResourceExhausted, codes.Unimplemented:
		c.Header("Retry-After", "5")
		respondErrorMsg(c, "snapshot_host_unavailable", "The snapshot host is temporarily unavailable", http.StatusServiceUnavailable)
		return true
	case codes.NotFound, codes.FailedPrecondition, codes.DataLoss, codes.InvalidArgument:
		h.markSavedSnapshotUnavailable(c, saved, "artifact_restore_failed")
		respondErrorMsg(c, "snapshot_unavailable", "Snapshot artifacts are missing or corrupt", http.StatusGone)
		return true
	default:
		return false
	}
}

func (h *Handlers) markSavedSnapshotUnavailable(c *gin.Context, saved db.Snapshot, reason string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), asyncTimeout)
	defer cancel()
	if _, err := h.DB.MarkSavedSnapshotUnavailable(ctx, db.MarkSavedSnapshotUnavailableParams{
		FailureReason: &reason,
		SnapshotID:    saved.ID,
		TeamID:        saved.TeamID,
	}); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			log.Error().Err(err).Str("snapshot_id", saved.ID.String()).Msg("mark saved snapshot unavailable")
		}
		return
	}
	RecordSavedSnapshotOutcome(ctx, telemetry.SavedSnapshotOperationRestore, telemetry.SavedSnapshotOutcomeUnavailable, savedSnapshotHostID(saved))
	h.capture(c, "snapshot_unavailable", map[string]any{
		"snapshot_id": saved.ID.String(),
		"reason":      reason,
	})
}
