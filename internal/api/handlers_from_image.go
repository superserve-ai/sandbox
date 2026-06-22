package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/start"
)

// fromImageRequest is the body of POST /v1/sandboxes/from-image — the
// bring-your-image one-call path. The image's own ENTRYPOINT/CMD runs (honored
// via the captured image_config + boxd /start), with command/env overriding it
// like `docker run`.
type fromImageRequest struct {
	Image     string            `json:"image"`             // required, e.g. ghcr.io/org/agent:latest
	Name      string            `json:"name"`              // sandbox name (required on HIT)
	Command   []string          `json:"command,omitempty"` // overrides image entrypoint+cmd
	Env       map[string]string `json:"env,omitempty"`     // layered over image env
	Vcpu      int32             `json:"vcpu,omitempty"`    // build shape (MISS only)
	MemoryMib int32             `json:"memory_mib,omitempty"`
	DiskMib   int32             `json:"disk_mib,omitempty"`
}

// CreateSandboxFromImage implements the digest-keyed bring-your-image path:
//
//	resolve image → digest
//	  HIT  (a ready template exists for (team,digest)) → create a sandbox from it
//	       and run the image's start command — sub-second restore.
//	  MISS → kick a template build for the image and return 202 building; the
//	       second create on the same digest is a HIT.
//
// v1 scope (documented): the HIT create does not yet attach secrets or network
// rules (use the templated POST /sandboxes for those); it is additive and does
// not touch the CreateSandbox critical path.
func (h *Handlers) CreateSandboxFromImage(c *gin.Context) {
	var req fromImageRequest
	if err := bindJSONStrict(c, &req); err != nil {
		respondErrorMsg(c, "bad_request", "Request body is not valid JSON or contains unknown fields.", http.StatusBadRequest)
		return
	}
	if req.Image == "" {
		respondErrorMsg(c, "bad_request", "image is required", http.StatusBadRequest)
		return
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}

	// Resolve the image reference to a content digest — the cache key. Matches
	// what the builder records as template.resolved_digest during a real pull.
	digest, err := resolveImageDigest(c.Request.Context(), req.Image)
	if err != nil {
		respondErrorMsg(c, "bad_request", fmt.Sprintf("could not resolve image %q: %v", req.Image, err), http.StatusBadRequest)
		return
	}

	digestPtr := digest
	tpl, err := h.DB.GetReadyTemplateByImageDigest(c.Request.Context(), db.GetReadyTemplateByImageDigestParams{
		TeamID:         teamID,
		ResolvedDigest: &digestPtr,
	})
	if err == nil {
		h.fromImageCacheHit(c, teamID, tpl, req, digest)
		return
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		respondError(c, ErrInternal)
		return
	}
	h.fromImageCacheMiss(c, teamID, req, digest)
}

// fromImageCacheHit creates a sandbox from the cached template and resolves the
// start command from the template's image_config + request overrides. Sequential
// (no parallel insert/vmd) and secret/network-free — additive v1.
func (h *Handlers) fromImageCacheHit(c *gin.Context, teamID uuid.UUID, tpl db.Template, req fromImageRequest, digest string) {
	if req.Name == "" {
		respondErrorMsg(c, "bad_request", "name is required to create a sandbox", http.StatusBadRequest)
		return
	}
	if tpl.SnapshotPath == nil || tpl.MemPath == nil {
		respondError(c, ErrInternal)
		return
	}

	// Resolve the effective start command (honored in-guest via boxd /start from
	// the baked start spec; surfaced here for the response/log and overrides).
	startSpec, err := resolveImageStartSpec(tpl.ImageConfig, req.Command, req.Env)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}

	hostID := h.pickHost()
	vmd, err := h.vmdForHost(c.Request.Context(), hostID)
	if err != nil {
		respondErrorMsg(c, "service_unavailable", "No hosts available", http.StatusServiceUnavailable)
		return
	}

	sandboxID := uuid.New()
	metadataJSON, _ := json.Marshal(map[string]string{"superserve.from_image": req.Image})
	insertCtx := context.WithoutCancel(c.Request.Context())
	sandbox, err := h.DB.CreateSandboxFromTemplate(insertCtx, db.CreateSandboxFromTemplateParams{
		ID:           sandboxID,
		TeamID:       teamID,
		Name:         req.Name,
		Status:       db.SandboxStatusStarting,
		VcpuCount:    1,
		MemoryMib:    1,
		HostID:       hostID,
		Metadata:     metadataJSON,
		ID_2:         tpl.ID,
		TeamID_2:     teamID,
		TeamID_3:     h.systemTeamID(),
		SnapshotPath: tpl.SnapshotPath,
		MemPath:      tpl.MemPath,
		BasePath:     tpl.BasePath,
		DeltaPath:    tpl.DeltaPath,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "not_found", "Template not found", http.StatusNotFound)
			return
		}
		if isSandboxQuotaErr(err) {
			h.respondQuotaExceeded(c, teamID)
			return
		}
		respondError(c, ErrInternal)
		return
	}

	base, deltaDir := "", ""
	if tpl.BasePath != nil {
		base = *tpl.BasePath
	}
	if tpl.DeltaPath != nil {
		deltaDir = filepath.Dir(*tpl.DeltaPath)
	}
	ip, vcpu, mem, vmdErr := vmd.RestoreSnapshot(c.Request.Context(), sandboxID.String(),
		*tpl.SnapshotPath, *tpl.MemPath, base, deltaDir, teamID.String(), ownerIDFromContext(c), req.Env)
	if vmdErr != nil {
		_ = h.DB.UpdateSandboxStatus(insertCtx, db.UpdateSandboxStatusParams{ID: sandbox.ID, Status: db.SandboxStatusFailed, TeamID: teamID})
		if isVMDFileMissing(vmdErr) {
			respondError(c, ErrHostStateMissing)
			return
		}
		respondError(c, ErrInternal)
		return
	}

	var ipAddr *netip.Addr
	if ip != "" {
		if a, perr := netip.ParseAddr(ip); perr == nil {
			ipAddr = &a
		}
	}
	if vcpu == 0 {
		vcpu = uint32(tpl.Vcpu)
	}
	if mem == 0 {
		mem = uint32(tpl.MemoryMib)
	}
	_ = h.DB.ActivateSandbox(insertCtx, db.ActivateSandboxParams{
		ID: sandbox.ID, VcpuCount: int32(vcpu), MemoryMib: int32(mem), IpAddress: ipAddr,
		TeamID: teamID, ActorID: actorUUID(actorIDFromContext(c)),
	})
	sandbox.Status = db.SandboxStatusActive
	sandbox.VcpuCount = int32(vcpu)
	sandbox.MemoryMib = int32(mem)
	sandbox.IpAddress = ipAddr

	_ = startSpec // delivered in-guest via the baked start.json / boxd /start (Epic 2.2)
	c.JSON(http.StatusCreated, h.sandboxToResponseWithToken(sandbox))
}

// fromImageCacheMiss kicks a template build for the image (digest not yet
// cached) and returns 202. The next create on the same digest is a HIT.
func (h *Handlers) fromImageCacheMiss(c *gin.Context, teamID uuid.UUID, req fromImageRequest, digest string) {
	spec := &buildSpec{From: req.Image}
	specJSON, _ := json.Marshal(spec)
	specHash, err := canonicalSpecHash(spec)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	name := req.Name
	if name == "" {
		name = "from-image-" + shortDigest(digest)
	}
	vcpu, mem, disk := req.Vcpu, req.MemoryMib, req.DiskMib
	if vcpu == 0 {
		vcpu = 1
	}
	if mem == 0 {
		mem = 1024
	}
	if disk == 0 {
		disk = 4096
	}
	row, err := h.DB.CreateTemplateWithBuild(c.Request.Context(), db.CreateTemplateWithBuildParams{
		TeamID: teamID, Name: name, BuildSpec: specJSON,
		Vcpu: vcpu, MemoryMib: mem, DiskMib: disk, BuildSpecHash: specHash,
	})
	if err != nil {
		if isUniqueViolation(err) {
			respondErrorMsg(c, "conflict", fmt.Sprintf("a build for %q is already in progress", req.Image), http.StatusConflict)
			return
		}
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"status":          "building",
		"template_id":     row.ID.String(),
		"build_id":        row.BuildID.String(),
		"resolved_digest": digest,
		"message":         "Image not cached yet; building a template. Retry from-image once ready for a sub-second restore.",
	})
}

// pickHost selects a host for placement (scheduler, else default).
func (h *Handlers) pickHost() string {
	if h.Scheduler != nil {
		if id, err := h.Scheduler.SelectHost(context.Background()); err == nil {
			return id
		}
	}
	if h.Config != nil && h.Config.DefaultHostID != "" {
		return h.Config.DefaultHostID
	}
	return "default"
}

func shortDigest(d string) string {
	d = trimDigestPrefix(d)
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

func trimDigestPrefix(d string) string {
	for i := 0; i < len(d); i++ {
		if d[i] == ':' {
			return d[i+1:]
		}
	}
	return d
}

// imageConfig mirrors the builder.ImageDefaults JSON shape persisted in
// template.image_config (jsonb). Duplicated here (rather than importing
// internal/builder) so the API package doesn't pull the OCI/registry stack in
// just to read five fields.
type imageConfig struct {
	Entrypoint []string          `json:"entrypoint,omitempty"`
	Cmd        []string          `json:"cmd,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	WorkingDir string            `json:"working_dir,omitempty"`
	User       string            `json:"user,omitempty"`
}

// resolveImageStartSpec computes the start command a sandbox should run, from a
// template's captured image config (the jsonb bytes, possibly nil/empty for
// legacy templates) plus per-request overrides. This is the bring-your-image
// glue: it turns "honor the image's ENTRYPOINT/CMD, with `command`/`env`
// overriding like `docker run`" into a concrete start.Spec that boxd supervises.
//
// A nil/empty imageConfigJSON with no command override yields a non-runnable
// Spec (Spec.IsRunnable()==false) — i.e. a base template with no auto-start,
// preserving today's behavior.
func resolveImageStartSpec(imageConfigJSON []byte, command []string, env map[string]string) (start.Spec, error) {
	var img start.Image
	if len(imageConfigJSON) > 0 {
		var cfg imageConfig
		if err := json.Unmarshal(imageConfigJSON, &cfg); err != nil {
			return start.Spec{}, err
		}
		img = start.Image{
			Entrypoint: cfg.Entrypoint,
			Cmd:        cfg.Cmd,
			Env:        cfg.Env,
			WorkingDir: cfg.WorkingDir,
			User:       cfg.User,
		}
	}
	return start.Resolve(img, start.Overrides{
		Command:    command,
		SandboxEnv: env,
	}), nil
}

// resolveImageDigest resolves an image reference to its content digest
// ("sha256:...") with a registry HEAD. Package var so tests can stub it without
// network. Mirrors how the builder resolves the digest during a real pull, so
// the value matches what FinalizeBuild persists as template.resolved_digest.
//
// Auth: uses the same authn.DefaultKeychain the builder uses
// (internal/builder/auth.go), so a private image the platform host is
// credentialed for (docker config / credential helper) resolves here instead of
// 401-ing on an anonymous HEAD. Per-team/per-request registry credentials are
// not yet supported — see the PR description.
var resolveImageDigest = func(ctx context.Context, imageRef string) (string, error) {
	return crane.Digest(imageRef, crane.WithContext(ctx), crane.WithAuthFromKeychain(authn.DefaultKeychain))
}
