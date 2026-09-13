package qm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/qm/adminlink"
	"github.com/superserve-ai/sandbox/internal/qm/provisioner"
	"github.com/superserve-ai/sandbox/internal/qm/secrets"
	"github.com/superserve-ai/sandbox/internal/qm/tenantstore"
)

const (
	// Event steps the API itself records, alongside the runner's.
	stepModelKey = "model_key"
	// stepTrigger is the provisioner's, since a run's intent event is what
	// identifies the attempt the job is started for.
	stepTrigger = provisioner.TriggerStep

	// maxCreateBodyBytes caps the create body before it is decoded: every
	// field is small (the model key, the largest, is capped at 4 KiB), so
	// an authenticated caller has no reason to send more and should not be
	// able to make the service allocate it.
	maxCreateBodyBytes = 32 << 10

	internalErrorMsg = "A problem occurred. Please try again, or contact the team if it persists."
)

// Handlers serves /v1/qm. Everything slow is delegated: the store is one
// transaction per call and the trigger returns as soon as a run is queued.
type Handlers struct {
	Store   tenantstore.Store
	Secrets secrets.Store
	Trigger provisioner.Trigger
	Log     zerolog.Logger

	// StaleAfter: an in-flight tenant whose newest event is older than this
	// is treated as having lost its run (the job never started, or died
	// before it could record a failure) and becomes retryable/deletable.
	// Zero disables the reclaim.
	StaleAfter time.Duration

	// Now and NewJTI are seams for deterministic admin-link tests.
	Now    func() time.Time
	NewJTI func() (string, error)
}

func (h *Handlers) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Handlers) newJTI() (string, error) {
	if h.NewJTI != nil {
		return h.NewJTI()
	}
	return adminlink.NewJTI()
}

// CreateTenant validates, inserts, stores the model key, and queues a
// provision run. The model key reaches Secret Manager directly from here
// (never the job's arguments, which are visible in execution metadata,
// and never Postgres). A tenant whose key or run could not be set up is
// left in status failed with an event explaining which, and the request
// reports the failure rather than 202.
func (h *Handlers) CreateTenant(c *gin.Context) {
	p := principalFrom(c)
	var req CreateTenantRequest
	if !decodeBody(c, &req) {
		return
	}
	req.normalize()
	if fields := req.validate(); len(fields) > 0 {
		respondFieldErrors(c, fields)
		return
	}

	ctx := c.Request.Context()
	tenant, err := h.Store.CreateTenant(ctx, p.TeamID, tenantstore.CreateParams{
		Slug: req.Slug, OrgName: req.OrgName, AdminEmail: req.AdminEmail, SignIn: req.SignIn,
		ModelProvider: req.ModelProvider, Harness: req.Harness, CreatedBy: p.ActorID,
	})
	switch {
	case errors.Is(err, tenantstore.ErrTeamHasTenant):
		respondError(c, http.StatusConflict, "This team already has a QM instance.")
		return
	case errors.Is(err, tenantstore.ErrSlugTaken):
		respondError(c, http.StatusConflict, "This slug is already taken.")
		return
	case errors.Is(err, tenantstore.ErrTeamNotHomed):
		respondError(c, http.StatusConflict, "This team is being moved to another region; try again once the move completes.")
		return
	case err != nil:
		h.Log.Error().Err(err).Msg("create tenant")
		respondError(c, http.StatusInternalServerError, internalErrorMsg)
		return
	}
	log := h.Log.With().Str("tenant_id", tenant.ID.String()).Logger()

	keyName := secrets.ModelKeyName(req.ModelProvider)
	ref, err := h.Secrets.Put(ctx, secrets.TenantSecretName(tenant.Slug, keyName), []byte(req.ModelKey))
	if err != nil {
		log.Error().Str("error", provisioner.ScrubString(err.Error())).Msg("store model key")
		h.failTenant(ctx, tenant, tenantstore.VersionOf(tenant), []string{tenantstore.StatusProvisioning}, stepModelKey, "The model key could not be stored. Delete this tenant and create it again.", err, nil)
		respondError(c, http.StatusBadGateway, "The tenant was created but its model key could not be stored. Delete it and try again.")
		return
	}
	if err := h.Store.SetSecretRef(ctx, p.TeamID, tenant.ID, keyName, ref); err != nil {
		log.Error().Err(err).Msg("record model key ref")
		// An error can follow a commit that did land (a dropped connection
		// on the way back); re-read before deciding. A reference that is
		// there means the key is usable and the tenant proceeds. One that
		// is not means the key must not outlive this request unreferenced:
		// remove it now, detached from the (possibly gone) caller.
		// If even the re-read fails the key is left in place: teardown
		// removes the derived name regardless, and a key deleted on a
		// guess could belong to a tenant that is in fact fine.
		dctx, cancel := detached(ctx)
		stored, lerr := h.modelKeyStored(dctx, tenant)
		switch {
		case lerr != nil:
			log.Error().Err(lerr).Msg("re-read model key ref")
			cancel()
			h.failTenant(ctx, tenant, tenantstore.VersionOf(tenant), []string{tenantstore.StatusProvisioning}, stepModelKey, "The model key reference could not be confirmed. Retry the tenant, or delete it and create it again.", err, nil)
			respondError(c, http.StatusInternalServerError, internalErrorMsg)
			return
		case stored:
			cancel()
			log.Warn().Msg("model key reference was recorded despite the error; continuing")
		default:
			if derr := h.Secrets.Delete(dctx, secrets.TenantSecretName(tenant.Slug, keyName)); derr != nil {
				log.Error().Str("error", provisioner.ScrubString(derr.Error())).Msg("remove unreferenced model key")
			}
			cancel()
			h.failTenant(ctx, tenant, tenantstore.VersionOf(tenant), []string{tenantstore.StatusProvisioning}, stepModelKey, "The model key reference could not be recorded. Delete this tenant and create it again.", err, nil)
			respondError(c, http.StatusInternalServerError, internalErrorMsg)
			return
		}
	}
	// A create whose Secret Manager write outlived StaleAfter can have been
	// reclaimed and torn down while it was in flight. A teardown that got
	// past its own secrets step before this reference landed will never see
	// it, and the key would outlive the tenant — so take it back here.
	retired, rerr := h.tenantRetired(ctx, tenant)
	if rerr != nil {
		log.Error().Err(rerr).Msg("confirm the tenant survived its model key")
	}
	if retired {
		dctx, cancel := detached(ctx)
		if derr := h.Secrets.Delete(dctx, secrets.TenantSecretName(tenant.Slug, keyName)); derr != nil {
			log.Error().Str("error", provisioner.ScrubString(derr.Error())).Msg("remove the model key of a retired tenant")
		}
		if derr := h.Store.DeleteSecretRef(dctx, p.TeamID, tenant.ID, keyName); derr != nil {
			log.Error().Err(derr).Msg("remove the model key reference of a retired tenant")
		}
		cancel()
		respondError(c, http.StatusConflict, "This tenant was deleted while it was being created. Create it again.")
		return
	}
	stored := h.event(ctx, tenant, stepModelKey, tenantstore.EventOK, keyName+" stored", nil)

	queued, ok := h.queueRun(c, tenant, versionAfter(tenant, stored), []string{tenantstore.StatusProvisioning}, provisioner.ModeProvision)
	if !ok {
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"tenant": toTenantResponse(queued)})
}

// decodeBody reads exactly one JSON value of at most maxCreateBodyBytes
// into out, writing the response and returning false otherwise. The
// trailing-data check is what makes the size limit meaningful: the reader
// only counts bytes the decoder pulls, so a body that is one valid object
// followed by megabytes of anything would otherwise pass unread.
func decodeBody(c *gin.Context, out any) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxCreateBodyBytes)
	dec := json.NewDecoder(c.Request.Body)
	err := dec.Decode(out)
	if err == nil {
		if rest := dec.Decode(new(json.RawMessage)); !errors.Is(rest, io.EOF) {
			err = rest
			if err == nil {
				err = errors.New("unexpected data after the JSON object")
			}
		}
	}
	if err == nil {
		return true
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		respondError(c, http.StatusRequestEntityTooLarge, "Request body is too large.")
		return false
	}
	respondError(c, http.StatusBadRequest, "Request body must be a single JSON object.")
	return false
}

func (h *Handlers) ListTenants(c *gin.Context) {
	p := principalFrom(c)
	tenants, err := h.Store.ListTenants(c.Request.Context(), p.TeamID)
	if err != nil {
		h.Log.Error().Err(err).Msg("list tenants")
		respondError(c, http.StatusInternalServerError, internalErrorMsg)
		return
	}
	c.JSON(http.StatusOK, gin.H{"tenants": toTenantResponses(tenants)})
}

func (h *Handlers) GetTenant(c *gin.Context) {
	tenant, ok := h.loadTenant(c)
	if !ok {
		return
	}
	events, err := h.Store.ListEvents(c.Request.Context(), tenant.TeamID, tenant.ID)
	if err != nil {
		h.Log.Error().Err(err).Msg("list tenant events")
		respondError(c, http.StatusInternalServerError, internalErrorMsg)
		return
	}
	c.JSON(http.StatusOK, gin.H{"tenant": toTenantResponse(tenant), "events": toEventResponses(events)})
}

// DeleteTenant moves a settled tenant to deprovisioning and queues the
// teardown. A run in flight is not interrupted: the two would race on the
// tenant's final status, so the caller waits for it to settle.
func (h *Handlers) DeleteTenant(c *gin.Context) {
	tenant, ok := h.loadTenant(c)
	if !ok {
		return
	}
	tenant, ok = h.reclaimStale(c, tenant)
	if !ok {
		return
	}
	switch tenant.Status {
	case tenantstore.StatusReady, tenantstore.StatusFailed:
	case tenantstore.StatusDeprovisioning:
		respondError(c, http.StatusConflict, "This tenant is already being deleted.")
		return
	default:
		respondError(c, http.StatusConflict, "Wait for provisioning to finish before deleting this tenant.")
		return
	}
	queued, ok := h.queueRun(c, tenant, tenantstore.VersionOf(tenant), []string{tenantstore.StatusReady, tenantstore.StatusFailed}, provisioner.ModeDeprovision)
	if !ok {
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"tenant": toTenantResponse(queued)})
}

// RetryTenant re-queues the plan a failed tenant was last running.
func (h *Handlers) RetryTenant(c *gin.Context) {
	tenant, ok := h.loadTenant(c)
	if !ok {
		return
	}
	tenant, ok = h.reclaimStale(c, tenant)
	if !ok {
		return
	}
	if tenant.Status != tenantstore.StatusFailed {
		respondError(c, http.StatusConflict, "Only a failed tenant can be retried.")
		return
	}
	ctx := c.Request.Context()
	events, err := h.Store.ListEvents(ctx, tenant.TeamID, tenant.ID)
	if err != nil {
		h.Log.Error().Err(err).Msg("list tenant events")
		respondError(c, http.StatusInternalServerError, internalErrorMsg)
		return
	}
	mode := lastRunMode(events)
	// The model key is only ever supplied at create time; a tenant whose key
	// never reached Secret Manager cannot be provisioned by any retry.
	if mode == provisioner.ModeProvision {
		stored, err := h.modelKeyStored(ctx, tenant)
		if err != nil {
			h.Log.Error().Err(err).Msg("list tenant secret refs")
			respondError(c, http.StatusInternalServerError, internalErrorMsg)
			return
		}
		if !stored {
			respondError(c, http.StatusConflict, "This tenant's model key was never stored. Delete it and create it again.")
			return
		}
	}
	queued, ok := h.queueRun(c, tenant, tenantstore.VersionOf(tenant), []string{tenantstore.StatusFailed}, mode)
	if !ok {
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"tenant": toTenantResponse(queued)})
}

// AdminLink mints a portal sign-in link for the tenant's admin. The portal
// session secret is read from Secret Manager per request and used only in
// memory; the link is returned once and never stored.
func (h *Handlers) AdminLink(c *gin.Context) {
	tenant, ok := h.loadTenant(c)
	if !ok {
		return
	}
	if tenant.Status != tenantstore.StatusReady || tenant.PublicUrl == nil {
		respondError(c, http.StatusConflict, "Admin links are available once the tenant is ready.")
		return
	}
	secret, err := h.Secrets.Get(c.Request.Context(), secrets.TenantSecretName(tenant.Slug, secrets.PortalSessionSecret))
	if err != nil {
		h.Log.Error().Err(err).Str("tenant_id", tenant.ID.String()).Msg("read portal session secret")
		respondError(c, http.StatusBadGateway, "The tenant's sign-in secret could not be read.")
		return
	}
	jti, err := h.newJTI()
	if err != nil {
		h.Log.Error().Err(err).Msg("admin link id")
		respondError(c, http.StatusInternalServerError, internalErrorMsg)
		return
	}
	link, err := adminlink.Mint(*tenant.PublicUrl, string(secret), tenant.AdminEmail, h.now(), jti)
	if err != nil {
		h.Log.Error().Err(err).Str("tenant_id", tenant.ID.String()).Msg("mint admin link")
		respondError(c, http.StatusInternalServerError, internalErrorMsg)
		return
	}
	c.JSON(http.StatusOK, AdminLinkResponse{URL: link.URL, ExpiresAt: link.ExpiresAt})
}

func (h *Handlers) SlugAvailability(c *gin.Context) {
	p := principalFrom(c)
	slug := strings.ToLower(strings.TrimSpace(c.Param("slug")))
	if reason := ValidateSlug(slug); reason != "" {
		c.JSON(http.StatusOK, SlugAvailabilityResponse{Available: false, Reason: reason})
		return
	}
	available, err := h.Store.SlugAvailable(c.Request.Context(), p.TeamID, slug)
	if err != nil {
		h.Log.Error().Err(err).Msg("slug availability")
		respondError(c, http.StatusInternalServerError, internalErrorMsg)
		return
	}
	if !available {
		c.JSON(http.StatusOK, SlugAvailabilityResponse{Available: false, Reason: "This slug is already taken."})
		return
	}
	c.JSON(http.StatusOK, SlugAvailabilityResponse{Available: true})
}

func (h *Handlers) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// reclaimStale moves an in-flight tenant whose run has gone quiet for
// longer than StaleAfter, and whose lock nobody holds, back to failed,
// recording why, so the caller's retry or delete can proceed. Returns the
// possibly updated tenant; false means a response was written.
func (h *Handlers) reclaimStale(c *gin.Context, tenant tenantstore.Tenant) (tenantstore.Tenant, bool) {
	if h.StaleAfter <= 0 || (tenant.Status != tenantstore.StatusProvisioning && tenant.Status != tenantstore.StatusDeprovisioning) {
		return tenant, true
	}
	ctx := c.Request.Context()
	events, err := h.Store.ListEvents(ctx, tenant.TeamID, tenant.ID)
	if err != nil {
		h.Log.Error().Err(err).Msg("list tenant events")
		respondError(c, http.StatusInternalServerError, internalErrorMsg)
		return tenantstore.Tenant{}, false
	}
	last := tenant.UpdatedAt
	if n := len(events); n > 0 && events[n-1].At.After(last) {
		last = events[n-1].At
	}
	if h.now().Sub(last) < h.StaleAfter {
		return tenant, true
	}
	// Quiet is not the same as dead: a run holds the tenant's lock for its
	// whole life, so if the lock is taken the run is alive (a slow step)
	// and must not be pulled out from under it. The lock is held through
	// the reclaim so a run that starts in between waits on the runner's
	// own status check rather than racing these writes.
	release, err := h.Store.Lock(ctx, tenant.TeamID, tenant.ID)
	if errors.Is(err, tenantstore.ErrLocked) {
		return tenant, true
	}
	if err != nil {
		h.Log.Error().Err(err).Msg("probe tenant lock")
		respondError(c, http.StatusInternalServerError, internalErrorMsg)
		return tenantstore.Tenant{}, false
	}
	defer release()
	mode := provisioner.ModeProvision
	if tenant.Status == tenantstore.StatusDeprovisioning {
		mode = provisioner.ModeDeprovision
	}
	// Keyed on the row version the staleness was judged on, not just the
	// status: another request can reclaim this run and queue a replacement
	// between the event read above and the lock, and the replacement wears
	// the same in-flight status. Failing it would strand a run the caller
	// was already told had been accepted.
	at := tenantstore.VersionOf(tenant)
	if n := len(events); n > 0 && events[n-1].Seq > at.EventSeq {
		at.EventSeq = events[n-1].Seq
	}
	updated, err := h.Store.TransitionStatusIfUnchanged(ctx, tenant.TeamID, tenant.ID, []string{tenant.Status}, tenantstore.StatusFailed, at)
	if errors.Is(err, tenantstore.ErrStatusConflict) || errors.Is(err, tenantstore.ErrNotFound) {
		// Something else moved it in the meantime; proceed with what it is now.
		current, gerr := h.Store.GetTenant(ctx, tenant.TeamID, tenant.ID)
		if errors.Is(gerr, tenantstore.ErrNotFound) {
			respondError(c, http.StatusNotFound, "Tenant not found.")
			return tenantstore.Tenant{}, false
		}
		if gerr != nil {
			respondError(c, http.StatusInternalServerError, internalErrorMsg)
			return tenantstore.Tenant{}, false
		}
		return current, true
	}
	if err != nil {
		h.Log.Error().Err(err).Msg("reclaim stale tenant")
		respondError(c, http.StatusInternalServerError, internalErrorMsg)
		return tenantstore.Tenant{}, false
	}
	h.Log.Warn().Str("tenant_id", tenant.ID.String()).Str("mode", string(mode)).Time("last_activity", last).Msg("reclaimed stale run")
	reclaimed := h.event(ctx, updated, provisioner.RunStep, tenantstore.EventFailed,
		"No progress for "+h.StaleAfter.String()+"; the "+string(mode)+" run is treated as lost.",
		map[string]any{"mode": string(mode), "last_activity": last.UTC().Format(time.RFC3339)})
	if reclaimed.Seq > updated.EventSeq {
		updated.EventSeq = reclaimed.Seq
	}
	return updated, true
}

// tenantRetired reports whether the tenant has been torn down, or is being
// torn down, since this request read it.
func (h *Handlers) tenantRetired(ctx context.Context, tenant tenantstore.Tenant) (bool, error) {
	current, err := h.Store.GetTenant(ctx, tenant.TeamID, tenant.ID)
	if errors.Is(err, tenantstore.ErrNotFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return current.Status == tenantstore.StatusDeprovisioning || current.Status == tenantstore.StatusDeleted, nil
}

func (h *Handlers) modelKeyStored(ctx context.Context, tenant tenantstore.Tenant) (bool, error) {
	refs, err := h.Store.ListSecretRefs(ctx, tenant.TeamID, tenant.ID)
	if err != nil {
		return false, err
	}
	want := secrets.ModelKeyName(tenant.ModelProvider)
	for _, ref := range refs {
		if ref.Name == want {
			return true, nil
		}
	}
	return false, nil
}

// loadTenant resolves {id} within the caller's team. Deleted tenants are
// gone from the API's point of view.
func (h *Handlers) loadTenant(c *gin.Context) (tenantstore.Tenant, bool) {
	p := principalFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		respondError(c, http.StatusNotFound, "Tenant not found.")
		return tenantstore.Tenant{}, false
	}
	tenant, err := h.Store.GetTenant(c.Request.Context(), p.TeamID, id)
	if errors.Is(err, tenantstore.ErrNotFound) || (err == nil && tenant.Status == tenantstore.StatusDeleted) {
		respondError(c, http.StatusNotFound, "Tenant not found.")
		return tenantstore.Tenant{}, false
	}
	if err != nil {
		h.Log.Error().Err(err).Msg("get tenant")
		respondError(c, http.StatusInternalServerError, internalErrorMsg)
		return tenantstore.Tenant{}, false
	}
	return tenant, true
}

// queueRun moves the tenant into mode's in-flight status and starts a run.
// On any failure the response is already written and false is returned.
//
// Four steps, in an order that keeps a retry honest under races:
//  1. a probe of the tenant's run lock: a previous run that has already
//     marked the tenant failed may still be writing its last event, and a
//     run queued now would find the lock taken, exit, and leave the tenant
//     in flight with nothing behind it — so the caller is told to retry in
//     a moment instead;
//  2. a compare-and-set on the status, so of two concurrent requests
//     (delete vs retry, say) exactly one proceeds and the other sees 409;
//  3. a required intent event carrying the mode — the winner's is the
//     newest mode-bearing event by construction, and a retry reads the
//     newest one, so a failed delete can never be retried as a provision;
//  4. the trigger, whose definite failure marks the tenant failed (mode
//     included).
func (h *Handlers) queueRun(c *gin.Context, tenant tenantstore.Tenant, at tenantstore.Version, from []string, mode provisioner.Mode) (tenantstore.Tenant, bool) {
	ctx := c.Request.Context()
	inFlight := tenantstore.StatusProvisioning
	if mode == provisioner.ModeDeprovision {
		inFlight = tenantstore.StatusDeprovisioning
	}
	// Errors that are neither a conflict nor absence leave a provision
	// marked failed (mode included): a just-created tenant otherwise sits
	// in provisioning with no run behind it until the stale reclaim. A
	// delete instead gets abandonDelete — see there.
	release, err := h.Store.Lock(ctx, tenant.TeamID, tenant.ID)
	switch {
	case errors.Is(err, tenantstore.ErrLocked):
		respondError(c, http.StatusConflict, "The previous run for this tenant is still finishing. Try again in a moment.")
		return tenantstore.Tenant{}, false
	case errors.Is(err, tenantstore.ErrNotFound):
		respondError(c, http.StatusNotFound, "Tenant not found.")
		return tenantstore.Tenant{}, false
	case err != nil:
		h.Log.Error().Err(err).Str("tenant_id", tenant.ID.String()).Msg("probe tenant lock")
		// No lock: nothing of this request's has been written, and the row
		// cannot be trusted to be this request's doing.
		h.abortQueue(c, tenant, &at, mode, from, inFlight, err)
		return tenantstore.Tenant{}, false
	}
	// Held through the transition and the intent write, not just the probe:
	// a delayed execution that took the lock in between would see the new
	// in-flight status while its own intent was still the newest, pass the
	// runner's attempt check, and run in place of the attempt being queued
	// here. Released before the trigger, since the run it starts has to be
	// able to take the lock itself.
	released := false
	releaseOnce := func() {
		if !released {
			released = true
			release()
		}
	}
	defer releaseOnce()
	updated, err := h.Store.TransitionStatus(ctx, tenant.TeamID, tenant.ID, from, inFlight)
	switch {
	case errors.Is(err, tenantstore.ErrStatusConflict):
		respondError(c, http.StatusConflict, "The tenant's status changed; reload and try again.")
		return tenantstore.Tenant{}, false
	case errors.Is(err, tenantstore.ErrNotFound):
		respondError(c, http.StatusNotFound, "Tenant not found.")
		return tenantstore.Tenant{}, false
	case err != nil:
		h.Log.Error().Err(err).Str("tenant_id", tenant.ID.String()).Msg("transition tenant status")
		// The transition may have committed before the error surfaced;
		// the lock is still held, so the row is authoritative.
		h.abortQueue(c, tenant, nil, mode, from, inFlight, err)
		return tenantstore.Tenant{}, false
	}
	detail := map[string]any{"mode": string(mode)}
	intent, err := h.Store.InsertEvent(ctx, updated.TeamID, tenantstore.EventParams{
		TenantID: updated.ID, Step: stepTrigger, Status: tenantstore.EventStarted, Message: string(mode) + " run requested", Detail: provisioner.ScrubDetail(detail),
	})
	if err != nil {
		h.Log.Error().Err(err).Str("tenant_id", tenant.ID.String()).Msg("record run intent")
		// Same again: the event may have landed, which moves the row's
		// version past the one this request's transition produced.
		h.abortQueue(c, tenant, nil, mode, from, inFlight, err)
		return tenantstore.Tenant{}, false
	}
	// The version this attempt owns from here on: its transition, plus the
	// intent event it just recorded. Anything else writing the tenant
	// (a stale reclaim and the retry behind it, say) moves the row past it.
	mine := tenantstore.Version{UpdatedAt: updated.UpdatedAt, EventSeq: intent.Seq}
	releaseOnce()
	if err := h.Trigger.Trigger(ctx, updated.TeamID, updated.ID, mode, intent.Seq); err != nil {
		h.Log.Error().Err(err).Str("tenant_id", tenant.ID.String()).Str("mode", string(mode)).Msg("trigger provisioner run")
		if errors.Is(err, provisioner.ErrTriggerRejected) {
			h.failTenant(ctx, updated, mine, []string{inFlight}, stepTrigger, "The "+string(mode)+" run could not be started. Retry the tenant.", err, map[string]any{"mode": string(mode)})
			respondError(c, http.StatusBadGateway, "The "+string(mode)+" run could not be started. Retry from the tenant page.")
			return tenantstore.Tenant{}, false
		}
		// Ambiguous: the execution may exist. Marking the tenant failed
		// now would let a retry or delete race a run that is about to
		// start, so it stays in flight; if no run ever reports progress
		// the stale reclaim makes it retryable.
		h.eventIfMine(ctx, updated, mine, stepTrigger, tenantstore.EventFailed,
			"The "+string(mode)+" run's start could not be confirmed. If no progress follows, it becomes retryable after "+h.StaleAfter.String()+".",
			map[string]any{"mode": string(mode), "error": err.Error(), "ambiguous": true})
		respondError(c, http.StatusBadGateway, "The "+string(mode)+" run's start could not be confirmed; the tenant stays in progress. Check back shortly.")
		return tenantstore.Tenant{}, false
	}
	h.eventIfMine(ctx, updated, mine, stepTrigger, tenantstore.EventOK, string(mode)+" run queued", detail)
	return updated, true
}

// eventIfMine records a trigger's outcome only while this attempt still
// owns the tenant. A trigger call that outlived StaleAfter comes back to a
// tenant something else has re-queued; appending to it would move the row's
// version past the one the replacement holds, and the replacement's own
// bookkeeping would then decline to touch the tenant it owns.
func (h *Handlers) eventIfMine(ctx context.Context, tenant tenantstore.Tenant, at tenantstore.Version, step, status, message string, detail map[string]any) {
	dctx, cancel := detached(ctx)
	defer cancel()
	current, err := h.Store.GetTenant(dctx, tenant.TeamID, tenant.ID)
	if err != nil {
		h.Log.Error().Err(err).Str("tenant_id", tenant.ID.String()).Msg("confirm this attempt still owns the tenant")
		return
	}
	if tenantstore.VersionOf(current) != at {
		h.Log.Warn().Str("tenant_id", tenant.ID.String()).Str("step", step).
			Msg("a later attempt owns this tenant; dropping this outcome event")
		return
	}
	h.eventIn(dctx, tenant, step, status, message, detail)
}

// abortQueue handles a queue attempt that failed before the run's intent
// event was durable.
//
// A provision is marked failed so it can be retried. A delete is not: the
// mode lives only in that intent event, so a tenant marked failed without
// one reads as a failed provision, and a retry would rebuild the stack the
// caller asked to tear down. Marking it failed would also lean on a
// failed-event write to carry the mode — the very thing that just broke.
// The delete simply has not happened, so the tenant goes back where it was
// and the caller issues it again.
// at is the row version this request owns. A nil at means the caller still
// holds the tenant's run lock and the failing write may have committed
// anyway — a connection dropped on the way back — so the row itself decides
// what to undo rather than what the request believed it wrote. Without the
// lock that re-read is unsafe: a concurrent request may have put the tenant
// in the same status for its own reasons, and this one would undo its work.
func (h *Handlers) abortQueue(c *gin.Context, tenant tenantstore.Tenant, at *tenantstore.Version, mode provisioner.Mode, from []string, inFlight string, cause error) {
	ctx := c.Request.Context()
	dctx, cancel := detached(ctx)
	defer cancel()

	row, version := tenant, tenantstore.Version{}
	switch {
	case at != nil:
		version = *at
	default:
		current, gerr := h.Store.GetTenant(dctx, tenant.TeamID, tenant.ID)
		if gerr != nil {
			h.Log.Error().Err(gerr).Str("tenant_id", tenant.ID.String()).Msg("re-read tenant to undo a queue attempt")
			current = tenant
		}
		row, version = current, tenantstore.VersionOf(current)
	}

	if mode != provisioner.ModeDeprovision {
		// The transition may or may not have landed, so either side of it
		// is a status this request owns; the version pins which attempt.
		owned := append(append([]string{}, from...), inFlight)
		h.failTenant(ctx, row, version, owned, stepTrigger, "The "+string(mode)+" run could not be queued. Retry the tenant.", cause, map[string]any{"mode": string(mode)})
		respondError(c, http.StatusInternalServerError, internalErrorMsg)
		return
	}
	// Keyed on the version as well as the status: a concurrent delete that
	// has already moved the tenant into the same in-flight status owns it
	// now, and reverting would silently cancel a delete that was accepted.
	// When this request's own transition never happened, nothing matches
	// and nothing changes, which is the desired end state either way.
	if _, rerr := h.Store.TransitionStatusIfUnchanged(dctx, tenant.TeamID, tenant.ID, []string{inFlight}, tenant.Status, version); rerr != nil && !errors.Is(rerr, tenantstore.ErrStatusConflict) && !errors.Is(rerr, tenantstore.ErrNotFound) {
		h.Log.Error().Err(rerr).Str("tenant_id", tenant.ID.String()).Msg("revert delete transition")
	}
	respondError(c, http.StatusInternalServerError, "The delete could not be recorded. Try again.")
}

// failTenant records why and moves the tenant to failed so it can be
// retried. Both writes run detached from the request: the failure being
// recorded may be the caller having gone away, and a tenant left in an
// in-flight status with no run behind it could never be retried.
//
// The status write comes first and is a compare-and-set on both the
// statuses this request owns and the row version it last saw. A slow
// trigger call can outlive StaleAfter, by which point the tenant may have
// been reclaimed and re-queued — as a teardown, or as a second provision
// attempt wearing the same status. Overwriting either would strand the run
// behind it, and the mode-bearing event would send the next retry down the
// wrong plan. A request that has been overtaken records nothing.
func (h *Handlers) failTenant(ctx context.Context, tenant tenantstore.Tenant, at tenantstore.Version, from []string, step, message string, cause error, detail map[string]any) {
	dctx, cancel := detached(ctx)
	defer cancel()
	updated, err := h.Store.TransitionStatusIfUnchanged(dctx, tenant.TeamID, tenant.ID, from, tenantstore.StatusFailed, at)
	switch {
	case errors.Is(err, tenantstore.ErrStatusConflict), errors.Is(err, tenantstore.ErrNotFound):
		h.Log.Warn().Str("tenant_id", tenant.ID.String()).Str("step", step).
			Msg("tenant moved on while this request was failing; leaving it to its current owner")
		return
	case err != nil:
		// The status could not be read or written at all; record the
		// failure anyway so the event log says what happened.
		h.Log.Error().Err(err).Str("tenant_id", tenant.ID.String()).Msg("mark tenant failed")
		updated = tenant
	}
	if detail == nil {
		detail = map[string]any{}
	}
	detail["error"] = cause.Error()
	h.eventIn(dctx, updated, step, tenantstore.EventFailed, message, detail)
}

// event appends an event on its own bookkeeping deadline and returns what
// was written; a failed write returns the zero Event, whose Seq leaves the
// tenant's version where it was.
func (h *Handlers) event(ctx context.Context, tenant tenantstore.Tenant, step, status, message string, detail map[string]any) tenantstore.Event {
	dctx, cancel := detached(ctx)
	defer cancel()
	return h.eventIn(dctx, tenant, step, status, message, detail)
}

// eventIn appends an event under a deadline the caller owns.
func (h *Handlers) eventIn(ctx context.Context, tenant tenantstore.Tenant, step, status, message string, detail map[string]any) tenantstore.Event {
	p := tenantstore.EventParams{TenantID: tenant.ID, Step: step, Status: status, Message: message}
	if detail != nil {
		p.Detail = provisioner.ScrubDetail(detail)
	}
	e, err := h.Store.InsertEvent(ctx, tenant.TeamID, p)
	if err != nil {
		h.Log.Error().Err(err).Str("tenant_id", tenant.ID.String()).Str("step", step).Msg("record tenant event")
	}
	return e
}

// versionAfter is the row's version once ev has been recorded against it.
func versionAfter(t tenantstore.Tenant, ev tenantstore.Event) tenantstore.Version {
	v := tenantstore.VersionOf(t)
	if ev.Seq > v.EventSeq {
		v.EventSeq = ev.Seq
	}
	return v
}

// bookkeepingTimeout bounds writes that must land after the request that
// caused them is gone.
const bookkeepingTimeout = 10 * time.Second

func detached(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), bookkeepingTimeout)
}

// lastRunMode reads the mode of the most recently requested run so a retry
// resumes the plan that was last asked for; a tenant with no run yet
// provisions. queueRun writes the trigger event synchronously after winning
// the status transition, so the newest one is the winner's.
//
// Only an attempt's opening event counts. A superseded request's outcome
// events land whenever its trigger call finally returns, which can be long
// after a delete has taken the tenant over; treating one of those as the
// latest intent would retry a teardown as a provision and rebuild what the
// caller deleted.
func lastRunMode(events []tenantstore.Event) provisioner.Mode {
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		if e.Status != tenantstore.EventStarted || len(e.Detail) == 0 {
			continue
		}
		if e.Step != provisioner.RunStep && e.Step != stepTrigger {
			continue
		}
		var detail struct {
			Mode string `json:"mode"`
		}
		if json.Unmarshal(e.Detail, &detail) != nil {
			continue
		}
		if mode, ok := provisioner.ParseMode(detail.Mode); ok {
			return mode
		}
	}
	return provisioner.ModeProvision
}
