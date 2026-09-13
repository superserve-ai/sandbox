package qm

import (
	"context"
	"encoding/json"
	"errors"
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
	stepTrigger  = "trigger"

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
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxCreateBodyBytes)
	if err := json.NewDecoder(c.Request.Body).Decode(&req); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			respondError(c, http.StatusRequestEntityTooLarge, "Request body is too large.")
			return
		}
		respondError(c, http.StatusBadRequest, "Request body must be a JSON object.")
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
		h.failTenant(ctx, tenant, stepModelKey, "The model key could not be stored. Delete this tenant and create it again.", err, nil)
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
			h.failTenant(ctx, tenant, stepModelKey, "The model key reference could not be confirmed. Retry the tenant, or delete it and create it again.", err, nil)
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
			h.failTenant(ctx, tenant, stepModelKey, "The model key reference could not be recorded. Delete this tenant and create it again.", err, nil)
			respondError(c, http.StatusInternalServerError, internalErrorMsg)
			return
		}
	}
	h.event(ctx, tenant, stepModelKey, tenantstore.EventOK, keyName+" stored", nil)

	queued, ok := h.queueRun(c, tenant, []string{tenantstore.StatusProvisioning}, provisioner.ModeProvision)
	if !ok {
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"tenant": toTenantResponse(queued)})
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
	queued, ok := h.queueRun(c, tenant, []string{tenantstore.StatusReady, tenantstore.StatusFailed}, provisioner.ModeDeprovision)
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
	queued, ok := h.queueRun(c, tenant, []string{tenantstore.StatusFailed}, mode)
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
	updated, err := h.Store.TransitionStatus(ctx, tenant.TeamID, tenant.ID, []string{tenant.Status}, tenantstore.StatusFailed)
	if errors.Is(err, tenantstore.ErrStatusConflict) {
		// Something else moved it in the meantime; proceed with what it is now.
		current, gerr := h.Store.GetTenant(ctx, tenant.TeamID, tenant.ID)
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
	h.event(ctx, updated, provisioner.RunStep, tenantstore.EventFailed,
		"No progress for "+h.StaleAfter.String()+"; the "+string(mode)+" run is treated as lost.",
		map[string]any{"mode": string(mode), "last_activity": last.UTC().Format(time.RFC3339)})
	return updated, true
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
func (h *Handlers) queueRun(c *gin.Context, tenant tenantstore.Tenant, from []string, mode provisioner.Mode) (tenantstore.Tenant, bool) {
	ctx := c.Request.Context()
	inFlight := tenantstore.StatusProvisioning
	if mode == provisioner.ModeDeprovision {
		inFlight = tenantstore.StatusDeprovisioning
	}
	// Errors that are neither a conflict nor absence mark the tenant
	// failed (mode included): a just-created tenant otherwise sits in
	// provisioning with no run behind it until the stale reclaim.
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
		h.failTenant(ctx, tenant, stepTrigger, "The "+string(mode)+" run could not be queued. Retry the tenant.", err, map[string]any{"mode": string(mode)})
		respondError(c, http.StatusInternalServerError, internalErrorMsg)
		return tenantstore.Tenant{}, false
	}
	// Released before the trigger: the run it starts must be able to take
	// the lock itself.
	release()
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
		h.failTenant(ctx, tenant, stepTrigger, "The "+string(mode)+" run could not be queued. Retry the tenant.", err, map[string]any{"mode": string(mode)})
		respondError(c, http.StatusInternalServerError, internalErrorMsg)
		return tenantstore.Tenant{}, false
	}
	detail := map[string]any{"mode": string(mode)}
	if _, err := h.Store.InsertEvent(ctx, updated.TeamID, tenantstore.EventParams{
		TenantID: updated.ID, Step: stepTrigger, Status: tenantstore.EventStarted, Message: string(mode) + " run requested", Detail: provisioner.ScrubDetail(detail),
	}); err != nil {
		h.Log.Error().Err(err).Str("tenant_id", tenant.ID.String()).Msg("record run intent")
		if mode == provisioner.ModeDeprovision {
			// The delete has not happened: put the tenant back where it
			// was so the caller simply issues it again. Marking it failed
			// would rely on a failed-event write (the very thing that just
			// broke) to carry the mode, and a retry without it would
			// provision instead of deleting.
			dctx, cancel := detached(ctx)
			if _, rerr := h.Store.TransitionStatus(dctx, updated.TeamID, updated.ID, []string{inFlight}, tenant.Status); rerr != nil {
				h.Log.Error().Err(rerr).Str("tenant_id", tenant.ID.String()).Msg("revert delete transition")
			}
			cancel()
			respondError(c, http.StatusInternalServerError, "The delete could not be recorded. Try again.")
			return tenantstore.Tenant{}, false
		}
		h.failTenant(ctx, updated, stepTrigger, "The "+string(mode)+" request could not be recorded. Retry the tenant.", err, map[string]any{"mode": string(mode)})
		respondError(c, http.StatusInternalServerError, internalErrorMsg)
		return tenantstore.Tenant{}, false
	}
	if err := h.Trigger.Trigger(ctx, updated.TeamID, updated.ID, mode); err != nil {
		h.Log.Error().Err(err).Str("tenant_id", tenant.ID.String()).Str("mode", string(mode)).Msg("trigger provisioner run")
		if errors.Is(err, provisioner.ErrTriggerRejected) {
			h.failTenant(ctx, updated, stepTrigger, "The "+string(mode)+" run could not be started. Retry the tenant.", err, map[string]any{"mode": string(mode)})
			respondError(c, http.StatusBadGateway, "The "+string(mode)+" run could not be started. Retry from the tenant page.")
			return tenantstore.Tenant{}, false
		}
		// Ambiguous: the execution may exist. Marking the tenant failed
		// now would let a retry or delete race a run that is about to
		// start, so it stays in flight; if no run ever reports progress
		// the stale reclaim makes it retryable.
		h.event(ctx, updated, stepTrigger, tenantstore.EventFailed,
			"The "+string(mode)+" run's start could not be confirmed. If no progress follows, it becomes retryable after "+h.StaleAfter.String()+".",
			map[string]any{"mode": string(mode), "error": err.Error(), "ambiguous": true})
		respondError(c, http.StatusBadGateway, "The "+string(mode)+" run's start could not be confirmed; the tenant stays in progress. Check back shortly.")
		return tenantstore.Tenant{}, false
	}
	h.event(ctx, updated, stepTrigger, tenantstore.EventOK, string(mode)+" run queued", detail)
	return updated, true
}

// failTenant records why and moves the tenant to failed so it can be
// retried. Both writes run detached from the request: the failure being
// recorded may be the caller having gone away, and a tenant left in an
// in-flight status with no run behind it could never be retried.
func (h *Handlers) failTenant(ctx context.Context, tenant tenantstore.Tenant, step, message string, cause error, detail map[string]any) {
	if detail == nil {
		detail = map[string]any{}
	}
	detail["error"] = cause.Error()
	h.event(ctx, tenant, step, tenantstore.EventFailed, message, detail)
	dctx, cancel := detached(ctx)
	defer cancel()
	if _, err := h.Store.SetStatus(dctx, tenant.TeamID, tenant.ID, tenantstore.StatusFailed); err != nil {
		h.Log.Error().Err(err).Str("tenant_id", tenant.ID.String()).Msg("mark tenant failed")
	}
}

func (h *Handlers) event(ctx context.Context, tenant tenantstore.Tenant, step, status, message string, detail map[string]any) {
	p := tenantstore.EventParams{TenantID: tenant.ID, Step: step, Status: status, Message: message}
	if detail != nil {
		p.Detail = provisioner.ScrubDetail(detail)
	}
	dctx, cancel := detached(ctx)
	defer cancel()
	if _, err := h.Store.InsertEvent(dctx, tenant.TeamID, p); err != nil {
		h.Log.Error().Err(err).Str("tenant_id", tenant.ID.String()).Str("step", step).Msg("record tenant event")
	}
}

// bookkeepingTimeout bounds writes that must land after the request that
// caused them is gone.
const bookkeepingTimeout = 10 * time.Second

func detached(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), bookkeepingTimeout)
}

// lastRunMode reads the mode of the most recent run or trigger event so a
// retry resumes the plan that was last requested; a tenant with no run yet
// provisions. queueRun writes the trigger event synchronously after winning
// the status transition, so the newest mode-bearing event is the winner's.
func lastRunMode(events []tenantstore.Event) provisioner.Mode {
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		if (e.Step != provisioner.RunStep && e.Step != stepTrigger) || len(e.Detail) == 0 {
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
