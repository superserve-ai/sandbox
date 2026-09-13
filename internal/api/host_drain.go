package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

func (h *Handlers) hostAdmissionClient(ctx context.Context, hostID string) (vmdclient.HostAdmissionClient, error) {
	client, err := h.vmdForHost(ctx, hostID)
	if err != nil {
		return nil, err
	}
	admission, ok := client.(vmdclient.HostAdmissionClient)
	if !ok {
		return nil, fmt.Errorf("host admission protocol unavailable; upgrade and enroll the host first")
	}
	return admission, nil
}

func (h *Handlers) transitionHostAdmission(c *gin.Context, hostID, desired string) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	client, err := h.hostAdmissionClient(ctx, hostID)
	if err != nil {
		respondErrorMsg(c, "conflict", err.Error(), http.StatusConflict)
		return
	}
	current, err := client.HostAdmission(ctx, 0, false)
	if err != nil || (desired == "active" && !current.Ready) {
		respondErrorMsg(c, "conflict", "host admission preflight unavailable or reconciliation incomplete", http.StatusConflict)
		return
	}
	host, err := h.DB.PrepareHostAdmission(ctx, db.PrepareHostAdmissionParams{ID: hostID, Status: desired, HeartbeatAfter: pgtype.Timestamptz{Time: time.Now().Add(-heartbeatTimeout), Valid: true}})
	if err == pgx.ErrNoRows {
		if _, lookupErr := h.DB.GetHost(ctx, hostID); lookupErr == pgx.ErrNoRows {
			respondErrorMsg(c, "not_found", "host not found", http.StatusNotFound)
			return
		}
		respondErrorMsg(c, "conflict", "host heartbeat stale", http.StatusConflict)
		return
	}
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	if h.Scheduler != nil {
		h.Scheduler.Invalidate()
	}
	state, err := client.HostAdmission(ctx, host.AdmissionRevision, desired == "draining")
	if err != nil {
		respondErrorMsg(c, "conflict", "directory status recorded but host fence unconfirmed; retry the transition, do not power off", http.StatusConflict)
		return
	}
	latest, err := h.DB.GetHost(ctx, hostID)
	if err != nil || latest.AdmissionRevision != host.AdmissionRevision || latest.Status != desired || state.Revision != host.AdmissionRevision || state.Closed != (desired == "draining") {
		respondErrorMsg(c, "conflict", "host admission transition superseded; inspect current state", http.StatusConflict)
		return
	}
	log.Info().Str("host_id", host.ID).Str("status", host.Status).Int64("admission_revision", host.AdmissionRevision).Msg("operator host admission transition acknowledged")
	c.JSON(http.StatusOK, gin.H{"id": host.ID, "status": host.Status, "admission": state})
}

func (h *Handlers) HostDrainStatus(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	id := c.Param("host_id")
	host, err := h.DB.GetHost(ctx, id)
	if err == pgx.ErrNoRows {
		respondErrorMsg(c, "not_found", "host not found", http.StatusNotFound)
		return
	}
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	counts, err := h.DB.HostOwnershipCounts(ctx, id)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	blockers := []string{}
	var state vmdclient.HostAdmissionState
	client, err := h.hostAdmissionClient(ctx, id)
	if err == nil {
		state, err = client.HostAdmission(ctx, 0, false)
	}
	fenced := err == nil && host.Status == "draining" && state.Closed && state.Revision == host.AdmissionRevision
	if !fenced {
		blockers = append(blockers, "placement fence is unconfirmed")
	}
	if !state.Ready {
		blockers = append(blockers, "host reconciliation is incomplete")
	}
	if state.Charged != 0 || state.PendingBoots != 0 {
		blockers = append(blockers, "host has charged or pending work")
	}
	for _, count := range counts {
		if count.Count > 0 {
			blockers = append(blockers, fmt.Sprintf("%s ownership: %d", count.Status, count.Count))
		}
	}
	latest, readErr := h.DB.GetHost(ctx, id)
	if readErr != nil || latest.AdmissionRevision != host.AdmissionRevision || latest.Status != host.Status {
		fenced = false
		blockers = append(blockers, "admission changed during observation")
	}
	// Database counts and the admission ledger cannot certify orphan processes,
	// unfinished backups or sole-copy template dependencies. Never promote this
	// progress report into automatic power-off authorization.
	blockers = append(blockers, "local orphan, stream, backup and artifact audit required before power off")
	c.JSON(http.StatusOK, gin.H{"id": id, "status": host.Status, "revision": host.AdmissionRevision, "observed_at": time.Now().UTC(), "placement_fenced": fenced, "admission": state, "ownership": counts, "safe_to_power_off": false, "blockers": blockers})
}
