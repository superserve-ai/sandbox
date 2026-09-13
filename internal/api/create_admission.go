package api

import (
	"context"
	"fmt"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

type excludingScheduler interface {
	SelectHostExcluding(context.Context, []string, string) (string, uint64, error)
}

// This applies only to this request's unactivated CREATE and only after a
// definitive pre-boot refusal, never after an ambiguous transport retry.
func (h *Handlers) reassignRefusedCreate(ctx context.Context, sandbox db.Sandbox, caps []string, refusal error, retried bool) (string, VMDClient, error) {
	if retried || !vmdclient.IsAdmissionRefusal(refusal) {
		return "", nil, fmt.Errorf("create boot outcome is not safe to re-place")
	}
	scheduler, ok := h.Scheduler.(excludingScheduler)
	if !ok {
		return "", nil, fmt.Errorf("no alternate admission-aware scheduler")
	}
	id, _, err := scheduler.SelectHostExcluding(ctx, caps, sandbox.HostID)
	if err != nil || id == "" || id == sandbox.HostID {
		return "", nil, fmt.Errorf("no alternative host available")
	}
	eligible, err := h.hostHasCapabilitiesCached(ctx, id, caps)
	if err != nil || !eligible {
		return "", nil, fmt.Errorf("alternative host is not eligible")
	}
	client, err := h.vmdForHost(ctx, id)
	if err != nil {
		return "", nil, err
	}
	changed, err := h.DB.ReassignRejectedCreateHost(ctx, db.ReassignRejectedCreateHostParams{ID: sandbox.ID, TeamID: sandbox.TeamID, OldHostID: sandbox.HostID, NewHostID: id})
	if err != nil {
		return "", nil, err
	}
	if changed != 1 {
		return "", nil, fmt.Errorf("create no longer eligible for pre-boot reassignment")
	}
	return id, client, nil
}
