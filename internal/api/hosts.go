package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

// Bounds on the heartbeat capability advertisement. Real advertisements are a
// handful of short well-known strings; anything past these bounds is a broken
// or hostile sender and is rejected rather than stored.
const (
	maxHostCapabilities     = 32
	maxHostCapabilityLength = 64
)

// hostHeartbeatRequest is the optional JSON body of a heartbeat. Older vmd
// builds POST an empty body — that decodes to no capabilities, which is
// exactly right: a build that predates the field enforces none of them.
type hostHeartbeatRequest struct {
	Capabilities []string `json:"capabilities"`
}

// HostHeartbeat handles POST /internal/hosts/:host_id/heartbeat.
// VMD calls this every 30s to prove liveness. The control plane updates
// last_heartbeat_at; a background detector marks hosts unhealthy after
// 2 minutes of silence. If the host was previously marked unhealthy, the
// heartbeat automatically re-activates it (recovery from transient outage).
//
// The body carries the host's data-plane capability advertisement, REPLACED
// on every beat so the row always reflects the currently running binary: a
// rollback stops advertising and the host immediately stops qualifying for
// strict-preview sandboxes.
func (h *Handlers) HostHeartbeat(c *gin.Context) {
	hostID := c.Param("host_id")
	if hostID == "" {
		respondErrorMsg(c, "bad_request", "host_id is required", http.StatusBadRequest)
		return
	}

	var req hostHeartbeatRequest
	if c.Request.ContentLength != 0 {
		if err := bindJSONStrict(c, &req); err != nil {
			respondErrorMsg(c, "bad_request", "Invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if len(req.Capabilities) > maxHostCapabilities {
		respondErrorMsg(c, "bad_request", "too many capabilities", http.StatusBadRequest)
		return
	}
	capabilities := make([]string, 0, len(req.Capabilities))
	for _, capability := range req.Capabilities {
		if capability == "" || len(capability) > maxHostCapabilityLength {
			respondErrorMsg(c, "bad_request", "capability entries must be non-empty and short", http.StatusBadRequest)
			return
		}
		capabilities = append(capabilities, capability)
	}

	host, err := h.DB.UpdateHostHeartbeat(c.Request.Context(), db.UpdateHostHeartbeatParams{
		ID:           hostID,
		Capabilities: capabilities,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			respondErrorMsg(c, "not_found", "host not found", http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("host_id", hostID).Msg("UpdateHostHeartbeat failed")
		respondError(c, ErrInternal)
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": host.Status})
}
