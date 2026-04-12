package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// HostHeartbeat handles POST /internal/hosts/:host_id/heartbeat.
// VMD calls this every 30s to prove liveness. The control plane updates
// last_heartbeat_at; a background detector marks hosts unhealthy after
// 2 minutes of silence.
func (h *Handlers) HostHeartbeat(c *gin.Context) {
	hostID := c.Param("host_id")
	if hostID == "" {
		respondErrorMsg(c, "bad_request", "host_id is required", http.StatusBadRequest)
		return
	}

	if err := h.DB.UpdateHostHeartbeat(c.Request.Context(), hostID); err != nil {
		log.Error().Err(err).Str("host_id", hostID).Msg("UpdateHostHeartbeat failed")
		respondError(c, ErrInternal)
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
