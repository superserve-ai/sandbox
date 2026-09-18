package api

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/abuse"
	"github.com/superserve-ai/sandbox/internal/telemetry"
	"net/http"
)

func (h *Handlers) requireComputeAllowed(c *gin.Context, team uuid.UUID, action abuse.Action) bool {
	decision := h.ComputeRestrictions.Evaluate(team, action)
	if rec, ok := currentTelemetryRecorder().(telemetry.ComputeRecorder); ok {
		rec.RecordComputeDecision(c.Request.Context(), string(action), string(decision.Mode), decision.Outcome, decision.SubjectType)
	}
	if decision.Outcome == "blocked" {
		respondErrorMsg(c, "abuse_denied", "Sandbox operation is not permitted", http.StatusForbidden)
		return false
	}
	return true
}
