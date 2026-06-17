package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/billing"
)

const maxBillingRollupBackfillHours = 24 * 366

type billingRollupBackfillRequest struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type billingRollupBackfillResponse struct {
	Start                   time.Time `json:"start"`
	End                     time.Time `json:"end"`
	Hours                   int       `json:"hours"`
	JobsEnqueuedOrRefreshed int64     `json:"jobs_enqueued_or_refreshed"`
}

func (h *Handlers) BackfillBillingRollups(c *gin.Context) {
	var req billingRollupBackfillRequest
	if err := bindJSONStrict(c, &req); err != nil {
		respondErrorMsg(c, "bad_request", "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	start := req.Start.UTC()
	end := req.End.UTC()
	if start.IsZero() || end.IsZero() {
		respondErrorMsg(c, "bad_request", "start and end are required", http.StatusBadRequest)
		return
	}
	if !start.Equal(start.Truncate(time.Hour)) || !end.Equal(end.Truncate(time.Hour)) {
		respondErrorMsg(c, "bad_request", "start and end must be aligned to hour boundaries", http.StatusBadRequest)
		return
	}
	if !end.After(start) {
		respondErrorMsg(c, "bad_request", "end must be after start", http.StatusBadRequest)
		return
	}
	hours := int(end.Sub(start) / time.Hour)
	if hours > maxBillingRollupBackfillHours {
		respondErrorMsg(c, "bad_request", "backfill range is too large", http.StatusBadRequest)
		return
	}
	if h.Pool == nil {
		log.Error().Msg("BackfillBillingRollups called without db pool")
		respondError(c, ErrInternal)
		return
	}

	result, err := billing.EnqueueHourlyRollupBackfill(c.Request.Context(), h.Pool, start, end)
	if err != nil {
		log.Error().Err(err).Time("start", start).Time("end", end).Msg("enqueue billing rollup backfill failed")
		respondError(c, ErrInternal)
		return
	}

	c.JSON(http.StatusAccepted, billingRollupBackfillResponse{
		Start:                   result.Start,
		End:                     result.End,
		Hours:                   result.Hours,
		JobsEnqueuedOrRefreshed: result.JobsEnqueuedOrRefreshed,
	})
}
