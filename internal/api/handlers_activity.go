package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

// activitySortColumns is the sort allow-list for GET /activity. created_at is
// the only sortable dimension the audit log exposes today; parsePageParams
// rejects anything else with a 400.
var activitySortColumns = []string{"created_at"}

// activityResponse is the JSON shape of one audit-log row. Field names and
// nullability mirror the console's ActivityResponse type so existing audit
// table rows render unchanged.
type activityResponse struct {
	ID          string          `json:"id"`
	SandboxID   *string         `json:"sandbox_id"`
	TemplateID  *string         `json:"template_id"`
	SecretID    *string         `json:"secret_id"`
	ActorID     *string         `json:"actor_id"`
	Category    string          `json:"category"`
	Action      string          `json:"action"`
	Status      *string         `json:"status"`
	SandboxName *string         `json:"sandbox_name"`
	SecretName  *string         `json:"secret_name"`
	DurationMs  *int32          `json:"duration_ms"`
	Error       *string         `json:"error"`
	Metadata    json.RawMessage `json:"metadata"`
	CreatedAt   time.Time       `json:"created_at"`
}

func activityToResponse(a db.Activity) activityResponse {
	// metadata is arbitrary jsonb — pass it through verbatim rather than
	// coercing to a fixed shape. NULL/empty renders as `{}` so the console
	// always gets an object, never `null`.
	meta := json.RawMessage(a.Metadata)
	if len(meta) == 0 {
		meta = json.RawMessage("{}")
	}
	return activityResponse{
		ID:          a.ID.String(),
		SandboxID:   nullableUUIDString(a.SandboxID),
		TemplateID:  nullableUUIDString(a.TemplateID),
		SecretID:    nullableUUIDString(a.SecretID),
		ActorID:     nullableUUIDString(a.ActorID),
		Category:    a.Category,
		Action:      a.Action,
		Status:      a.Status,
		SandboxName: a.SandboxName,
		SecretName:  a.SecretName,
		DurationMs:  a.DurationMs,
		Error:       a.Error,
		Metadata:    meta,
		CreatedAt:   a.CreatedAt,
	}
}

// nullableUUIDString renders a nullable pgtype.UUID as a *string for JSON
// (null when the column is NULL), matching how the console consumes
// sandbox_id / secret_id.
func nullableUUIDString(u pgtype.UUID) *string {
	if !u.Valid {
		return nil
	}
	s := uuid.UUID(u.Bytes).String()
	return &s
}

// parseTimeFilter parses an optional RFC3339 timestamp query param into a
// pgtype.Timestamptz. Empty → NULL (filter off); unparseable → error so the
// handler can respond 400.
func parseTimeFilter(v string) (pgtype.Timestamptz, error) {
	if v == "" {
		return pgtype.Timestamptz{}, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return pgtype.Timestamptz{}, err
	}
	return pgtype.Timestamptz{Time: t, Valid: true}, nil
}

// ListActivity serves the paginated, filterable team audit log backing the
// console Audit Logs page. Mirrors ListSandboxes: parsePageParams + optional
// filters (category, status, q substring, created_at window) + resolveTotal +
// X-Total-Count, returning a bare JSON array so omitting `limit` yields the
// full list.
func (h *Handlers) ListActivity(c *gin.Context) {
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSandboxRead(c, teamID) {
		return
	}

	pg, err := parsePageParams(c, activitySortColumns, "created_at")
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	// The activity table is an unbounded, ever-growing event log — unlike the
	// bounded sandbox/template lists (capped by quota, few-per-team, and
	// filtered to non-destroyed rows). It also has no pre-existing unpaginated
	// callers to preserve. So an omitted `limit` defaults to maxPageSize
	// instead of "return everything", so a raw GET /activity can't force a
	// full-history scan + serialize. (Do NOT lift this to match the sandbox
	// list — that list is bounded; this one is not.)
	if pg.Limit == nil {
		lim := int64(maxPageSize)
		pg.Limit = &lim
	}

	createdAfter, err := parseTimeFilter(c.Query("start"))
	if err != nil {
		respondErrorMsg(c, "bad_request", "start must be an RFC3339 timestamp", http.StatusBadRequest)
		return
	}
	createdBefore, err := parseTimeFilter(c.Query("end"))
	if err != nil {
		respondErrorMsg(c, "bad_request", "end must be an RFC3339 timestamp", http.StatusBadRequest)
		return
	}

	category := nullableStr(c.Query("category"))
	statusFilter := nullableStr(c.Query("status"))
	search := searchTerm(c.Query("q"))

	ctx := c.Request.Context()
	rows, err := h.DB.ListActivityByTeamPaged(ctx, db.ListActivityByTeamPagedParams{
		TeamID:        teamID,
		Category:      category,
		Status:        statusFilter,
		Search:        search,
		CreatedAfter:  createdAfter,
		CreatedBefore: createdBefore,
		SortBy:        pg.SortBy,
		SortDir:       pg.SortDir,
		RowOffset:     pg.Offset,
		RowLimit:      pg.Limit,
	})
	if err != nil {
		log.Error().Err(err).Msg("DB ListActivityByTeamPaged failed")
		respondError(c, ErrInternal)
		return
	}

	total, err := resolveTotal(pg, len(rows), func() (int64, error) {
		return h.DB.CountActivityByTeamPaged(ctx, db.CountActivityByTeamPagedParams{
			TeamID:        teamID,
			Category:      category,
			Status:        statusFilter,
			Search:        search,
			CreatedAfter:  createdAfter,
			CreatedBefore: createdBefore,
		})
	})
	if err != nil {
		log.Error().Err(err).Msg("DB CountActivityByTeamPaged failed")
		respondError(c, ErrInternal)
		return
	}
	c.Header("X-Total-Count", strconv.FormatInt(total, 10))

	out := make([]activityResponse, len(rows))
	for i, a := range rows {
		out[i] = activityToResponse(a)
	}
	c.JSON(http.StatusOK, out)
}
