package api

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

// networkEvent is one row in the unified per-sandbox egress log. kind says
// whether it came from the connection log (net_flow) or the request log
// (proxy_audit); fields not applicable to a kind are omitted.
type networkEvent struct {
	Kind string `json:"kind"` // "connection" | "request"
	ID   int64  `json:"id"`
	Ts   string `json:"ts"`
	Host string `json:"host,omitempty"`

	// connection (net_flow)
	DstIP     string  `json:"dst_ip,omitempty"`
	DstPort   *int32  `json:"dst_port,omitempty"`
	Verdict   string  `json:"verdict,omitempty"`
	MatchRule *string `json:"match_rule,omitempty"`
	BytesSent *int64  `json:"bytes_sent,omitempty"`
	BytesRecv *int64  `json:"bytes_recv,omitempty"`

	// request (proxy_audit)
	Method         string  `json:"method,omitempty"`
	Path           string  `json:"path,omitempty"`
	Status         *int32  `json:"status,omitempty"`
	UpstreamStatus *int32  `json:"upstream_status,omitempty"`
	LatencyMs      *int32  `json:"latency_ms,omitempty"`
	SecretID       *string `json:"secret_id,omitempty"`
	ErrorCode      *string `json:"error_code,omitempty"`

	ts time.Time // unexported, for the merge sort
}

// networkResponse wraps the event page with cursor metadata so clients can
// paginate without inferring the cursor from the rows themselves.
type networkResponse struct {
	Data       []networkEvent `json:"data"`
	NextCursor *string        `json:"next_cursor"`
	HasMore    bool           `json:"has_more"`
}

// GetSandboxNetwork returns the unified per-sandbox egress log: connection rows
// (net_flow) and request rows (proxy_audit) merged into one time-ordered
// stream, most recent first. Supports an optional time window (since/before)
// and verdict filter; before is also the pagination cursor. The response wraps
// the rows with next_cursor and has_more.
func (h *Handlers) GetSandboxNetwork(c *gin.Context) {
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	sandboxID, err := parseSandboxID(c)
	if err != nil {
		return
	}

	if _, err := h.DB.GetSandbox(c.Request.Context(), db.GetSandboxParams{
		ID: sandboxID, TeamID: teamID,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondError(c, ErrSandboxNotFound)
			return
		}
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB GetSandbox failed")
		respondError(c, ErrInternal)
		return
	}

	limit, err := parseAuditLimit(c.Query("limit"))
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	before, err := parseNetworkTime(c.Query("before"), "before")
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	since, err := parseNetworkTime(c.Query("since"), "since")
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	verdict, err := parseNetworkVerdict(c.Query("verdict"))
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}

	ctx := c.Request.Context()
	// Fetch a full page from each source; merging then trimming to `limit`
	// yields the correct newest-first window across both.
	flows, err := h.DB.ListNetFlowEvents(ctx, db.ListNetFlowEventsParams{
		SandboxID: sandboxID, Before: before, Since: since, Verdict: verdict, RowLimit: limit,
	})
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB ListNetFlowEvents failed")
		respondError(c, ErrInternal)
		return
	}
	// Request rows carry no verdict, so a verdict filter restricts the result
	// to connection rows.
	var requests []db.ProxyAudit
	if verdict == nil {
		requests, err = h.DB.ListProxyAuditEvents(ctx, db.ListProxyAuditEventsParams{
			SandboxID: sandboxID, Before: before, Since: since, RowLimit: limit,
		})
		if err != nil {
			log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB ListProxyAuditEvents failed")
			respondError(c, ErrInternal)
			return
		}
	}

	merged := make([]networkEvent, 0, len(flows)+len(requests))
	for _, f := range flows {
		merged = append(merged, flowToEvent(f))
	}
	for _, r := range requests {
		merged = append(merged, requestToEvent(r))
	}
	sort.Slice(merged, func(i, j int) bool { return merged[i].ts.After(merged[j].ts) })

	// More rows remain if either source filled its page, or the merge held more
	// than one page's worth (the trimmed remainder is also "more").
	hasMore := len(flows) == int(limit) || len(requests) == int(limit) || len(merged) > int(limit)
	if len(merged) > int(limit) {
		merged = merged[:limit]
	}
	var nextCursor *string
	if hasMore && len(merged) > 0 {
		cursor := merged[len(merged)-1].Ts
		nextCursor = &cursor
	}
	c.JSON(http.StatusOK, networkResponse{Data: merged, NextCursor: nextCursor, HasMore: hasMore})
}

func flowToEvent(f db.NetFlow) networkEvent {
	ev := networkEvent{
		Kind:      "connection",
		ID:        f.ID,
		Ts:        f.Ts.UTC().Format(time.RFC3339Nano),
		ts:        f.Ts,
		DstIP:     f.DstIp.String(),
		DstPort:   &f.DstPort,
		Verdict:   f.Verdict,
		MatchRule: f.MatchRule,
		BytesSent: f.BytesSent,
		BytesRecv: f.BytesRecv,
	}
	if f.Host != nil {
		ev.Host = *f.Host
	}
	return ev
}

func requestToEvent(r db.ProxyAudit) networkEvent {
	ev := networkEvent{
		Kind:           "request",
		ID:             r.ID,
		Ts:             r.Ts.UTC().Format(time.RFC3339Nano),
		ts:             r.Ts,
		Host:           r.Host,
		Method:         r.Method,
		Path:           r.Path,
		Status:         &r.Status,
		UpstreamStatus: r.UpstreamStatus,
		LatencyMs:      r.LatencyMs,
		ErrorCode:      r.ErrorCode,
	}
	if r.SecretID.Valid {
		s := uuid.UUID(r.SecretID.Bytes).String()
		ev.SecretID = &s
	}
	return ev
}

// parseNetworkTime parses an RFC3339 time-window param (before/since), including
// the sub-second cursor emitted as next_cursor. Empty leaves the bound unset.
func parseNetworkTime(raw, param string) (pgtype.Timestamptz, error) {
	if raw == "" {
		return pgtype.Timestamptz{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return pgtype.Timestamptz{}, fmt.Errorf("%s must be an RFC3339 timestamp", param)
	}
	return pgtype.Timestamptz{Time: t, Valid: true}, nil
}

// parseNetworkVerdict validates the optional ?verdict= filter. Empty = no
// filter (nil); a verdict restricts results to connection rows.
func parseNetworkVerdict(raw string) (*string, error) {
	switch raw {
	case "":
		return nil, nil
	case "allowed", "blocked", "failed":
		return &raw, nil
	default:
		return nil, errors.New("verdict must be one of allowed, blocked, failed")
	}
}
