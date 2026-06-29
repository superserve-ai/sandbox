package api

import (
	"encoding/base64"
	"encoding/json"
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
	if !h.requireTeamSettingsRead(c, teamID) {
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
	cursor, err := parseNetworkCursor(c.Query("before"))
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
		SandboxID: sandboxID, Since: since, Verdict: verdict, RowLimit: limit,
		CursorTs: cursor.ts, CursorKind: cursor.kind, CursorID: cursor.id,
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
			SandboxID: sandboxID, Since: since, RowLimit: limit,
			CursorTs: cursor.ts, CursorKind: cursor.kind, CursorID: cursor.id,
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
	// Total order (ts, kind, id) DESC — the same order the queries and the cursor
	// use, so a page boundary inside a group of equal-ts rows resumes exactly.
	sort.Slice(merged, func(i, j int) bool {
		a, b := merged[i], merged[j]
		if !a.ts.Equal(b.ts) {
			return a.ts.After(b.ts)
		}
		if a.Kind != b.Kind {
			return a.Kind > b.Kind
		}
		return a.ID > b.ID
	})

	// More rows remain if either source filled its page, or the merge held more
	// than one page's worth (the trimmed remainder is also "more").
	hasMore := len(flows) == int(limit) || len(requests) == int(limit) || len(merged) > int(limit)
	if len(merged) > int(limit) {
		merged = merged[:limit]
	}
	var nextCursor *string
	if hasMore && len(merged) > 0 {
		last := merged[len(merged)-1]
		tok := encodeNetworkCursor(last.ts, last.Kind, last.ID)
		nextCursor = &tok
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

// networkCursor is the (ts, kind, id) keyset both list queries page against.
type networkCursor struct {
	ts   pgtype.Timestamptz
	kind *string
	id   *int64
}

// cursorToken is the opaque next_cursor payload: the total-order position of the
// last returned row. Clients treat it as opaque and echo it back via ?before=.
type cursorToken struct {
	Ts   time.Time `json:"t"`
	Kind string    `json:"k"`
	ID   int64     `json:"i"`
}

// parseNetworkCursor interprets ?before=, which is either a plain RFC3339 time
// bound (first request) or an opaque token from a prior next_cursor. Both reduce
// to a (ts, kind, id) keyset; a time bound t becomes (t, "", 0), i.e. strictly
// older than t. Empty leaves the keyset unset.
func parseNetworkCursor(raw string) (networkCursor, error) {
	if raw == "" {
		return networkCursor{}, nil
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		k, id := "", int64(0)
		return networkCursor{ts: pgtype.Timestamptz{Time: t, Valid: true}, kind: &k, id: &id}, nil
	}
	tok, ok := decodeNetworkCursor(raw)
	if !ok {
		return networkCursor{}, fmt.Errorf("before must be an RFC3339 timestamp or a cursor from next_cursor")
	}
	return networkCursor{ts: pgtype.Timestamptz{Time: tok.Ts, Valid: true}, kind: &tok.Kind, id: &tok.ID}, nil
}

func encodeNetworkCursor(ts time.Time, kind string, id int64) string {
	b, _ := json.Marshal(cursorToken{Ts: ts, Kind: kind, ID: id})
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeNetworkCursor(s string) (cursorToken, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return cursorToken{}, false
	}
	var tok cursorToken
	if err := json.Unmarshal(raw, &tok); err != nil || tok.Ts.IsZero() {
		return cursorToken{}, false
	}
	return tok, true
}

// parseNetworkTime parses an RFC3339 time-window param (since). Empty leaves the
// bound unset.
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
