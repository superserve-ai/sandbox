package api

import (
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
)

func TestFlowToEvent(t *testing.T) {
	host := "api.example.com"
	rule := "domain"
	var sent, recv int64 = 100, 200
	f := db.NetFlow{
		ID: 7, Ts: time.Unix(1000, 0).UTC(),
		Host: &host, DstIp: netip.MustParseAddr("1.2.3.4"), DstPort: 443,
		Verdict: "allowed", MatchRule: &rule, BytesSent: &sent, BytesRecv: &recv,
	}
	ev := flowToEvent(f)

	if ev.Kind != "connection" || ev.ID != 7 || ev.Host != "api.example.com" ||
		ev.DstIP != "1.2.3.4" || ev.Verdict != "allowed" {
		t.Errorf("connection fields wrong: %+v", ev)
	}
	if ev.DstPort == nil || *ev.DstPort != 443 || ev.BytesSent == nil || *ev.BytesSent != 100 {
		t.Errorf("ports/bytes wrong: %+v", ev)
	}
	// Request-only fields must stay empty.
	if ev.Method != "" || ev.Status != nil || ev.SecretID != nil {
		t.Errorf("request fields leaked onto a connection: %+v", ev)
	}
}

func TestRequestToEvent(t *testing.T) {
	secret := uuid.New()
	var upstream, latency int32 = 200, 42
	r := db.ProxyAudit{
		ID: 9, Ts: time.Unix(2000, 0).UTC(),
		SecretID: pgtype.UUID{Bytes: secret, Valid: true},
		Method:   "POST", Host: "api.anthropic.com", Path: "/v1/messages",
		Status: 200, UpstreamStatus: &upstream, LatencyMs: &latency,
	}
	ev := requestToEvent(r)

	if ev.Kind != "request" || ev.ID != 9 || ev.Method != "POST" ||
		ev.Host != "api.anthropic.com" || ev.Path != "/v1/messages" {
		t.Errorf("request fields wrong: %+v", ev)
	}
	if ev.Status == nil || *ev.Status != 200 {
		t.Errorf("status wrong: %+v", ev)
	}
	if ev.SecretID == nil || *ev.SecretID != secret.String() {
		t.Errorf("secret_id = %v, want %s", ev.SecretID, secret)
	}
	// Connection-only fields must stay empty.
	if ev.DstIP != "" || ev.Verdict != "" || ev.DstPort != nil {
		t.Errorf("connection fields leaked onto a request: %+v", ev)
	}
}

func TestRequestToEventNullSecret(t *testing.T) {
	ev := requestToEvent(db.ProxyAudit{ID: 1, Ts: time.Unix(1, 0), Status: 200})
	if ev.SecretID != nil {
		t.Errorf("secret_id should be nil when not set, got %v", *ev.SecretID)
	}
}

func TestParseNetworkTime(t *testing.T) {
	if got, err := parseNetworkTime("", "before"); err != nil || got.Valid {
		t.Errorf("empty should be (invalid, nil), got (%v, %v)", got, err)
	}
	if got, err := parseNetworkTime("2026-06-09T12:00:00Z", "since"); err != nil || !got.Valid {
		t.Errorf("valid RFC3339 should parse, got (%v, %v)", got, err)
	}
	// The next_cursor is sub-second; it must round-trip back through before/since.
	sub := "2026-06-09T12:00:00.123456789Z"
	if got, err := parseNetworkTime(sub, "before"); err != nil || !got.Valid || got.Time.Nanosecond() != 123456789 {
		t.Errorf("sub-second cursor should parse with nanos, got (%v, %v)", got, err)
	}
	if _, err := parseNetworkTime("not-a-time", "since"); err == nil {
		t.Error("garbage timestamp should error")
	}
}

func TestParseNetworkVerdict(t *testing.T) {
	if got, err := parseNetworkVerdict(""); err != nil || got != nil {
		t.Errorf("empty should be (nil, nil), got (%v, %v)", got, err)
	}
	for _, v := range []string{"allowed", "blocked", "failed"} {
		if got, err := parseNetworkVerdict(v); err != nil || got == nil || *got != v {
			t.Errorf("%q should parse, got (%v, %v)", v, got, err)
		}
	}
	if _, err := parseNetworkVerdict("bogus"); err == nil {
		t.Error("invalid verdict should error")
	}
}

func TestNetworkCursorRoundTrip(t *testing.T) {
	ts := time.Date(2026, 6, 15, 1, 2, 3, 456789000, time.UTC)
	tok := encodeNetworkCursor(ts, "request", 42)

	// Opaque token round-trips back to the same (ts, kind, id).
	c, err := parseNetworkCursor(tok)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if !c.ts.Time.Equal(ts) || c.kind == nil || *c.kind != "request" || c.id == nil || *c.id != 42 {
		t.Errorf("round-trip mismatch: ts=%v kind=%v id=%v", c.ts.Time, c.kind, c.id)
	}
}

func TestParseNetworkCursorForms(t *testing.T) {
	// Empty -> unset keyset.
	if c, err := parseNetworkCursor(""); err != nil || c.ts.Valid {
		t.Errorf("empty: %+v %v", c, err)
	}
	// RFC3339 time bound -> keyset (t, "", 0): strictly older than t.
	c, err := parseNetworkCursor("2026-06-15T01:02:03Z")
	if err != nil {
		t.Fatal(err)
	}
	if !c.ts.Valid || c.kind == nil || *c.kind != "" || c.id == nil || *c.id != 0 {
		t.Errorf("time bound -> wrong keyset: %+v", c)
	}
	// Garbage that is neither RFC3339 nor a valid token -> error.
	if _, err := parseNetworkCursor("not-a-time-or-token!!"); err == nil {
		t.Error("expected error for malformed before")
	}
}
