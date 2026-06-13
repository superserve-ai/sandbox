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
