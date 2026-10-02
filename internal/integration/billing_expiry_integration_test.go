//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/billing"
)

type expiryQueryTrace struct {
	mu   sync.Mutex
	sql  string
	args []any
}

func (r *expiryQueryTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.Contains(d.SQL, "last_error='retry window expired'") {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.sql, r.args = d.SQL, append([]any(nil), d.Args...)
	}
	return ctx
}
func (*expiryQueryTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestIntegration_IncrementalExpiryBatchAndQueryCost(t *testing.T) {
	s, p := seedIncrementalPeriod(t)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := testPool.Exec(t.Context(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	// A long history and an outage backlog must not turn each claim into a
	// period-wide rewrite. Both pending and uncertain attempts can expire.
	exec(`INSERT INTO billing_export_allocation(team_id,period_start,period_end,resource_type,coverage_start,coverage_end,measured_through)
        SELECT $1,$2,$3,'cpu',n-1,n,$3 FROM generate_series(1,10000) n ORDER BY n`, p.TeamID, p.Start, p.End)
	exec(`INSERT INTO billing_export_event(id,allocation_id,identifier,idempotency_key,event_name,customer_id,
        quantity,quantity_payload,event_timestamp,source,status,first_attempt_at,attempt_count)
        SELECT gen_random_uuid(),id,'usage-'||id,'usage-'||id,'example_cpu_hours','cus_example',1,'1',
        extract(epoch FROM period_end-interval '1 second')::bigint,'export',
        CASE WHEN coverage_end>2000 THEN 'submitted' WHEN coverage_end::int%2=0 THEN 'pending' ELSE 'uncertain' END,
        now()-interval '24 hours',1 FROM billing_export_allocation
        WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End)
	leased := reserveIncrement(t, s, p, "10001")
	exec(`UPDATE billing_export_event SET first_attempt_at=now()-interval '25 hours',lease_until=now()+interval '1 hour' WHERE id=$1`, leased.ID)
	_, other := seedIncrementalPeriod(t)
	foreign := reserveIncrement(t, s, other, "1")
	exec(`UPDATE billing_export_event SET first_attempt_at=now()-interval '25 hours' WHERE id=$1`, foreign.ID)
	exec(`ANALYZE billing_export_event`)
	exec(`ANALYZE billing_export_allocation`)

	trace := &expiryQueryTrace{}
	cfg := testPool.Config()
	cfg.ConnConfig.Tracer = trace
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	s.Pool = pool
	for batch := 1; batch <= 3; batch++ {
		if event, err := s.Claim(t.Context(), p); err != nil || event != nil {
			t.Fatalf("claimed expired backlog: %+v %v", event, err)
		}
		var expired, attempts int
		if err := testPool.QueryRow(t.Context(), `SELECT count(*) FILTER (WHERE status='recovery_required'),sum(attempt_count)
            FROM billing_export_event e JOIN billing_export_allocation a ON a.id=e.allocation_id
            WHERE a.team_id=$1 AND a.period_start=$2 AND a.period_end=$3`, p.TeamID, p.Start, p.End).Scan(&expired, &attempts); err != nil {
			t.Fatal(err)
		}
		if expired != batch*100 || attempts != 10000 {
			t.Fatalf("batch %d: expired=%d attempts=%d", batch, expired, attempts)
		}
	}
	for _, event := range []*billing.ExportEvent{leased, foreign} {
		var status string
		if err := testPool.QueryRow(t.Context(), `SELECT status FROM billing_export_event WHERE id=$1`, event.ID).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status != "pending" {
			t.Fatalf("changed leased or foreign event: %s", status)
		}
	}
	if event := reserveIncrement(t, s, p, "10001"); event != nil {
		t.Fatal("expiry released reserved coverage")
	}

	trace.mu.Lock()
	sql, args := trace.sql, trace.args
	trace.mu.Unlock()
	if sql == "" {
		t.Fatal("did not capture production expiry query")
	}
	tx, err := testPool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	var raw []byte
	if err = tx.QueryRow(t.Context(), "EXPLAIN(ANALYZE,BUFFERS,FORMAT JSON) "+sql, args...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	t.Logf("expiry query with 10000 events: %s", raw)
	var plans []map[string]any
	if err = json.Unmarshal(raw, &plans); err != nil {
		t.Fatal(err)
	}
	indexed := false
	var inspect func(map[string]any)
	inspect = func(node map[string]any) {
		if node["Index Name"] == "billing_export_event_expiry" {
			indexed = true
		}
		rows, _ := node["Actual Rows"].(float64)
		removed, _ := node["Rows Removed by Filter"].(float64)
		rechecked, _ := node["Rows Removed by Index Recheck"].(float64)
		loops, _ := node["Actual Loops"].(float64)
		if (rows+removed+rechecked)*loops > 512 {
			t.Errorf("expiry batch scanned more than 512 rows: %v", node)
		}
		if children, ok := node["Plans"].([]any); ok {
			for _, child := range children {
				inspect(child.(map[string]any))
			}
		}
	}
	inspect(plans[0]["Plan"].(map[string]any))
	if !indexed {
		t.Error("expiry selection did not use the expiry index")
	}
	if err = tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}

	// Eligible work still progresses while older expired events await a batch.
	fresh := reserveIncrement(t, s, p, "10002")
	claimed, err := s.Claim(t.Context(), p)
	if err != nil || claimed == nil || claimed.ID != fresh.ID || claimed.ExportPayload != fresh.ExportPayload {
		t.Fatalf("fresh claim: %+v %v", claimed, err)
	}
	exec(`UPDATE billing_export_event SET lease_until=now()-interval '1 second' WHERE id=$1`, fresh.ID)
	retry, err := s.Claim(t.Context(), p)
	if err != nil || retry == nil || retry.ID != fresh.ID || retry.ExportPayload != fresh.ExportPayload {
		t.Fatalf("safe retry changed identity or payload: %+v %v", retry, err)
	}
	exec(`UPDATE billing_export_event SET first_attempt_at=now()-interval '23 hours',lease_until=NULL WHERE id=$1`, fresh.ID)
	if event, err := s.Claim(t.Context(), p); err != nil || event != nil {
		t.Fatalf("retried at expiry boundary behind backlog: %+v %v", event, err)
	}
}
