//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/google/uuid"
)

func BenchmarkFreeShapeAdmission(b *testing.B) {
	ctx := b.Context()
	team := uuid.New()
	if _, err := testPool.Exec(ctx, `INSERT INTO team(id,name) VALUES($1,$2)`, team, "shape-benchmark-"+team.String()); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _, _ = testPool.Exec(context.Background(), `DELETE FROM team WHERE id=$1`, team) })
	if _, err := testPool.Exec(ctx, `INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason)
	 VALUES($1,'free','free','{}','{"max_concurrent":1,"max_vcpu":1,"max_memory_mib":1024,"max_disk_mib":4096}',clock_timestamp(),'migration','admission measurement')`, team); err != nil {
		b.Fatal(err)
	}
	var execution, guard []float64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tx, err := testPool.Begin(ctx)
		if err != nil {
			b.Fatal(err)
		}
		var raw []byte
		err = tx.QueryRow(ctx, `EXPLAIN(ANALYZE,FORMAT JSON) INSERT INTO sandbox(team_id,name,status,host_id,vcpu_count,memory_mib,disk_mib)
		 VALUES($1,$2,'starting',$3,1,1024,4096)`, team, "shape-benchmark-"+uuid.NewString(), testDefaultHostID).Scan(&raw)
		_ = tx.Rollback(ctx)
		if err != nil {
			b.Fatal(err)
		}
		var plan []struct {
			Execution float64 `json:"Execution Time"`
			Triggers  []struct {
				Name string  `json:"Trigger Name"`
				Time float64 `json:"Time"`
			} `json:"Triggers"`
		}
		if err := json.Unmarshal(raw, &plan); err != nil {
			b.Fatal(err)
		}
		execution = append(execution, plan[0].Execution)
		for _, trigger := range plan[0].Triggers {
			if trigger.Name == "sandbox_free_shape" {
				guard = append(guard, trigger.Time)
			}
		}
	}
	b.StopTimer()
	if len(guard) != b.N {
		b.Fatal("Free shape trigger measurement missing")
	}
	for name, samples := range map[string][]float64{"sql": execution, "guard": guard} {
		slices.Sort(samples)
		b.ReportMetric(samples[len(samples)/2], name+"-p50-ms")
		b.ReportMetric(samples[(len(samples)-1)*95/100], name+"-p95-ms")
	}
}
