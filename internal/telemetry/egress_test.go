package telemetry

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestEgressMetrics(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer provider.Shutdown(context.Background())
	r, err := newEgressRecorder(provider, []attribute.KeyValue{attribute.String("host_id", "host-test")})
	if err != nil {
		t.Fatal(err)
	}
	r.Connection(1)
	r.Connection(1)
	r.Connection(-1)
	r.Reject("host")
	r.Reject("raw-sensitive-value")
	r.Duration("dns", 250*time.Millisecond, nil)
	r.Duration("dial", time.Second, context.DeadlineExceeded)
	m := collectMetrics(t, reader)
	if got := m["egress_connections_active"].Data.(metricdata.Sum[int64]).DataPoints[0].Value; got != 1 {
		t.Fatalf("active=%d", got)
	}
	for _, point := range m["egress_rejections_total"].Data.(metricdata.Sum[int64]).DataPoints {
		reason, _ := point.Attributes.Value("reason")
		if reason.AsString() != "host" && reason.AsString() != "other" {
			t.Fatalf("unbounded reason %v", reason)
		}
	}
	points := m["egress_duration_seconds"].Data.(metricdata.Histogram[float64]).DataPoints
	if len(points) != 2 {
		t.Fatalf("duration points=%d", len(points))
	}
	for _, point := range points {
		stage, _ := point.Attributes.Value("stage")
		result, _ := point.Attributes.Value("result")
		if stage.AsString() == "dns" && (point.Sum != 0.25 || result.AsString() != "success") {
			t.Fatalf("DNS duration=%+v", point)
		}
		if stage.AsString() == "dial" && result.AsString() != "timeout" {
			t.Fatal("lost timeout classification")
		}
	}
	var disabled *EgressRecorder
	disabled.Connection(1)
	disabled.Reject("host")
	disabled.Duration("dial", time.Second, nil)
	disabled.Sample(context.Background(), 1, true)
}

func TestEgressResourceAvailability(t *testing.T) {
	root := t.TempDir()
	put := func(path, data string) {
		t.Helper()
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	put("sys/net/netfilter/nf_conntrack_count", "19\n")
	put("sys/net/netfilter/nf_conntrack_max", "invalid")
	put("sys/net/ipv4/ip_local_port_range", "32768 60999\n")
	put("self/limits", "Max open files            65536                65536                files\n")
	put("self/fd/0", "")
	put("self/fd/1", "")
	put("net/sockstat", "TCP: inuse 11 orphan 0 tw 18 alloc 20 mem 1\n")
	sample := map[string]egressResource{}
	for _, v := range readEgressResources(root) {
		sample[v.name] = v
	}
	for name, want := range map[string]int64{"conntrack_count": 19, "process_fds": 2, "process_fd_limit": 65536, "ephemeral_port_range": 28232, "tcp_inuse": 11, "tcp_time_wait": 18} {
		if v := sample[name]; !v.ok || v.value != want {
			t.Errorf("%s=%+v want %d", name, v, want)
		}
	}
	if sample["conntrack_max"].ok {
		t.Fatal("malformed kernel value reported healthy")
	}
	for _, v := range readEgressResources(t.TempDir()) {
		if v.ok {
			t.Errorf("missing %s reported available", v.name)
		}
	}
}
