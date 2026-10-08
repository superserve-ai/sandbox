package telemetry

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// EgressRecorder shares VMD's existing provider and its bounded exporter.
// Nil receivers keep admission independent of telemetry availability.
type EgressRecorder struct {
	attrs                                   []attribute.KeyValue
	active                                  metric.Int64UpDownCounter
	rejected                                metric.Int64Counter
	duration                                metric.Float64Histogram
	capacity, enforced, pressure, available metric.Int64Gauge
}

func NewEgressRecorder(recorder Recorder) (*EgressRecorder, error) {
	r, ok := recorder.(*OTelRecorder)
	if !ok {
		return nil, nil
	}
	return newEgressRecorder(r.provider, r.attrs(attribute.String("host_id", r.hostID)))
}

func newEgressRecorder(provider *sdkmetric.MeterProvider, attrs []attribute.KeyValue) (*EgressRecorder, error) {
	r := &EgressRecorder{attrs: attrs}
	m := provider.Meter(instrumentationName)
	var err error
	if r.active, err = m.Int64UpDownCounter("egress_connections_active"); err != nil {
		return nil, err
	}
	if r.rejected, err = m.Int64Counter("egress_rejections_total"); err != nil {
		return nil, err
	}
	if r.duration, err = m.Float64Histogram("egress_duration_seconds", metric.WithExplicitBucketBoundaries(latencyBuckets...)); err != nil {
		return nil, err
	}
	for name, dest := range map[string]*metric.Int64Gauge{
		"egress_connection_limit": &r.capacity, "egress_enforced": &r.enforced,
		"egress_resource_value": &r.pressure, "egress_resource_available": &r.available,
	} {
		if *dest, err = m.Int64Gauge(name); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (r *EgressRecorder) options(extra ...attribute.KeyValue) metric.MeasurementOption {
	attrs := make([]attribute.KeyValue, 0, len(r.attrs)+len(extra))
	attrs = append(attrs, r.attrs...)
	attrs = append(attrs, extra...)
	return metric.WithAttributes(attrs...)
}
func (r *EgressRecorder) Connection(delta int64) {
	if r != nil {
		r.active.Add(context.Background(), delta, r.options())
	}
}
func (r *EgressRecorder) Reject(reason string) {
	if r == nil {
		return
	}
	switch reason {
	case "host", "sandbox", "accept_error":
	default:
		reason = "other"
	}
	r.rejected.Add(context.Background(), 1, r.options(attribute.String("reason", reason)))
}
func (r *EgressRecorder) Duration(stage string, duration time.Duration, err error) {
	if r == nil {
		return
	}
	switch stage {
	case "dns", "dial":
	default:
		return
	}
	result := "success"
	if err != nil {
		result = "error"
		var ne net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
			result = "timeout"
		}
	}
	r.duration.Record(context.Background(), duration.Seconds(), r.options(attribute.String("stage", stage), attribute.String("result", result)))
}

type egressResource struct {
	name  string
	value int64
	ok    bool
}

func readEgressResources(root string) []egressResource {
	read := func(path string) string { b, _ := os.ReadFile(root + path); return string(b) }
	integer := func(name, path string) egressResource {
		n, err := strconv.ParseInt(strings.TrimSpace(read(path)), 10, 64)
		return egressResource{name, n, err == nil && n >= 0}
	}
	resources := []egressResource{
		integer("conntrack_count", "/sys/net/netfilter/nf_conntrack_count"),
		integer("conntrack_max", "/sys/net/netfilter/nf_conntrack_max"),
	}
	// Read directory entries in fixed batches; never allocate one string per FD
	// in a host-sized slice. This sampler runs once per interval, not per flow.
	var count int64
	fd, err := os.Open(root + "/self/fd")
	if err == nil {
		for {
			entries, e := fd.ReadDir(256)
			count += int64(len(entries))
			if e != nil {
				if !errors.Is(e, io.EOF) {
					err = e
				}
				break
			}
		}
		fd.Close()
	}
	resources = append(resources, egressResource{"process_fds", count, err == nil})
	limit := egressResource{name: "process_fd_limit"}
	for _, line := range strings.Split(read("/self/limits"), "\n") {
		if strings.HasPrefix(line, "Max open files") {
			f := strings.Fields(line)
			if len(f) >= 4 {
				n, e := strconv.ParseInt(f[3], 10, 64)
				limit.value = n
				limit.ok = e == nil && n > 0
			}
		}
	}
	resources = append(resources, limit)
	ports := egressResource{name: "ephemeral_port_range"}
	f := strings.Fields(read("/sys/net/ipv4/ip_local_port_range"))
	if len(f) == 2 {
		low, e1 := strconv.ParseInt(f[0], 10, 64)
		high, e2 := strconv.ParseInt(f[1], 10, 64)
		ports.ok = e1 == nil && e2 == nil && low > 0 && high >= low && high <= 65535
		ports.value = high - low + 1
	}
	resources = append(resources, ports)
	inuse, tw := egressResource{name: "tcp_inuse"}, egressResource{name: "tcp_time_wait"}
	for _, line := range strings.Split(read("/net/sockstat"), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "TCP:" {
			continue
		}
		for i := 1; i+1 < len(f); i += 2 {
			n, e := strconv.ParseInt(f[i+1], 10, 64)
			if f[i] == "inuse" {
				inuse.value = n
				inuse.ok = e == nil && n >= 0
			}
			if f[i] == "tw" {
				tw.value = n
				tw.ok = e == nil && n >= 0
			}
		}
	}
	return append(resources, inuse, tw)
}

// Sample runs outside lifecycle request paths. Host socket counters are pressure
// proxies, not an exact ephemeral-port occupancy percentage.
func (r *EgressRecorder) Sample(ctx context.Context, limit int, enforce bool) {
	if r == nil {
		return
	}
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		r.capacity.Record(ctx, int64(limit), r.options())
		enabled := int64(0)
		if enforce {
			enabled = 1
		}
		r.enforced.Record(ctx, enabled, r.options())
		r.Connection(0)
		for _, s := range readEgressResources("/proc") {
			opt := r.options(attribute.String("resource", s.name))
			available := int64(0)
			if s.ok {
				available = 1
				r.pressure.Record(ctx, s.value, opt)
			}
			r.available.Record(ctx, available, opt)
		}
	}
}
