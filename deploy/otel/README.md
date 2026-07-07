# OpenTelemetry metrics

Phase 1 sends a small internal metrics set from the control plane to a local OpenTelemetry Collector. The app exports OTLP to localhost; the checked-in local collector config prints detailed metrics with the debug exporter so names and labels can be reviewed before GMP ingestion.

Start the local collector:

```bash
docker run --rm --name sandbox-otel-collector \
  -p 4317:4317 \
  -p 4318:4318 \
  -v "$PWD/deploy/otel/collector-local.yaml:/etc/otelcol/config.yaml:ro" \
  otel/opentelemetry-collector-contrib:0.104.0 \
  --config=/etc/otelcol/config.yaml
```

The Docker config binds OTLP receivers to `0.0.0.0` inside the container so Docker port publishing works from the host. For a host-installed collector, prefer `127.0.0.1` receiver endpoints so OTLP is not exposed as a network-ingress surface.

Run the control plane with metrics enabled:

```bash
export OTEL_METRICS_ENABLED=true
export OTEL_SERVICE_NAME=sandbox-controlplane
export OTEL_ENVIRONMENT=dev
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
export OTEL_EXPORT_INTERVAL=15s
```

`OTEL_EXPORTER_OTLP_INSECURE` defaults to false. HTTP endpoints such as `http://localhost:4318` are treated as insecure automatically; set the env var only when you need to override that behavior explicitly.

The debug exporter should show metrics such as `sandbox_transition_total`, `vmd_call_duration_seconds`, `db_pool_acquired_conns`, `db_pool_acquire_total`, and `db_pool_acquire_duration_seconds_total`. Metric attributes are intentionally limited to bounded operational labels: `operation`, `result`, `region`, `host_id`, `method`, `service.name`, and `environment`.

For average DB pool acquire wait over time, use the cumulative counters rather than histogram percentiles:

```promql
rate(db_pool_acquire_duration_seconds_total[5m]) / rate(db_pool_acquire_total[5m])
```

Do not add customer, user, sandbox, request, raw URL, or raw error-message labels to Phase 1 metrics. The collector config also defensively drops known high-cardinality internal labels, but application code should avoid emitting them in the first place.
