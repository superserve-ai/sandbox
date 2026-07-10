# OpenTelemetry metrics

Phase 1 sends a small internal metrics set from the control plane to an OpenTelemetry Collector. Phase 2 keeps the application metric surface the same, but changes the deployment target: staging sends OTLP to a host-local collector, and that collector exports to Google Managed Service for Prometheus (GMP).

Google's current documentation warns that the `googlemanagedprometheus` exporter is no longer the preferred long-term path; OTLP export to the Telemetry API is the newer recommendation. Phase 2 still uses `googlemanagedprometheus` because that is the scoped rollout target for this branch. Plan a later migration rather than mixing exporter changes into this rollout.

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

## Phase 2 collector

Use [collector-gmp.yaml](/home/lando/superserve-ai/sandbox/deploy/otel/collector-gmp.yaml) for staging and later production rollout. It:

- receives OTLP from the control plane on `4317` and `4318`
- exports to GMP through `googlemanagedprometheus`
- scrapes collector self-metrics from `127.0.0.1:8888`
- drops banned high-cardinality labels before export
- keeps exporter queueing and memory limiting visible through self-metrics

### Bare-metal host deployment

Install exactly one collector per VMD host. Phase 2 assumes the control plane sends OTLP to the host's internal IP, not to localhost inside Cloud Run.

Suggested layout:

- binary: `/usr/local/bin/otelcol-contrib`
- config: `/etc/sandbox/otel/collector-gmp.yaml`
- env overrides: `/etc/sandbox/otel/collector.env`
- systemd unit: [superserve-otel-collector.service](/home/lando/superserve-ai/sandbox/deploy/superserve-otel-collector.service)

Minimal install steps:

```bash
sudo install -D -m 0644 deploy/otel/collector-gmp.yaml /etc/sandbox/otel/collector-gmp.yaml
sudo install -D -m 0644 deploy/superserve-otel-collector.service /etc/systemd/system/superserve-otel-collector.service
sudo tee /etc/sandbox/otel/collector.env >/dev/null <<'EOF'
GCP_PROJECT=rayai-dev
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now superserve-otel-collector
```

Validate on-host:

```bash
sudo systemctl status superserve-otel-collector
curl -sf http://127.0.0.1:13133/
curl -sf http://127.0.0.1:8888/metrics | rg '^otelcol_'
```

### Staging rollout

Staging is the only environment enabled in Terraform for app-side OTEL export in Phase 2. Cloud Run sends OTLP to `http://10.0.0.2:4318`, which is the staging VMD host's internal IP.

Required staging runtime env:

```text
OTEL_METRICS_ENABLED=true
OTEL_SERVICE_NAME=sandbox-controlplane
OTEL_ENVIRONMENT=staging
OTEL_EXPORTER_OTLP_ENDPOINT=http://10.0.0.2:4318
OTEL_EXPORT_INTERVAL=15s
```

Production remains rollout-plan only in this phase.

### GCP IAM

The collector's GCE service account needs permission to write Monitoring metric data. Phase 2 grants:

```text
roles/monitoring.metricWriter
```

In staging, that role is bound to the service account already attached to the VMD host. For production, prefer a dedicated host runtime service account before enabling OTEL export.

### Dashboards

Terraform now creates two Cloud Monitoring dashboards for staging:

- `Sandbox Telemetry / Staging Operations`
- `Sandbox Telemetry / Collector`

These cover:

- DB pool pressure and average acquire latency
- sandbox lifecycle success, error, and latency
- VMD error rate and p95 latency by host
- host used vCPU, used memory, and running sandboxes
- sandbox create rate plus conflict/error/timeout spikes as abuse signals
- collector export failures, dropped metric points, queue pressure, and memory-limiter refusals

### Cardinality validation

Phase 2 keeps cardinality bounded in two places:

- application code only emits bounded labels such as `operation`, `result`, `method`, `region`, `host_id`, `service.name`, and `environment`
- both collector configs delete `sandbox_id`, `team_id`, `user_id`, `api_key_id`, `request_id`, `url`, and `error`

Validation checklist for staging:

```bash
curl -sf http://127.0.0.1:8888/metrics | rg 'otelcol_(exporter|processor)'
```

In Cloud Monitoring PromQL, verify the banned labels do not exist on exported series before enabling production:

```promql
count by (sandbox_id) (sandbox_transition_total)
count by (user_id) (sandbox_transition_total)
count by (api_key_id) (sandbox_transition_total)
count by (request_id) (sandbox_transition_total)
count by (url) (sandbox_transition_total)
count by (error) (sandbox_transition_total)
```

Each query should return no series.

### Production rollout plan

Phase 2 does not enable production OTEL export yet. Before that rollout:

1. Install one collector per production VMD host.
2. Bind `roles/monitoring.metricWriter` to the production host collector service account.
3. Verify dashboard queries against staging for at least one sustained deployment window.
4. Confirm collector failure metrics stay quiet under normal traffic.
5. Re-run the banned-label validation queries in the production metrics scope.
