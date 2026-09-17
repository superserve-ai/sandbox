#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_DIR="${ROOT_DIR}/infra/envs/production/us-west2"

cd "${ENV_DIR}"
terraform init
terraform validate
terraform plan -out=tfplan
terraform show -no-color tfplan > plan.txt

# The control plane's vmd dial, its identity label, and its OTLP export must
# all point at the cell's host, and the ingress firewalls must admit them.
terraform show -json tfplan | jq -e '
  .variables.standby_host_id.value as $host_id
  | .planned_values
  | def resources: .. | objects | select(has("address") and has("values"));
  ([resources | select(.address == "module.api.google_cloud_run_v2_service.this")][0].values.template[0].containers[0].env
    | map({key: .name, value: .value}) | from_entries) as $env
  | ([resources | select(.address == "module.sandbox_host_b.google_compute_instance.this")][0].values) as $host
  | ([resources | select(.address == "module.network.google_compute_subnetwork.connector[0]")][0].values.ip_cidr_range) as $connector_cidr
  | ([resources | select(.address == "module.network.google_compute_firewall.rules[\"allow_vmd_grpc\"]")][0].values) as $grpc_firewall
  | ([resources | select(.address == "module.network.google_compute_firewall.rules[\"allow_otel_ingress\"]")][0].values) as $otel_firewall
  | ($host.network_interface[0].network_ip) as $host_ip
  | select($host.tags == ["vmd-usw2"])
  | select($env.VMD_GRPC_ADDRESS == ($host_ip + ":50051"))
  | select($env.DEFAULT_HOST_ID == $host_id)
  | select($env.DB_MAX_CONNS == "15")
  | select($env.OTEL_ENVIRONMENT == "production")
  | select($env.OTEL_EXPORTER_OTLP_ENDPOINT == ("http://" + $host_ip + ":4318"))
  | select($env.OTEL_EXPORT_INTERVAL == "15s")
  | select($env.OTEL_METRICS_ENABLED == "true")
  | select($env.OTEL_SERVICE_NAME == "sandbox-controlplane")
  | select($grpc_firewall.allow == [{"protocol": "tcp", "ports": ["50051"]}])
  | select($otel_firewall.direction == "INGRESS")
  | select($otel_firewall.source_ranges == [$connector_cidr])
  | select($otel_firewall.target_tags == ["vmd-usw2"])
  | select($otel_firewall.allow == [{"protocol": "tcp", "ports": ["4317", "4318"]}])
  | true
' >/dev/null

echo "Wrote ${ENV_DIR}/plan.txt"
echo "Verified the VMD and OTLP endpoints in ${ENV_DIR}"
