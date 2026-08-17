#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_DIR="${ROOT_DIR}/infra/envs/production/us-west2"

cd "${ENV_DIR}"
terraform init
terraform validate
terraform plan -out=tfplan
terraform show -no-color tfplan > plan.txt

verify_plan() {
  local plan_file="$1"
  local host_address="$2"

  terraform show -json "${plan_file}" | jq -e --arg host_address "${host_address}" '
  def resources: .. | objects | select(has("address") and has("values"));
  ([resources | select(.address == "module.api.google_cloud_run_v2_service.this")][0].values.template[0].containers[0].env
    | map({key: .name, value: .value}) | from_entries) as $env
  | ([resources | select(.address == $host_address)][0].values.network_interface[0].network_ip) as $host_ip
  | ([resources | select(.address == $host_address)][0].values.tags) as $host_tags
  | ([resources | select(.address == "module.network.google_compute_subnetwork.connector[0]")][0].values.ip_cidr_range) as $connector_cidr
  | ([resources | select(.address == "module.network.google_compute_firewall.rules[\"allow_vmd_grpc\"]")][0].values) as $grpc_firewall
  | ([resources | select(.address == "module.network.google_compute_firewall.rules[\"allow_otel_ingress\"]")][0].values) as $otel_firewall
  | select($host_tags == ["vmd-usw2"])
  | select($env.VMD_GRPC_ADDRESS == ($host_ip + ":50051"))
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
}

# Check both active-host selections so exporter and gRPC routing cannot regress
# for either the default primary or promoted standby path.
verify_plan tfplan 'module.sandbox_host.google_compute_instance.this'
terraform plan -var='active_sandbox_host=standby' -out=tfplan-standby
verify_plan tfplan-standby 'module.sandbox_host_b.google_compute_instance.this'

echo "Wrote ${ENV_DIR}/plan.txt"
echo "Verified primary and standby VMD and OTLP endpoints in ${ENV_DIR}"
