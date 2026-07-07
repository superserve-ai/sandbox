#!/usr/bin/env bash
set -euo pipefail

echo "Review before running. This imports existing resources into Terraform state."
exit 1

terraform import 'module.network.google_compute_network.this[0]' 'projects/rayai-dev/global/networks/superserve-network-3cb2c3b'
terraform import 'module.network.google_compute_subnetwork.primary' 'projects/rayai-dev/regions/us-central1/subnetworks/superserve-subnet-05cb005'
terraform import 'module.network.google_vpc_access_connector.this[0]' 'projects/rayai-dev/locations/us-central1/connectors/ss-vpc-conn-f1b3552'
terraform import 'module.network.google_compute_firewall.rules["vmd_grpc"]' 'projects/rayai-dev/global/firewalls/superserve-allow-internal-7506206'
terraform import 'module.api.google_cloud_run_v2_service.this' 'projects/rayai-dev/locations/us-central1/services/superserve-api'
terraform import 'module.artifact_storage.google_storage_bucket.buckets["superserve_artifacts"]' 'superserve-artifacts'
terraform import 'module.sandbox_host.google_compute_instance.this' 'projects/rayai-dev/zones/us-central1-a/instances/superserve-vmd-staging'
