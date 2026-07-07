import {
  to = module.network.google_compute_network.this[0]
  id = "projects/rayai-dev/global/networks/superserve-network-3cb2c3b"
}

import {
  to = module.network.google_compute_subnetwork.primary
  id = "projects/rayai-dev/regions/us-central1/subnetworks/superserve-subnet-05cb005"
}

import {
  to = module.network.google_vpc_access_connector.this[0]
  id = "projects/rayai-dev/locations/us-central1/connectors/ss-vpc-conn-f1b3552"
}

import {
  to = module.network.google_compute_firewall.rules["vmd_grpc"]
  id = "projects/rayai-dev/global/firewalls/superserve-allow-internal-7506206"
}

import {
  to = module.api.google_cloud_run_v2_service.this
  id = "projects/rayai-dev/locations/us-central1/services/superserve-api"
}

import {
  to = module.artifact_storage.google_storage_bucket.buckets["superserve_artifacts"]
  id = "superserve-artifacts"
}

import {
  to = module.sandbox_host.google_compute_instance.this
  id = "projects/rayai-dev/zones/us-central1-a/instances/superserve-vmd-staging"
}
