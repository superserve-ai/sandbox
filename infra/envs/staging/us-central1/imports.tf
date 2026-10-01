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

# The api module now declares the public invoker binding that already exists on
# this service; import so the apply is a no-op. iam_member is idempotent.
import {
  to = module.api.google_cloud_run_v2_service_iam_member.public_invoker[0]
  id = "projects/rayai-dev/locations/us-central1/services/superserve-api roles/run.invoker allUsers"
}

# CD service account's compute.networkAdmin grant, added out-of-band during the
# #257 incident to unblock the VPC flow-log subnet update. Import so the apply
# adopts the existing binding instead of planning a create.
import {
  to = module.iam.google_project_iam_member.project_bindings["cd_network_admin"]
  id = "rayai-dev roles/compute.networkAdmin serviceAccount:superserve-github-actions@rayai-dev.iam.gserviceaccount.com"
}
