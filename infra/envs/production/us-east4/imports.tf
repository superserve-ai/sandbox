# One-time state adoption for resources created imperatively (gcloud) during the
# us-central1 -> us-east4 host migration. Native `import {}` blocks make the CD
# `terraform apply` ADOPT these into state instead of trying to create names that
# already exist (which would fail AlreadyExists and turn the rollout red). Same
# pattern as infra/envs/staging/us-central1/imports.tf. Safe to remove after the
# first successful apply has populated state.

# --- api.superserve.ai external HTTPS load balancer (module.api_cert_lb) ---

import {
  to = module.api_cert_lb.google_compute_region_network_endpoint_group.cloud_run
  id = "projects/rayai-prod/regions/us-east4/networkEndpointGroups/superserve-api-use4-neg"
}

import {
  to = module.api_cert_lb.google_compute_backend_service.cloud_run
  id = "projects/rayai-prod/global/backendServices/superserve-api-backend-use4"
}

import {
  to = module.api_cert_lb.google_compute_url_map.this
  id = "projects/rayai-prod/global/urlMaps/superserve-api-url-map"
}

import {
  to = module.api_cert_lb.google_certificate_manager_dns_authorization.this
  id = "projects/rayai-prod/locations/global/dnsAuthorizations/api-superserve-dnsauth"
}

import {
  to = module.api_cert_lb.google_certificate_manager_certificate.this
  id = "projects/rayai-prod/locations/global/certificates/api-superserve-cert"
}

import {
  to = module.api_cert_lb.google_certificate_manager_certificate_map.this
  id = "projects/rayai-prod/locations/global/certificateMaps/api-superserve-certmap"
}

import {
  to = module.api_cert_lb.google_certificate_manager_certificate_map_entry.this
  id = "projects/rayai-prod/locations/global/certificateMaps/api-superserve-certmap/certificateMapEntries/api-superserve-entry"
}

import {
  to = module.api_cert_lb.google_compute_global_address.this
  id = "projects/rayai-prod/global/addresses/api-superserve-use4-ip"
}

import {
  to = module.api_cert_lb.google_compute_target_https_proxy.this
  id = "projects/rayai-prod/global/targetHttpsProxies/api-superserve-use4-proxy"
}

import {
  to = module.api_cert_lb.google_compute_global_forwarding_rule.this
  id = "projects/rayai-prod/global/forwardingRules/api-superserve-use4-fwd"
}

# Public invoker binding (allUsers -> roles/run.invoker), added out-of-band at
# cutover so api.superserve.ai serves unauthenticated at the edge. iam_member is
# idempotent, but importing keeps the plan a no-op.
import {
  to = module.api.google_cloud_run_v2_service_iam_member.public_invoker[0]
  id = "projects/rayai-prod/locations/us-east4/services/superserve-api-use4 roles/run.invoker allUsers"
}

# CD service account's certificatemanager.editor grant, added out-of-band during
# the #257 incident to unblock the cert-map / dns-auth import. Import so the
# apply adopts the existing binding instead of planning a create.
import {
  to = google_project_iam_member.cd_certificatemanager
  id = "rayai-prod roles/certificatemanager.editor serviceAccount:superserve-github-actions@rayai-prod.iam.gserviceaccount.com"
}

# IAP SSH allow rule (enable_iap_ssh = true). Created imperatively (gcloud) to
# unblock the vmd deploy after manage_public_ssh_deny closed :22 with no IAP
# allow; import so the apply adopts it instead of failing AlreadyExists.
import {
  to = module.network.google_compute_firewall.allow_iap_ssh[0]
  id = "projects/rayai-prod/global/firewalls/superserve-production-vpc-us-east4-allow-iap-ssh"
}
