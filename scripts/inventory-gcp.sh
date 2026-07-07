#!/usr/bin/env bash
set -euo pipefail

: "${GCP_PROJECT:?GCP_PROJECT is required}"

OUT_DIR="${1:-inventory/gcp}"
mkdir -p "${OUT_DIR}"

echo "Writing read-only GCP inventory to ${OUT_DIR}"

gcloud run services list --project="${GCP_PROJECT}" --platform=managed --format=json > "${OUT_DIR}/cloud-run-services.json"
gcloud compute instances list --project="${GCP_PROJECT}" --format=json > "${OUT_DIR}/instances.json"
gcloud compute networks list --project="${GCP_PROJECT}" --format=json > "${OUT_DIR}/networks.json"
gcloud compute subnetworks list --project="${GCP_PROJECT}" --format=json > "${OUT_DIR}/subnetworks.json"
gcloud compute firewall-rules list --project="${GCP_PROJECT}" --format=json > "${OUT_DIR}/firewall-rules.json"
gcloud compute backend-services list --global --project="${GCP_PROJECT}" --format=json > "${OUT_DIR}/backend-services.json"
gcloud compute forwarding-rules list --global --project="${GCP_PROJECT}" --format=json > "${OUT_DIR}/global-forwarding-rules.json"
gcloud compute addresses list --global --project="${GCP_PROJECT}" --format=json > "${OUT_DIR}/global-addresses.json"
gcloud compute target-ssl-proxies list --project="${GCP_PROJECT}" --format=json > "${OUT_DIR}/target-ssl-proxies.json"
gcloud compute target-tcp-proxies list --project="${GCP_PROJECT}" --format=json > "${OUT_DIR}/target-tcp-proxies.json"
gcloud compute health-checks list --project="${GCP_PROJECT}" --format=json > "${OUT_DIR}/health-checks.json"
gcloud compute instance-groups unmanaged list --project="${GCP_PROJECT}" --format=json > "${OUT_DIR}/unmanaged-instance-groups.json"
gcloud storage buckets list --project="${GCP_PROJECT}" --format=json > "${OUT_DIR}/storage-buckets.json"
gcloud iam service-accounts list --project="${GCP_PROJECT}" --format=json > "${OUT_DIR}/service-accounts.json"
gcloud compute networks vpc-access connectors list --project="${GCP_PROJECT}" --region=all --format=json > "${OUT_DIR}/vpc-connectors.json"
gcloud certificate-manager certificates list --project="${GCP_PROJECT}" --location=global --format=json > "${OUT_DIR}/certificates.json"
gcloud certificate-manager dns-authorizations list --project="${GCP_PROJECT}" --location=global --format=json > "${OUT_DIR}/dns-authorizations.json"
gcloud certificate-manager maps list --project="${GCP_PROJECT}" --location=global --format=json > "${OUT_DIR}/certificate-maps.json"
