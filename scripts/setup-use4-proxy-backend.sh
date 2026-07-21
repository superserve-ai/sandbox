#!/usr/bin/env bash
# setup-use4-proxy-backend.sh
#
# Build-ahead setup for the us-east4 edge-proxy data-plane backend, part of the
# use-cell host migration (the vmd host is moving us-central1 -> us-east4).
#
# It mirrors the live central data-plane backend (dp-use -> sandbox-proxy-ig)
# as dp-use4 -> a new us-east4 instance group, so the data-plane cutover is a
# single, reversible backend swap on the sandbox-dataplane URL map:
#
#   gcloud compute url-maps set-default-service sandbox-dataplane \
#     --default-service=dp-use4 --global --project=rayai-prod
#
# This script is INERT: it does NOT touch the URL map, so nothing serves from
# us-east4 until that swap. The dp-use4 backend stays UNHEALTHY until the proxy
# is deployed on the east host (Deploy Proxy, at the cutover label-flip) — that
# is expected and harmless while it is off the URL map.
#
# Idempotent: safe to re-run. Reuses the global dp-hc health check.
set -euo pipefail

PROJECT=rayai-prod
ZONE=us-east4-c
INSTANCE=superserve-vmd-use4
NETWORK=superserve-production-vpc
TAG=vmd-use4

IG=sandbox-proxy-ig-use4
BACKEND=dp-use4
HC=dp-hc                       # reuse the global data-plane health check
FW=allow-sandbox-proxy-lb-use4

PROXY_PORT=5007                # main listener (HTTP after LB TLS termination)
PROXY_REDIRECT_PORT=5008       # HTTP->HTTPS redirect listener

echo "==> [1/3] Unmanaged instance group (${IG}) with the east host"
if ! gcloud compute instance-groups unmanaged describe "${IG}" --zone="${ZONE}" --project="${PROJECT}" &>/dev/null; then
  gcloud compute instance-groups unmanaged create "${IG}" --zone="${ZONE}" --project="${PROJECT}"
fi
# Ensure the east host is a member on every run — a create whose add-instances
# failed, or a pre-created group, must not slip through and leave the cutover
# pointed at an empty group.
if ! gcloud compute instance-groups unmanaged list-instances "${IG}" \
     --zone="${ZONE}" --project="${PROJECT}" --format="value(instance)" 2>/dev/null \
     | grep -q "/${INSTANCE}$"; then
  gcloud compute instance-groups unmanaged add-instances "${IG}" \
    --instances="${INSTANCE}" --zone="${ZONE}" --project="${PROJECT}"
fi
# Named ports are what dp-use4's port-name (proxy) resolves to on the backend.
gcloud compute instance-groups unmanaged set-named-ports "${IG}" \
  --named-ports="proxy:${PROXY_PORT},proxy-redirect:${PROXY_REDIRECT_PORT}" \
  --zone="${ZONE}" --project="${PROJECT}"

echo "==> [2/3] Firewall: LB health-check + backend traffic to the east proxy ports"
# GCP LB health-check + Envoy backend source ranges.
if ! gcloud compute firewall-rules describe "${FW}" --project="${PROJECT}" &>/dev/null; then
  gcloud compute firewall-rules create "${FW}" \
    --network="${NETWORK}" \
    --allow="tcp:${PROXY_PORT},tcp:${PROXY_REDIRECT_PORT}" \
    --source-ranges="35.191.0.0/16,130.211.0.0/22" \
    --target-tags="${TAG}" \
    --description="Allow GCP LB health-check + backend traffic to the us-east4 edge proxy" \
    --project="${PROJECT}"
fi

echo "==> [3/3] Data-plane backend service (${BACKEND}), mirror of dp-use -> east IG"
# Matches dp-use: EXTERNAL_MANAGED / HTTP / port-name proxy / 24h timeout so
# long-lived exec + file WebSocket streams are not cut at the LB.
if ! gcloud compute backend-services describe "${BACKEND}" --global --project="${PROJECT}" &>/dev/null; then
  gcloud compute backend-services create "${BACKEND}" \
    --global \
    --load-balancing-scheme=EXTERNAL_MANAGED \
    --protocol=HTTP \
    --port-name=proxy \
    --health-checks="${HC}" \
    --timeout=86400 \
    --project="${PROJECT}"
fi
# Attach the east IG only if it isn't already a backend — so real failures
# (bad zone/IG, permission, quota) surface instead of being swallowed and
# leaving dp-use4 with no backend.
if ! gcloud compute backend-services describe "${BACKEND}" --global --project="${PROJECT}" \
     --format="value(backends[].group)" 2>/dev/null | grep -q "/${IG}$"; then
  gcloud compute backend-services add-backend "${BACKEND}" \
    --global \
    --instance-group="${IG}" \
    --instance-group-zone="${ZONE}" \
    --balancing-mode=UTILIZATION \
    --max-utilization=0.8 \
    --project="${PROJECT}"
fi

echo ""
echo "Done. ${BACKEND} is created and INERT (not on any URL map)."
echo "Cutover (at the window, after the east proxy is deployed + healthy):"
echo "  gcloud compute url-maps set-default-service sandbox-dataplane \\"
echo "    --default-service=${BACKEND} --global --project=${PROJECT}"
