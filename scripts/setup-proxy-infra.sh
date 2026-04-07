#!/usr/bin/env bash
# setup-proxy-infra.sh
#
# One-time setup of the GCP HTTPS load balancer + Certificate Manager wildcard
# cert for the edge proxy. Run this once; subsequent deploys just restart the
# proxy service via the deploy workflow.
#
# After this script completes, you must add two DNS records in Vercel:
#   1. TXT record for Certificate Manager domain authorization (printed at the end)
#   2. A record:  *.sandbox  A  <LB_IP>  (also printed at the end)
#
# The wildcard cert will not provision until the TXT record is live.
# Certificate provisioning takes ~10-15 minutes after DNS propagates.
#
# Usage:
#   GCP_PROJECT=my-project \
#   ZONE=us-central1-a \
#   INSTANCE=my-vmd-instance \
#   NETWORK=my-vpc-network \
#   DOMAIN=sandbox.example.com \
#   ./scripts/setup-proxy-infra.sh

set -euo pipefail

# ---------------------------------------------------------------------------
# Config — all required via env vars, no hardcoded defaults
# ---------------------------------------------------------------------------
: "${GCP_PROJECT:?GCP_PROJECT is required}"
: "${ZONE:?ZONE is required (e.g. us-central1-a)}"
: "${INSTANCE:?INSTANCE is required (bare metal GCP instance name)}"
: "${NETWORK:?NETWORK is required (VPC network name)}"
: "${DOMAIN:?DOMAIN is required (e.g. sandbox.example.com)}"

PROJECT="${GCP_PROJECT}"
REGION="${ZONE%-*}"  # strips zone suffix, e.g. us-central1-a → us-central1
WILDCARD_DOMAIN="*.${DOMAIN}"
PROXY_PORT=5007

# Resource names
IP_NAME="sandbox-proxy-ip"
IG_NAME="sandbox-proxy-ig"          # unmanaged instance group
HC_NAME="sandbox-proxy-hc"          # health check
BACKEND_NAME="sandbox-proxy-backend"
CERT_MAP_NAME="sandbox-proxy-cert-map"
CERT_MAP_ENTRY="sandbox-proxy-cert-entry"
CERT_NAME="sandbox-proxy-cert"
DNS_AUTH_NAME="sandbox-proxy-dns-auth"
URL_MAP_NAME="sandbox-proxy-url-map"
URL_MAP_HTTP_NAME="sandbox-proxy-url-map-http"  # for HTTP→HTTPS redirect
HTTPS_PROXY_NAME="sandbox-proxy-https"
HTTP_PROXY_NAME="sandbox-proxy-http"
FWD_RULE_HTTPS="sandbox-proxy-https-fwd"
FWD_RULE_HTTP="sandbox-proxy-http-fwd"

echo "==> Project: ${PROJECT}, Zone: ${ZONE}, Region: ${REGION}"

# ---------------------------------------------------------------------------
# 1. Reserve a global static external IP
# ---------------------------------------------------------------------------
echo ""
echo "==> [1/9] Reserving global static IP..."
if gcloud compute addresses describe "${IP_NAME}" --global --project="${PROJECT}" &>/dev/null; then
  echo "    already exists, skipping"
else
  gcloud compute addresses create "${IP_NAME}" \
    --global \
    --project="${PROJECT}"
fi
LB_IP=$(gcloud compute addresses describe "${IP_NAME}" --global --project="${PROJECT}" --format="get(address)")
echo "    LB IP: ${LB_IP}"

# ---------------------------------------------------------------------------
# 2. Create unmanaged instance group for the bare metal host
# ---------------------------------------------------------------------------
echo ""
echo "==> [2/9] Creating unmanaged instance group..."
if gcloud compute instance-groups unmanaged describe "${IG_NAME}" --zone="${ZONE}" --project="${PROJECT}" &>/dev/null; then
  echo "    already exists, skipping"
else
  gcloud compute instance-groups unmanaged create "${IG_NAME}" \
    --zone="${ZONE}" \
    --project="${PROJECT}"
  gcloud compute instance-groups unmanaged add-instances "${IG_NAME}" \
    --instances="${INSTANCE}" \
    --zone="${ZONE}" \
    --project="${PROJECT}"
fi

# Define the named port so the backend service knows which port to target.
gcloud compute instance-groups unmanaged set-named-ports "${IG_NAME}" \
  --named-ports="proxy:${PROXY_PORT}" \
  --zone="${ZONE}" \
  --project="${PROJECT}"

# ---------------------------------------------------------------------------
# 3. Firewall: allow LB health check probes and LB→backend traffic on PROXY_PORT
#    GCP LB health checks originate from 35.191.0.0/16 and 130.211.0.0/22
# ---------------------------------------------------------------------------
echo ""
echo "==> [3/9] Creating firewall rules..."
FW_HC_NAME="allow-sandbox-proxy-hc"
FW_LB_NAME="allow-sandbox-proxy-lb"

if ! gcloud compute firewall-rules describe "${FW_HC_NAME}" --project="${PROJECT}" &>/dev/null; then
  gcloud compute firewall-rules create "${FW_HC_NAME}" \
    --network="${NETWORK}" \
    --allow="tcp:${PROXY_PORT}" \
    --source-ranges="35.191.0.0/16,130.211.0.0/22" \
    --description="Allow GCP LB health check probes to edge proxy" \
    --project="${PROJECT}"
fi

if ! gcloud compute firewall-rules describe "${FW_LB_NAME}" --project="${PROJECT}" &>/dev/null; then
  gcloud compute firewall-rules create "${FW_LB_NAME}" \
    --network="${NETWORK}" \
    --allow="tcp:${PROXY_PORT}" \
    --source-ranges="130.211.0.0/22,35.191.0.0/16" \
    --description="Allow GCP LB backend traffic to edge proxy" \
    --project="${PROJECT}"
fi

# ---------------------------------------------------------------------------
# 4. HTTP health check on /health
# ---------------------------------------------------------------------------
echo ""
echo "==> [4/9] Creating health check..."
if gcloud compute health-checks describe "${HC_NAME}" --global --project="${PROJECT}" &>/dev/null; then
  echo "    already exists, skipping"
else
  gcloud compute health-checks create http "${HC_NAME}" \
    --global \
    --port="${PROXY_PORT}" \
    --request-path="/health" \
    --check-interval=10 \
    --timeout=5 \
    --healthy-threshold=2 \
    --unhealthy-threshold=3 \
    --project="${PROJECT}"
fi

# ---------------------------------------------------------------------------
# 5. Backend service
#    Timeout 630s > proxy server idle (620s) > proxy transport idle (610s) > GCP LB upstream (600s)
# ---------------------------------------------------------------------------
echo ""
echo "==> [5/9] Creating backend service..."
if gcloud compute backend-services describe "${BACKEND_NAME}" --global --project="${PROJECT}" &>/dev/null; then
  echo "    already exists, skipping"
else
  gcloud compute backend-services create "${BACKEND_NAME}" \
    --global \
    --protocol=HTTP \
    --port-name=proxy \
    --health-checks="${HC_NAME}" \
    --timeout=630 \
    --project="${PROJECT}"
  gcloud compute backend-services add-backend "${BACKEND_NAME}" \
    --global \
    --instance-group="${IG_NAME}" \
    --instance-group-zone="${ZONE}" \
    --balancing-mode=UTILIZATION \
    --project="${PROJECT}"
fi

# ---------------------------------------------------------------------------
# 6. Certificate Manager — wildcard cert via DNS authorization
# ---------------------------------------------------------------------------
echo ""
echo "==> [6/9] Setting up Certificate Manager wildcard cert..."

# DNS authorization (proves we own the domain)
if ! gcloud certificate-manager dns-authorizations describe "${DNS_AUTH_NAME}" --project="${PROJECT}" &>/dev/null; then
  gcloud certificate-manager dns-authorizations create "${DNS_AUTH_NAME}" \
    --domain="${DOMAIN}" \
    --project="${PROJECT}"
fi

# Get the DNS authorization TXT record (needed in Vercel before cert can provision)
DNS_AUTH_RECORD=$(gcloud certificate-manager dns-authorizations describe "${DNS_AUTH_NAME}" \
  --project="${PROJECT}" \
  --format="value(dnsResourceRecord.name,dnsResourceRecord.type,dnsResourceRecord.data)" 2>/dev/null || echo "")

# Certificate
if ! gcloud certificate-manager certificates describe "${CERT_NAME}" --project="${PROJECT}" &>/dev/null; then
  gcloud certificate-manager certificates create "${CERT_NAME}" \
    --domains="${WILDCARD_DOMAIN},${DOMAIN}" \
    --dns-authorizations="${DNS_AUTH_NAME}" \
    --project="${PROJECT}"
fi

# Certificate map + entry
if ! gcloud certificate-manager maps describe "${CERT_MAP_NAME}" --project="${PROJECT}" &>/dev/null; then
  gcloud certificate-manager maps create "${CERT_MAP_NAME}" --project="${PROJECT}"
fi
if ! gcloud certificate-manager maps entries describe "${CERT_MAP_ENTRY}" \
    --map="${CERT_MAP_NAME}" --project="${PROJECT}" &>/dev/null; then
  gcloud certificate-manager maps entries create "${CERT_MAP_ENTRY}" \
    --map="${CERT_MAP_NAME}" \
    --certificates="${CERT_NAME}" \
    --hostname="${WILDCARD_DOMAIN}" \
    --project="${PROJECT}"
fi

# ---------------------------------------------------------------------------
# 7. URL maps
# ---------------------------------------------------------------------------
echo ""
echo "==> [7/9] Creating URL maps..."

# HTTPS: route everything to the backend
if ! gcloud compute url-maps describe "${URL_MAP_NAME}" --global --project="${PROJECT}" &>/dev/null; then
  gcloud compute url-maps create "${URL_MAP_NAME}" \
    --default-service="${BACKEND_NAME}" \
    --global \
    --project="${PROJECT}"
fi

# HTTP: redirect all traffic to HTTPS
if ! gcloud compute url-maps describe "${URL_MAP_HTTP_NAME}" --global --project="${PROJECT}" &>/dev/null; then
  gcloud compute url-maps import "${URL_MAP_HTTP_NAME}" \
    --global \
    --project="${PROJECT}" \
    --source=/dev/stdin <<'YAML'
name: sandbox-proxy-url-map-http
defaultUrlRedirect:
  redirectResponseCode: MOVED_PERMANENTLY_DEFAULT
  httpsRedirect: true
YAML
fi

# ---------------------------------------------------------------------------
# 8. Target proxies and forwarding rules
# ---------------------------------------------------------------------------
echo ""
echo "==> [8/9] Creating target proxies and forwarding rules..."

# HTTPS target proxy — references the certificate map
if ! gcloud compute target-https-proxies describe "${HTTPS_PROXY_NAME}" --global --project="${PROJECT}" &>/dev/null; then
  gcloud compute target-https-proxies create "${HTTPS_PROXY_NAME}" \
    --url-map="${URL_MAP_NAME}" \
    --certificate-map="${CERT_MAP_NAME}" \
    --global \
    --project="${PROJECT}"
fi

# HTTP target proxy (for redirect)
if ! gcloud compute target-http-proxies describe "${HTTP_PROXY_NAME}" --global --project="${PROJECT}" &>/dev/null; then
  gcloud compute target-http-proxies create "${HTTP_PROXY_NAME}" \
    --url-map="${URL_MAP_HTTP_NAME}" \
    --global \
    --project="${PROJECT}"
fi

# HTTPS forwarding rule
if ! gcloud compute forwarding-rules describe "${FWD_RULE_HTTPS}" --global --project="${PROJECT}" &>/dev/null; then
  gcloud compute forwarding-rules create "${FWD_RULE_HTTPS}" \
    --global \
    --target-https-proxy="${HTTPS_PROXY_NAME}" \
    --address="${IP_NAME}" \
    --ports=443 \
    --project="${PROJECT}"
fi

# HTTP forwarding rule (redirect to HTTPS)
if ! gcloud compute forwarding-rules describe "${FWD_RULE_HTTP}" --global --project="${PROJECT}" &>/dev/null; then
  gcloud compute forwarding-rules create "${FWD_RULE_HTTP}" \
    --global \
    --target-http-proxy="${HTTP_PROXY_NAME}" \
    --address="${IP_NAME}" \
    --ports=80 \
    --project="${PROJECT}"
fi

# ---------------------------------------------------------------------------
# 9. Done — print what to add in Vercel DNS
# ---------------------------------------------------------------------------
echo ""
echo "==> [9/9] Done! Add these two DNS records in Vercel for superserve.ai:"
echo ""
echo "    Record 1 — routes *.sandbox.superserve.ai to the LB:"
echo "      Name:  *.sandbox"
echo "      Type:  A"
echo "      Value: ${LB_IP}"
echo ""
echo "    Record 2 — Certificate Manager domain authorization (required for wildcard cert):"
if [ -n "${DNS_AUTH_RECORD}" ]; then
  echo "      ${DNS_AUTH_RECORD}"
else
  echo "      Run: gcloud certificate-manager dns-authorizations describe ${DNS_AUTH_NAME} --project=${PROJECT}"
  echo "      and add the dnsResourceRecord (name, type=CNAME, data) to Vercel DNS."
fi
echo ""
echo "    The wildcard cert provisions automatically after DNS propagates (~10-15 min)."
echo "    Check status: gcloud certificate-manager certificates describe ${CERT_NAME} --project=${PROJECT}"
