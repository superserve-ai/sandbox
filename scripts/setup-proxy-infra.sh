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
PROXY_PORT=5007            # Main listener: HTTPS-after-LB-termination, HTTP/1.1, WebSocket
PROXY_REDIRECT_PORT=5008   # Tiny listener: HTTP→HTTPS 301 redirect

# Resource names
IP_NAME="sandbox-proxy-ip"
IG_NAME="sandbox-proxy-ig"          # unmanaged instance group
HC_NAME="sandbox-proxy-hc"          # HTTP health check on PROXY_PORT
HC_REDIRECT_NAME="sandbox-proxy-redirect-hc"  # TCP health check on PROXY_REDIRECT_PORT
BACKEND_NAME="sandbox-proxy-backend"          # main TCP backend → proxy:5007
BACKEND_REDIRECT_NAME="sandbox-proxy-redirect-backend"  # TCP backend → proxy:5008
CERT_MAP_NAME="sandbox-proxy-cert-map"
CERT_MAP_ENTRY="sandbox-proxy-cert-entry"
CERT_NAME="sandbox-proxy-cert"
DNS_AUTH_NAME="sandbox-proxy-dns-auth"
SSL_PROXY_NAME="sandbox-proxy-ssl"   # target SSL proxy (terminates TLS at LB)
TCP_PROXY_NAME="sandbox-proxy-tcp"   # target TCP proxy (port 80 → redirect listener)
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

# Define the named ports so backend services know which ports to target.
# - "proxy" → main HTTP listener (TLS terminates at the LB, plain HTTP here)
# - "proxy-redirect" → tiny HTTP listener that 301-redirects to https://
gcloud compute instance-groups unmanaged set-named-ports "${IG_NAME}" \
  --named-ports="proxy:${PROXY_PORT},proxy-redirect:${PROXY_REDIRECT_PORT}" \
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
    --allow="tcp:${PROXY_PORT},tcp:${PROXY_REDIRECT_PORT}" \
    --source-ranges="35.191.0.0/16,130.211.0.0/22" \
    --target-tags="${INSTANCE_TAG:-vmd}" \
    --description="Allow GCP LB health check probes to edge proxy (main + redirect ports)" \
    --project="${PROJECT}"
fi

if ! gcloud compute firewall-rules describe "${FW_LB_NAME}" --project="${PROJECT}" &>/dev/null; then
  gcloud compute firewall-rules create "${FW_LB_NAME}" \
    --network="${NETWORK}" \
    --allow="tcp:${PROXY_PORT},tcp:${PROXY_REDIRECT_PORT}" \
    --source-ranges="130.211.0.0/22,35.191.0.0/16" \
    --target-tags="${INSTANCE_TAG:-vmd}" \
    --description="Allow GCP LB backend traffic to edge proxy (main + redirect ports)" \
    --project="${PROJECT}"
fi

# ---------------------------------------------------------------------------
# 4. Health checks
#    - Main backend uses an HTTP health check on /health
#    - Redirect backend uses a TCP health check (the redirect listener has
#      no /health endpoint, only a 301 handler)
# ---------------------------------------------------------------------------
echo ""
echo "==> [4/9] Creating health checks..."
if gcloud compute health-checks describe "${HC_NAME}" --global --project="${PROJECT}" &>/dev/null; then
  echo "    ${HC_NAME} already exists, skipping"
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

if gcloud compute health-checks describe "${HC_REDIRECT_NAME}" --global --project="${PROJECT}" &>/dev/null; then
  echo "    ${HC_REDIRECT_NAME} already exists, skipping"
else
  gcloud compute health-checks create tcp "${HC_REDIRECT_NAME}" \
    --global \
    --port-name=proxy-redirect \
    --check-interval=10 \
    --timeout=5 \
    --healthy-threshold=2 \
    --unhealthy-threshold=3 \
    --project="${PROJECT}"
fi

# ---------------------------------------------------------------------------
# 5. Backend services
#
# We use TWO backend services and TWO load balancers in front of the proxy:
#
# (a) Main backend (TCP protocol, port-name=proxy) — fronted by an SSL
#     Proxy Network LB on port 443. The LB terminates TLS using the
#     Certificate Manager wildcard cert and forwards plain TCP to the
#     proxy on port 5007. The proxy serves plain HTTP — TLS termination
#     is at the LB.
#
#     Critically, SSL Proxy LB does NOT advertise HTTP/2 in TLS ALPN, so
#     browsers fall back to HTTP/1.1. This is the *whole reason* we use
#     SSL Proxy LB instead of the Application LB: GCP's Application LB
#     advertises h2 in ALPN and then strips the WebSocket Upgrade headers
#     during HTTP/2→HTTP/1.1 translation, breaking every browser-based
#     WebSocket upgrade. Confirmed empirically; do not switch back.
#
# (b) Redirect backend (TCP protocol, port-name=proxy-redirect) — fronted
#     by a TCP Proxy LB on port 80. Plain TCP forwarding to the proxy's
#     tiny HTTP-only redirect listener on port 5008, which serves a 301
#     to the same URL on https://. Lives on the same instance group, just
#     a different named port.
#
# Long timeouts on the main backend so streaming WebSocket connections
# (terminal sessions, exec streams) survive idle periods. The 86400s
# (24h) value matches the maximum the proxy itself will allow before
# its idle timer kicks in.
# ---------------------------------------------------------------------------
echo ""
echo "==> [5/9] Creating backend services..."
if gcloud compute backend-services describe "${BACKEND_NAME}" --global --project="${PROJECT}" &>/dev/null; then
  echo "    ${BACKEND_NAME} already exists, skipping"
else
  gcloud compute backend-services create "${BACKEND_NAME}" \
    --global \
    --load-balancing-scheme=EXTERNAL_MANAGED \
    --protocol=TCP \
    --port-name=proxy \
    --health-checks="${HC_NAME}" \
    --timeout=86400 \
    --connection-draining-timeout=300 \
    --enable-logging \
    --logging-sample-rate=1.0 \
    --project="${PROJECT}"
  gcloud compute backend-services add-backend "${BACKEND_NAME}" \
    --global \
    --instance-group="${IG_NAME}" \
    --instance-group-zone="${ZONE}" \
    --balancing-mode=UTILIZATION \
    --max-utilization=0.8 \
    --project="${PROJECT}"
fi

if gcloud compute backend-services describe "${BACKEND_REDIRECT_NAME}" --global --project="${PROJECT}" &>/dev/null; then
  echo "    ${BACKEND_REDIRECT_NAME} already exists, skipping"
else
  gcloud compute backend-services create "${BACKEND_REDIRECT_NAME}" \
    --global \
    --load-balancing-scheme=EXTERNAL_MANAGED \
    --protocol=TCP \
    --port-name=proxy-redirect \
    --health-checks="${HC_REDIRECT_NAME}" \
    --timeout=30 \
    --project="${PROJECT}"
  gcloud compute backend-services add-backend "${BACKEND_REDIRECT_NAME}" \
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
# 7. Target proxies
#
# - target-ssl-proxy → SSL Proxy LB on port 443. Terminates TLS at the LB
#   using the Certificate Manager wildcard cert. Forwards plain TCP to the
#   main backend. Does NOT speak HTTP, does NOT advertise h2 in ALPN.
# - target-tcp-proxy → TCP Proxy LB on port 80. Plain TCP forwarding to
#   the redirect backend (which serves a 301).
#
# We deliberately do NOT use target-https-proxy / Application LB here
# because GCP's Application LB strips the WebSocket Upgrade headers when
# translating HTTP/2 client connections to HTTP/1.1 backend connections,
# breaking every browser-based WebSocket upgrade. Both classic and
# modern (EXTERNAL_MANAGED) Application LBs have this bug. Confirmed
# empirically. Do not switch back without re-verifying.
# ---------------------------------------------------------------------------
echo ""
echo "==> [7/9] Creating target proxies..."

if ! gcloud compute target-ssl-proxies describe "${SSL_PROXY_NAME}" --project="${PROJECT}" &>/dev/null; then
  gcloud compute target-ssl-proxies create "${SSL_PROXY_NAME}" \
    --backend-service="${BACKEND_NAME}" \
    --certificate-map="${CERT_MAP_NAME}" \
    --project="${PROJECT}"
fi

if ! gcloud compute target-tcp-proxies describe "${TCP_PROXY_NAME}" --project="${PROJECT}" &>/dev/null; then
  gcloud compute target-tcp-proxies create "${TCP_PROXY_NAME}" \
    --backend-service="${BACKEND_REDIRECT_NAME}" \
    --project="${PROJECT}"
fi

# ---------------------------------------------------------------------------
# 8. Forwarding rules (both on the same global static IP)
# ---------------------------------------------------------------------------
echo ""
echo "==> [8/9] Creating forwarding rules..."

if ! gcloud compute forwarding-rules describe "${FWD_RULE_HTTPS}" --global --project="${PROJECT}" &>/dev/null; then
  gcloud compute forwarding-rules create "${FWD_RULE_HTTPS}" \
    --global \
    --load-balancing-scheme=EXTERNAL_MANAGED \
    --target-ssl-proxy="${SSL_PROXY_NAME}" \
    --address="${IP_NAME}" \
    --ports=443 \
    --project="${PROJECT}"
fi

if ! gcloud compute forwarding-rules describe "${FWD_RULE_HTTP}" --global --project="${PROJECT}" &>/dev/null; then
  gcloud compute forwarding-rules create "${FWD_RULE_HTTP}" \
    --global \
    --load-balancing-scheme=EXTERNAL_MANAGED \
    --target-tcp-proxy="${TCP_PROXY_NAME}" \
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
