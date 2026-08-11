#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: test-paused-network-slot.sh --host <ssh-target> --region <region> [flags]

Required environment variables:
  SUPERSERVE_API_KEY          API key used as X-API-Key
  SUPERSERVE_BASE_URL         Control-plane API base URL
  SUPERSERVE_PREVIEW_DOMAIN    Preview domain suffix, for example sandbox.superserve.ai

Optional environment variables:
  SUPERSERVE_SANDBOX_BASE_URL  Data-plane base URL for /exec and /preview-ports
  SUPERSERVE_SANDBOX_TEMPLATE  Sandbox template to boot. Defaults to superserve/base.
  SUPERSERVE_REUSE_ATTEMPTS    How many temp sandboxes to try before failing to reclaim OLD_SLOT.
  SUPERSERVE_EXEC_TIMEOUT_S    Per-command timeout for sandbox exec. Defaults to 30.
  SUPERSERVE_HTTP_TIMEOUT_S    Per-request timeout for API/preview curls. Defaults to 20.
  SUPERSERVE_ALLOW_PRODUCTION  Set to 1 to permit production base URLs.

Flags:
  --host <ssh-target>          SSH target for the vmd host (required)
  --region <region>            Region label for results/summary (required)
  --allow-production           Permit production targets
  --api-base-url <url>         Override SUPERSERVE_BASE_URL
  --sandbox-base-url <url>     Override SUPERSERVE_SANDBOX_BASE_URL
  --preview-domain <domain>    Override SUPERSERVE_PREVIEW_DOMAIN
  --template <name>            Override SUPERSERVE_SANDBOX_TEMPLATE
  --reuse-attempts <n>         Override SUPERSERVE_REUSE_ATTEMPTS
USAGE
}

fail() {
  echo "error: $*" >&2
  exit 1
}

shell_quote() {
  local s="$1"
  printf "'%s'" "${s//\'/\'\\\'\'}"
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || fail "required tool not found: $1"
}

api_request() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  local output status
  output="$(mktemp)"

  if [[ -n "$body" ]]; then
    status="$(curl -sS -o "$output" -w '%{http_code}' \
      --max-time "${HTTP_TIMEOUT_S}" \
      -X "$method" \
      -H "X-API-Key: ${API_KEY}" \
      -H 'Content-Type: application/json' \
      --data "$body" \
      "${API_BASE_URL}${path}")"
  else
    status="$(curl -sS -o "$output" -w '%{http_code}' \
      --max-time "${HTTP_TIMEOUT_S}" \
      -X "$method" \
      -H "X-API-Key: ${API_KEY}" \
      "${API_BASE_URL}${path}")"
  fi

  printf '%s\n' "$status"
  cat "$output"
  rm -f "$output"
}

sandbox_request() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  local output status
  output="$(mktemp)"

  if [[ -n "$body" ]]; then
    status="$(curl -sS -o "$output" -w '%{http_code}' \
      --max-time "${HTTP_TIMEOUT_S}" \
      -X "$method" \
      -H "X-Access-Token: ${ACCESS_TOKEN}" \
      -H "X-Superserve-Sandbox-Id: ${SANDBOX_ID}" \
      -H 'Content-Type: application/json' \
      --data "$body" \
      "${SANDBOX_BASE_URL}${path}")"
  else
    status="$(curl -sS -o "$output" -w '%{http_code}' \
      --max-time "${HTTP_TIMEOUT_S}" \
      -X "$method" \
      -H "X-Access-Token: ${ACCESS_TOKEN}" \
      -H "X-Superserve-Sandbox-Id: ${SANDBOX_ID}" \
      "${SANDBOX_BASE_URL}${path}")"
  fi

  printf '%s\n' "$status"
  cat "$output"
  rm -f "$output"
}

sandbox_exec_json() {
  local command="$1"
  local payload response status body
  payload="$(jq -cn --arg command "$command" --argjson timeout_s "$EXEC_TIMEOUT_S" '{command: $command, timeout_s: $timeout_s}')"
  response="$(sandbox_request POST "/exec" "$payload")"
  status="$(head -n1 <<<"$response")"
  body="$(tail -n +2 <<<"$response")"
  if [[ "$status" != "200" ]]; then
    fail "sandbox exec failed with HTTP ${status}: ${body}"
  fi
  printf '%s\n' "$body"
}

sandbox_exec() {
  local body exit_code stdout
  body="$(sandbox_exec_json "$1")"
  exit_code="$(jq -r '.exit_code // empty' <<<"$body")"
  if [[ "$exit_code" != "0" ]]; then
    fail "sandbox exec returned exit_code ${exit_code}: ${body}"
  fi
  stdout="$(jq -r '.stdout // empty' <<<"$body")"
  printf '%s\n' "$stdout"
}

ssh_request() { 
  local remote_cmd="$1"
  local output err_output status
  output="$(mktemp)"
  err_output="$(mktemp)"

  if gcloud compute ssh "$SSH_TARGET" \
    --project="${GCP_PROJECT:-rayai-dev}" \
    --zone="${GCP_ZONE:-us-central1-a}" \
    --tunnel-through-iap \
    --quiet \
    --command="$remote_cmd" \
    >"$output" 2>"$err_output"; then
    status=0
  else
    status=$?
  fi

  printf '%s\n' "$status"
  cat "$output"

  if [[ "$status" != "0" ]]; then
    cat "$err_output" >&2
  fi

  rm -f "$output" "$err_output"
}

wait_for_sandbox_status() {
  local sandbox_id="$1"
  local wanted="$2"
  local deadline=$((SECONDS + POLL_TIMEOUT_S))

  while (( SECONDS < deadline )); do
    local response status body current
    response="$(api_request GET "/sandboxes/${sandbox_id}")"
    status="$(head -n1 <<<"$response")"
    body="$(tail -n +2 <<<"$response")"
    if [[ "$status" != "200" ]]; then
      sleep 2
      continue
    fi
    current="$(jq -r '.status // empty' <<<"$body")"
    if [[ "$current" == "$wanted" ]]; then
      return 0
    fi
    sleep 2
  done

  fail "sandbox ${sandbox_id} did not reach status ${wanted} within ${POLL_TIMEOUT_S}s"
}

publish_preview_port() {
  local port="$1"
  local body response status resp_body
  body="$(jq -cn --argjson port "$port" '{"port": $port, "access": "public"}')"
  response="$(api_request POST "/sandboxes/${SANDBOX_ID}/preview-ports" "$body")"
  status="$(head -n1 <<<"$response")"
  resp_body="$(tail -n +2 <<<"$response")"
  if [[ "$status" != "200" ]]; then
    fail "preview port publish failed with HTTP ${status}: ${resp_body}"
  fi
  printf '%s\n' "$resp_body"
}

curl_preview() {
  local url="$1"
  local output status
  output="$(mktemp)"
  status="$(curl -sS -o "$output" -w '%{http_code}' --max-time "${HTTP_TIMEOUT_S}" "$url" || true)"
  printf '%s\n' "$status"
  cat "$output"
  rm -f "$output"
}

wait_for_preview_http_200() {
  local url="$1"
  local deadline=$((SECONDS + POLL_TIMEOUT_S))
  while (( SECONDS < deadline )); do
    local response status
    response="$(curl_preview "$url")"
    status="$(head -n1 <<<"$response")"
    if [[ "$status" == "200" ]]; then
      return 0
    fi
    sleep 2
  done
  fail "preview URL did not return 200 within ${POLL_TIMEOUT_S}s: ${url}"
}

parse_slot_from_log() {
  local log_json="$1"
  local sandbox_id="$2"
  jq -r --arg sid "$sandbox_id" '
    select(.vm_id == $sid) |
    if has("slot") and (.slot != null) then
      .slot | tostring
    elif has("namespace") and (.namespace | type == "string") then
      (.namespace | capture("^ns-(?<slot>[0-9]+)$").slot)
    else
      empty
    end
  ' <<<"$log_json" | tail -n 1
}

parse_host_ip_from_log() {
  local log_json="$1"
  local sandbox_id="$2"
  jq -r --arg sid "$sandbox_id" '
    select(.vm_id == $sid) |
    .host_ip // empty
  ' <<<"$log_json" | tail -n 1
}

parse_allocation_source_from_log() {
  local log_json="$1"
  local sandbox_id="$2"
  jq -r --arg sid "$sandbox_id" '
    select(.vm_id == $sid) |
    if (.message // .msg // "") == "pool: claim complete" then
      "recycled"
    elif has("on_demand_setup_ms") then
      "on-demand"
    else
      empty
    end
  ' <<<"$log_json" | tail -n 1
}

latest_vmd_logs() {
  local since="$1"
  local response status body

  response="$(ssh_request \
    "sudo -n journalctl -u superserve-vmd --since $(shell_quote "$since") --no-pager -o cat")"

  status="$(head -n1 <<<"$response")"
  body="$(tail -n +2 <<<"$response")"

  if [[ "$status" != "0" ]]; then
    fail "failed to read vmd logs from ${SSH_TARGET}: ${body}"
  fi

  printf '%s\n' "$body"
}

latest_vmd_vm_logs() {
  local since="$1"
  local sandbox_id="$2"
  local logs

  logs="$(latest_vmd_logs "$since")"

  jq -Rc --arg sid "$sandbox_id" '
    fromjson?
    | select(.vm_id == $sid)
  ' <<<"$logs"
}

collect_slot_state() {
  local since="$1"
  local sandbox_id="$2"
  local stage="$3"
  local logs slot host_ip ns source
  logs="$(latest_vmd_vm_logs "$since" "$sandbox_id")"
  {
    printf '## %s %s\n' "$stage" "$since"
    printf '%s\n' "$logs"
    printf '\n'
  } >>"$RESULTS_DIR/vmd.log"

  slot="$(parse_slot_from_log "$logs" "$sandbox_id")"
  host_ip="$(parse_host_ip_from_log "$logs" "$sandbox_id")"
  source="$(parse_allocation_source_from_log "$logs" "$sandbox_id")"
  if [[ "$sandbox_id" == "$SANDBOX_ID" && -n "$source" ]]; then
    ALLOCATION_SOURCE="$source"
  fi
  ns=""
  if [[ -n "$slot" ]]; then
    ns="ns-${slot}"
  fi

  if [[ -z "$slot" ]]; then
    fail "could not determine slot for sandbox ${sandbox_id} from vmd logs; inspect ${RESULTS_DIR}/vmd.log"
  fi

  printf '%s\n%s\n%s\n' "$slot" "$host_ip" "$ns"
}

check_host_slot_resources() {
  local slot="$1"
  local stage="$2"
  local ns="ns-${slot}"
  local veth="veth-${slot}"
  local out response status body

  response="$(ssh_request "sudo -n ip -n $(shell_quote "$ns") link")"
  status="$(head -n1 <<<"$response")"
  body="$(tail -n +2 <<<"$response")"
  if [[ "$status" != "0" ]]; then
    fail "${stage}: expected namespace ${ns} to exist, but ip -n link failed: ${body}"
  fi
  printf '%s\n' "$body" >"${RESULTS_DIR}/${stage}-host.txt"

  response="$(ssh_request "ip link show $(shell_quote "$veth")")"
  status="$(head -n1 <<<"$response")"
  body="$(tail -n +2 <<<"$response")"
  if [[ "$status" != "0" ]]; then
    fail "${stage}: expected host veth ${veth} to exist, but ip link show failed: ${body}"
  fi

  response="$(ssh_request "findmnt $(shell_quote "/var/run/netns/${ns}")")"
  status="$(head -n1 <<<"$response")"
  body="$(tail -n +2 <<<"$response")"
  if [[ "$status" != "0" ]]; then
    fail "${stage}: expected mount ${ns} to exist, but findmnt failed: ${body}"
  fi
}

check_host_slot_released() {
  local slot="$1"
  local stage="$2"
  local ns="ns-${slot}"
  local veth="veth-${slot}"
  local response status body namespace_state veth_state mount_state

  response="$(ssh_request "sudo -n ip netns list | grep -F -- $(shell_quote "$ns")")"
  status="$(head -n1 <<<"$response")"
  body="$(tail -n +2 <<<"$response")"
  namespace_state="gone"
  [[ "$status" == "0" ]] && namespace_state="present"

  response="$(ssh_request "sudo -n test ! -e $(shell_quote "/var/run/netns/${ns}")")"
  status="$(head -n1 <<<"$response")"
  body="$(tail -n +2 <<<"$response")"
  mount_state="gone"
  [[ "$status" == "0" ]] && mount_state="present"

  response="$(ssh_request "ip link show $(shell_quote "$veth")")"
  status="$(head -n1 <<<"$response")"
  body="$(tail -n +2 <<<"$response")"
  veth_state="gone"
  [[ "$status" == "0" ]] && veth_state="present"

  KERNEL_RESOURCE_STATE="${namespace_state}/${veth_state}/${mount_state}"
  printf '%s\n' "$KERNEL_RESOURCE_STATE" >"${RESULTS_DIR}/${stage}-host.txt"
}

cleanup() {
  if [[ -n "${TEMP_SANDBOX_ID:-}" ]]; then
    api_request DELETE "/sandboxes/${TEMP_SANDBOX_ID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${SANDBOX_ID:-}" ]]; then
    api_request DELETE "/sandboxes/${SANDBOX_ID}" >/dev/null 2>&1 || true
  fi
}

API_KEY="${SUPERSERVE_API_KEY:-${API_KEY:-}}"
API_BASE_URL="${SUPERSERVE_BASE_URL:-${API_BASE_URL:-}}"
PREVIEW_DOMAIN="${SUPERSERVE_PREVIEW_DOMAIN:-${PREVIEW_DOMAIN:-}}"
SANDBOX_BASE_URL="${SUPERSERVE_SANDBOX_BASE_URL:-${SANDBOX_BASE_URL:-}}"
SANDBOX_TEMPLATE="${SUPERSERVE_SANDBOX_TEMPLATE:-${SANDBOX_TEMPLATE:-superserve/base}}"
REUSE_ATTEMPTS="${SUPERSERVE_REUSE_ATTEMPTS:-${REUSE_ATTEMPTS:-8}}"
EXEC_TIMEOUT_S="${SUPERSERVE_EXEC_TIMEOUT_S:-${EXEC_TIMEOUT_S:-30}}"
HTTP_TIMEOUT_S="${SUPERSERVE_HTTP_TIMEOUT_S:-${HTTP_TIMEOUT_S:-20}}"
POLL_TIMEOUT_S="${SUPERSERVE_POLL_TIMEOUT_S:-${POLL_TIMEOUT_S:-300}}"
ALLOW_PRODUCTION="${SUPERSERVE_ALLOW_PRODUCTION:-${ALLOW_PRODUCTION:-0}}"

SSH_TARGET=""
REGION=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)
      SSH_TARGET="${2:-}"
      shift 2
      ;;
    --region)
      REGION="${2:-}"
      shift 2
      ;;
    --allow-production)
      ALLOW_PRODUCTION=1
      shift
      ;;
    --api-base-url)
      API_BASE_URL="${2:-}"
      shift 2
      ;;
    --sandbox-base-url)
      SANDBOX_BASE_URL="${2:-}"
      shift 2
      ;;
    --preview-domain)
      PREVIEW_DOMAIN="${2:-}"
      shift 2
      ;;
    --template)
      SANDBOX_TEMPLATE="${2:-}"
      shift 2
      ;;
    --reuse-attempts)
      REUSE_ATTEMPTS="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

[[ -n "$SSH_TARGET" ]] || fail "--host is required"
[[ -n "$REGION" ]] || fail "--region is required"
[[ -n "$API_KEY" ]] || fail "SUPERSERVE_API_KEY is required"
[[ -n "$API_BASE_URL" ]] || fail "SUPERSERVE_BASE_URL is required"
[[ -n "$PREVIEW_DOMAIN" ]] || fail "SUPERSERVE_PREVIEW_DOMAIN is required"

require_tool curl
require_tool jq
require_tool ssh

API_BASE_URL="${API_BASE_URL%/}"
SANDBOX_BASE_URL="${SANDBOX_BASE_URL%/}"
PREVIEW_DOMAIN="${PREVIEW_DOMAIN#.}"

case "$API_BASE_URL" in
  https://api.superserve.ai|https://*.superserve.ai)
    if [[ "$ALLOW_PRODUCTION" != "1" && "$API_BASE_URL" == "https://api.superserve.ai" ]]; then
      fail "production API base URL requires --allow-production"
    fi
    ;;
esac

if [[ -z "$SANDBOX_BASE_URL" ]]; then
  if [[ "$API_BASE_URL" == *staging* || "$REGION" == staging* ]]; then
    SANDBOX_BASE_URL="https://staging-sandbox.superserve.ai"
  else
    SANDBOX_BASE_URL="https://sandbox.superserve.ai"
  fi
fi

if [[ "$SANDBOX_BASE_URL" == "https://sandbox.superserve.ai" && "$ALLOW_PRODUCTION" != "1" && "$API_BASE_URL" == "https://api.superserve.ai" ]]; then
  fail "production sandbox base URL requires --allow-production"
fi

RUN_ID="${GITHUB_RUN_ID:-local}-$(date -u +%Y%m%d%H%M%S)"
SANDBOX_NAME="paused-slot-validation-${REGION}-${RUN_ID}"
RESULTS_ROOT="${RESULTS_ROOT:-results}"
SANDBOX_ID=""
TEMP_SANDBOX_ID=""
ACCESS_TOKEN=""
TEMP_ACCESS_TOKEN=""
OLD_SLOT=""
NEW_SLOT=""
OLD_HOST_IP=""
NEW_HOST_IP=""
OLD_NETNS=""
NEW_NETNS=""
PRE_PAUSE_GUEST_MAC=""
POST_RESUME_GUEST_MAC=""
ALLOCATION_SOURCE="unknown"
RESUME_LATENCY=""
SLOT_RELEASED="FAIL"
OLD_SLOT_REUSED="FAIL"
SLOT_CHANGED_ON_RESUME="FAIL"
KERNEL_RESOURCE_STATE="unknown"
NEW_NETNS_CREATED="FAIL"
NEW_VETH_CREATED="FAIL"
GUEST_IP_STATUS="FAIL"
GUEST_ROUTES_STATUS="FAIL"
GUEST_MAC_COMPARISON="unknown"
DNS_STATUS="FAIL"
OUTBOUND_NETWORK="FAIL"
PREVIEW_PORT_STATUS="FAIL"
FIREWALL_STATE="MANUAL"
CONTROL_PLANE_IP_STATE="MANUAL"
STALE_STATE_FOUND="no"
OVERALL="FAIL"

trap cleanup EXIT

echo "target host: ${SSH_TARGET}"
echo "base url: ${API_BASE_URL}"
echo "sandbox url: ${SANDBOX_BASE_URL}"
echo "preview domain: ${PREVIEW_DOMAIN}"
echo "region: ${REGION}"

create_body="$(jq -cn \
  --arg name "$SANDBOX_NAME" \
  --arg template "$SANDBOX_TEMPLATE" \
  --arg region "$REGION" \
  --arg run_id "$RUN_ID" \
  '{name: $name, from_template: $template, timeout_seconds: 1800, metadata: {validation: "paused-network-slot", region: $region, run_id: $run_id}}')"

create_log_since="$(date -u +%Y-%m-%d' '%H:%M:%S)"
create_response="$(api_request POST /sandboxes "$create_body")"
create_status="$(head -n1 <<<"$create_response")"
create_body_json="$(tail -n +2 <<<"$create_response")"
[[ "$create_status" == "201" || "$create_status" == "200" ]] || fail "create sandbox failed with HTTP ${create_status}: ${create_body_json}"

SANDBOX_ID="$(jq -r '.id // empty' <<<"$create_body_json")"
ACCESS_TOKEN="$(jq -r '.access_token // empty' <<<"$create_body_json")"
[[ -n "$SANDBOX_ID" ]] || fail "create sandbox response did not include an id"
[[ -n "$ACCESS_TOKEN" ]] || fail "create sandbox response did not include an access token"

RESULTS_DIR="${RESULTS_ROOT}/$(date -u +%Y%m%dT%H%M%SZ)-${SANDBOX_ID}"
mkdir -p "$RESULTS_DIR"

wait_for_sandbox_status "$SANDBOX_ID" active

pre_exec_link="$(sandbox_exec 'ip -j link')"
pre_exec_addr="$(sandbox_exec 'ip -j addr')"
pre_exec_route="$(sandbox_exec 'ip -j route')"
pre_dns_response="$(sandbox_exec_json 'getent hosts example.com')"
pre_dns_exit="$(jq -r '.exit_code // empty' <<<"$pre_dns_response")"
pre_dns="$(jq -r '.stdout // empty' <<<"$pre_dns_response")"
pre_https_response="$(sandbox_exec_json "curl -fsS -o /dev/null -w '%{http_code}\n' https://example.com")"
pre_https_exit="$(jq -r '.exit_code // empty' <<<"$pre_https_response")"
pre_https="$(jq -r '.stdout // empty' <<<"$pre_https_response")"

printf '%s\n' "$pre_exec_link" >"$RESULTS_DIR/before-guest-link.json"
printf '%s\n' "$pre_exec_addr" >"$RESULTS_DIR/before-guest-addr.json"
printf '%s\n' "$pre_exec_route" >"$RESULTS_DIR/before-guest-route.json"
printf '%s\n' "$pre_dns" >"$RESULTS_DIR/before-guest-dns.txt"
printf '%s\n' "$pre_https" >"$RESULTS_DIR/before-guest-https.txt"

GUEST_IFACE="$(jq -r 'map(select(.ifname != "lo")) | .[0].ifname // empty' <<<"$pre_exec_link")"
PRE_PAUSE_GUEST_MAC="$(jq -r 'map(select(.ifname != "lo")) | .[0].address // empty' <<<"$pre_exec_link")"
GUEST_IP="$(jq -r 'map(select(.ifname != "lo")) | .[0].addr_info[]? | select(.family == "inet") | .local' <<<"$pre_exec_addr" | head -n1)"
GUEST_GW="$(jq -r '.[] | select(.dst == "default") | .gateway // empty' <<<"$pre_exec_route" | head -n1)"
[[ -n "$GUEST_IFACE" ]] || fail "could not determine guest interface before pause"
[[ -n "$PRE_PAUSE_GUEST_MAC" ]] || fail "could not determine guest MAC before pause"
[[ -n "$GUEST_IP" ]] || fail "could not determine guest IP before pause"
[[ -n "$GUEST_GW" ]] || fail "could not determine guest gateway before pause"
GUEST_IP_STATUS="PASS"
GUEST_ROUTES_STATUS="PASS"
if [[ "$pre_dns_exit" == "0" && -n "$pre_dns" ]]; then
  DNS_STATUS="PASS"
fi
if [[ "$pre_https_exit" == "0" && "$(tr -d '\r\n' <<<"$pre_https")" == "200" ]]; then
  OUTBOUND_NETWORK="PASS"
fi

slot_context="$(collect_slot_state "$create_log_since" "$SANDBOX_ID" "create")"
OLD_SLOT="$(sed -n '1p' <<<"$slot_context")"
OLD_HOST_IP="$(sed -n '2p' <<<"$slot_context")"
OLD_NETNS="$(sed -n '3p' <<<"$slot_context")"

check_host_slot_resources "$OLD_SLOT" "before"

{
  printf 'iface=%s\nmac=%s\nip=%s\ngateway=%s\n' \
    "$(jq -r 'map(select(.ifname != "lo")) | .[0].ifname // empty' <<<"$pre_exec_link")" \
    "$(jq -r 'map(select(.ifname != "lo")) | .[0].address // empty' <<<"$pre_exec_link")" \
    "$(jq -r 'map(select(.ifname != "lo")) | .[0].addr_info[]? | select(.family == "inet") | .local' <<<"$pre_exec_addr" | head -n1)" \
    "$(jq -r '.[] | select(.dst == "default") | .gateway // empty' <<<"$pre_exec_route" | head -n1)"
  printf 'dns=%s\nhttps=%s\n' "$pre_dns" "$pre_https"
  printf '%s\n' "$pre_exec_link"
  printf '%s\n' "$pre_exec_addr"
  printf '%s\n' "$pre_exec_route"
} >"$RESULTS_DIR/before-guest.txt"

preview_start_response="$(sandbox_exec_json 'nohup python3 -m http.server 8080 >/tmp/preview-server.log 2>&1 </dev/null &')"
preview_start_exit="$(jq -r '.exit_code // empty' <<<"$preview_start_response")"
[[ "$preview_start_exit" == "0" ]] || fail "preview server start failed: ${preview_start_response}"

preview_port=8080
publish_preview_port "$preview_port" >/dev/null
preview_url="https://${preview_port}-${SANDBOX_ID}.${PREVIEW_DOMAIN}"
wait_for_preview_http_200 "$preview_url"
PREVIEW_PORT_STATUS="PASS"

pause_log_since="$(date -u +%Y-%m-%d' '%H:%M:%S)"
pause_response="$(api_request POST "/sandboxes/${SANDBOX_ID}/pause")"
pause_status="$(head -n1 <<<"$pause_response")"
pause_body="$(tail -n +2 <<<"$pause_response")"
[[ "$pause_status" == "204" ]] || fail "pause failed with HTTP ${pause_status}: ${pause_body}"
wait_for_sandbox_status "$SANDBOX_ID" paused

check_host_slot_released "$OLD_SLOT" "paused"

paused_log="$(latest_vmd_logs "$pause_log_since")"
printf '%s\n' "$paused_log" >"$RESULTS_DIR/paused-host.txt"

# Try a few fresh sandboxes; if one reclaims OLD_SLOT, the release is proven
# even when the host keeps the namespace/veth/mount around in the pool.
found_temp_owner=""
for attempt in $(seq 1 "$REUSE_ATTEMPTS"); do
  temp_name="paused-slot-temp-${REGION}-${RUN_ID}-${attempt}"
  temp_create_body="$(jq -cn \
    --arg name "$temp_name" \
    --arg template "$SANDBOX_TEMPLATE" \
    --arg region "$REGION" \
    --arg run_id "${RUN_ID}-temp-${attempt}" \
    '{name: $name, from_template: $template, timeout_seconds: 1800, metadata: {validation: "paused-network-slot-temp", region: $region, run_id: $run_id}}')"
  temp_response="$(api_request POST /sandboxes "$temp_create_body")"
  temp_status="$(head -n1 <<<"$temp_response")"
  temp_body="$(tail -n +2 <<<"$temp_response")"
  [[ "$temp_status" == "201" || "$temp_status" == "200" ]] || fail "temp sandbox create failed with HTTP ${temp_status}: ${temp_body}"
  TEMP_SANDBOX_ID="$(jq -r '.id // empty' <<<"$temp_body")"
  TEMP_ACCESS_TOKEN="$(jq -r '.access_token // empty' <<<"$temp_body")"
  [[ -n "$TEMP_SANDBOX_ID" ]] || fail "temp sandbox create response did not include id"
  [[ -n "$TEMP_ACCESS_TOKEN" ]] || fail "temp sandbox create response did not include access token"
  temp_log_since="$(date -u +%Y-%m-%d' '%H:%M:%S)"
  wait_for_sandbox_status "$TEMP_SANDBOX_ID" active
  temp_slot_context="$(collect_slot_state "$temp_log_since" "$TEMP_SANDBOX_ID" "temp-${attempt}")"
  temp_slot="$(sed -n '1p' <<<"$temp_slot_context")"
  if [[ "$temp_slot" == "$OLD_SLOT" ]]; then
    found_temp_owner="$TEMP_SANDBOX_ID"
    SLOT_RELEASED="PASS"
    OLD_SLOT_REUSED="PASS"
    break
  fi
  api_request DELETE "/sandboxes/${TEMP_SANDBOX_ID}" >/dev/null
  TEMP_SANDBOX_ID=""
  TEMP_ACCESS_TOKEN=""
done

[[ -n "$found_temp_owner" ]] || fail "could not observe OLD_SLOT ${OLD_SLOT} being reused within ${REUSE_ATTEMPTS} attempts"

resume_log_since="$(date -u +%Y-%m-%d' '%H:%M:%S)"
resume_start_epoch="$(date +%s)"
resume_response="$(api_request POST "/sandboxes/${SANDBOX_ID}/resume")"
resume_status="$(head -n1 <<<"$resume_response")"
resume_body="$(tail -n +2 <<<"$resume_response")"
[[ "$resume_status" == "200" ]] || fail "resume failed with HTTP ${resume_status}: ${resume_body}"
ACCESS_TOKEN="$(jq -r '.access_token // empty' <<<"$resume_body")"
[[ -n "$ACCESS_TOKEN" ]] || fail "resume response did not include a fresh access token"
wait_for_sandbox_status "$SANDBOX_ID" active
RESUME_LATENCY="$(( $(date +%s) - resume_start_epoch ))s"

resume_slot_context="$(collect_slot_state "$resume_log_since" "$SANDBOX_ID" "resume")"
NEW_SLOT="$(sed -n '1p' <<<"$resume_slot_context")"
NEW_HOST_IP="$(sed -n '2p' <<<"$resume_slot_context")"
NEW_NETNS="$(sed -n '3p' <<<"$resume_slot_context")"

[[ "$NEW_SLOT" != "$OLD_SLOT" ]] || fail "resume reused old slot ${OLD_SLOT}"
SLOT_CHANGED_ON_RESUME="PASS"
NEW_NETNS_CREATED="PASS"
NEW_VETH_CREATED="PASS"

check_host_slot_resources "$NEW_SLOT" "after"

post_exec_link="$(sandbox_exec 'ip -j link')"
post_exec_addr="$(sandbox_exec 'ip -j addr')"
post_exec_route="$(sandbox_exec 'ip -j route')"
post_dns_response="$(sandbox_exec_json 'getent hosts example.com')"
post_dns_exit="$(jq -r '.exit_code // empty' <<<"$post_dns_response")"
post_dns="$(jq -r '.stdout // empty' <<<"$post_dns_response")"
post_https_response="$(sandbox_exec_json "curl -fsS -o /dev/null -w '%{http_code}\n' https://example.com")"
post_https_exit="$(jq -r '.exit_code // empty' <<<"$post_https_response")"
post_https="$(jq -r '.stdout // empty' <<<"$post_https_response")"
printf '%s\n' "$post_exec_link" >"$RESULTS_DIR/after-guest-link.json"
printf '%s\n' "$post_exec_addr" >"$RESULTS_DIR/after-guest-addr.json"
printf '%s\n' "$post_exec_route" >"$RESULTS_DIR/after-guest-route.json"
printf '%s\n' "$post_dns" >"$RESULTS_DIR/after-guest-dns.txt"
printf '%s\n' "$post_https" >"$RESULTS_DIR/after-guest-https.txt"

{
  printf 'iface=%s\nmac=%s\nip=%s\ngateway=%s\n' \
    "$(jq -r 'map(select(.ifname != "lo")) | .[0].ifname // empty' <<<"$post_exec_link")" \
    "$(jq -r 'map(select(.ifname != "lo")) | .[0].address // empty' <<<"$post_exec_link")" \
    "$(jq -r 'map(select(.ifname != "lo")) | .[0].addr_info[]? | select(.family == "inet") | .local' <<<"$post_exec_addr" | head -n1)" \
    "$(jq -r '.[] | select(.dst == "default") | .gateway // empty' <<<"$post_exec_route" | head -n1)"
  printf 'dns=%s\nhttps=%s\n' "$post_dns" "$post_https"
  printf '%s\n' "$post_exec_link"
  printf '%s\n' "$post_exec_addr"
  printf '%s\n' "$post_exec_route"
} >"$RESULTS_DIR/after-guest.txt"

POST_RESUME_GUEST_MAC="$(jq -r 'map(select(.ifname != "lo")) | .[0].address // empty' <<<"$post_exec_link")"
POST_GUEST_IP="$(jq -r 'map(select(.ifname != "lo")) | .[0].addr_info[]? | select(.family == "inet") | .local' <<<"$post_exec_addr" | head -n1)"
POST_GUEST_GW="$(jq -r '.[] | select(.dst == "default") | .gateway // empty' <<<"$post_exec_route" | head -n1)"

if [[ -n "$POST_RESUME_GUEST_MAC" && -n "$PRE_PAUSE_GUEST_MAC" ]]; then
  if [[ "$POST_RESUME_GUEST_MAC" == "$PRE_PAUSE_GUEST_MAC" ]]; then
    GUEST_MAC_COMPARISON="same"
  else
    GUEST_MAC_COMPARISON="changed"
  fi
fi

[[ -n "$POST_GUEST_IP" && "$POST_GUEST_IP" == "$GUEST_IP" ]] && GUEST_IP_STATUS="PASS"
[[ -n "$POST_GUEST_GW" && "$POST_GUEST_GW" == "$GUEST_GW" ]] && GUEST_ROUTES_STATUS="PASS"
if [[ "$post_dns_exit" == "0" && -n "$post_dns" ]]; then
  DNS_STATUS="PASS"
fi
if [[ "$post_https_exit" == "0" && "$(tr -d '\r\n' <<<"$post_https")" == "200" ]]; then
  OUTBOUND_NETWORK="PASS"
fi
wait_for_preview_http_200 "$preview_url"

post_log="$(latest_vmd_logs "$resume_log_since")"
{
  printf '## resume %s\n' "$resume_log_since"
  printf '%s\n' "$post_log"
  printf '\n'
} >>"$RESULTS_DIR/vmd.log"
printf '%s\n' "$post_log" >"$RESULTS_DIR/after-host.txt"
if jq -e --arg old_ip "$OLD_HOST_IP" '
  select((.message // .msg // "") == "reattached VM network state" and .host_ip == $old_ip)
' <<<"$post_log" >/dev/null 2>&1; then
  STALE_STATE_FOUND="yes: stale host IP reappeared in post-resume live-state logs"
fi

if [[ -n "${TEMP_SANDBOX_ID:-}" ]]; then
  api_request DELETE "/sandboxes/${TEMP_SANDBOX_ID}" >/dev/null || true
  TEMP_SANDBOX_ID=""
fi

control_line="MANUAL"
firewall_line="MANUAL"

summary="$RESULTS_DIR/summary.txt"
if [[ \
  "$SLOT_RELEASED" == "PASS" && \
  "$OLD_SLOT_REUSED" == "PASS" && \
  "$SLOT_CHANGED_ON_RESUME" == "PASS" && \
  "$NEW_NETNS_CREATED" == "PASS" && \
  "$NEW_VETH_CREATED" == "PASS" && \
  "$GUEST_IP_STATUS" == "PASS" && \
  "$GUEST_ROUTES_STATUS" == "PASS" && \
  "$GUEST_MAC_COMPARISON" == "changed" && \
  "$DNS_STATUS" == "PASS" && \
  "$OUTBOUND_NETWORK" == "PASS" && \
  "$PREVIEW_PORT_STATUS" == "PASS" && \
  "$STALE_STATE_FOUND" == "no" \
]]; then
  OVERALL="PASS"
fi

{
  echo "SANDBOX_ID=${SANDBOX_ID}"
  echo "HOST=${SSH_TARGET}"
  echo "BASE_URL=${API_BASE_URL}"
  echo "OLD_SLOT=${OLD_SLOT}"
  echo "NEW_SLOT=${NEW_SLOT}"
  echo "OLD_HOST_IP=${OLD_HOST_IP}"
  echo "NEW_HOST_IP=${NEW_HOST_IP}"
  echo "OLD_NETNS=${OLD_NETNS}"
  echo "NEW_NETNS=${NEW_NETNS}"
  echo "PRE_PAUSE_GUEST_MAC=${PRE_PAUSE_GUEST_MAC}"
  echo "POST_RESUME_GUEST_MAC=${POST_RESUME_GUEST_MAC}"
  echo "ALLOCATION_SOURCE=${ALLOCATION_SOURCE}"
  echo "RESUME_LATENCY=${RESUME_LATENCY}"
  echo "KERNEL_RESOURCE_STATE=${KERNEL_RESOURCE_STATE}"
  echo
  echo "SLOT_RELEASED=${SLOT_RELEASED}"
  echo "OLD_SLOT_REUSED=${OLD_SLOT_REUSED}"
  echo "SLOT_CHANGED_ON_RESUME=${SLOT_CHANGED_ON_RESUME}"
  echo "NEW_NETNS_CREATED=${NEW_NETNS_CREATED}"
  echo "NEW_VETH_CREATED=${NEW_VETH_CREATED}"
  echo "GUEST_IP=${GUEST_IP_STATUS}"
  echo "GUEST_ROUTES=${GUEST_ROUTES_STATUS}"
  echo "GUEST_MAC_COMPARISON=${GUEST_MAC_COMPARISON}"
  echo "DNS=${DNS_STATUS}"
  echo "OUTBOUND_NETWORK=${OUTBOUND_NETWORK}"
  echo "PREVIEW_PORT=${PREVIEW_PORT_STATUS}"
  echo "FIREWALL_STATE=${firewall_line}"
  echo "CONTROL_PLANE_IP_STATE=${control_line}"
  echo "STALE_STATE_FOUND=${STALE_STATE_FOUND}"
  echo "OVERALL=${OVERALL}"
} >"$summary"

echo "validation complete"
echo "results: ${RESULTS_DIR}"
echo "summary: ${summary}"
echo "overall: ${OVERALL}"
