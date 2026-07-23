#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: smoke-test-region.sh <environment> <region>

Required environment variables:
  API_KEY             Team API key used as X-API-Key

Optional environment variables:
  API_BASE_URL        Control-plane API base URL. Defaults by environment/region.
  SANDBOX_BASE_URL    Data-plane base URL. Defaults by environment/region.
  SANDBOX_TEMPLATE    Template name to boot. Defaults to superserve/base.
  SMOKE_TIMEOUT_S     Per-command timeout. Defaults to 30.
  POLL_TIMEOUT_S      Lifecycle polling timeout. Defaults to 300.
USAGE
}

if [[ $# -ne 2 ]]; then
  usage
  exit 1
fi

ENVIRONMENT="$1"
REGION="$2"

: "${API_KEY:?API_KEY is required}"

case "${ENVIRONMENT}/${REGION}" in
  staging/us-central1)
    API_BASE_URL="${API_BASE_URL:-https://superserve-api-eszjsyysqa-uc.a.run.app}"
    SANDBOX_BASE_URL="${SANDBOX_BASE_URL:-https://staging-sandbox.superserve.ai}"
    ;;
  production/us-central1 | production/us-east4)
    # The "use" cell — served by the shared api/sandbox domains regardless of
    # which host (central or its us-east4 successor) is primary.
    API_BASE_URL="${API_BASE_URL:-https://api.superserve.ai}"
    SANDBOX_BASE_URL="${SANDBOX_BASE_URL:-https://sandbox.superserve.ai}"
    ;;
  production/us-west2)
    API_BASE_URL="${API_BASE_URL:-https://superserve-api-usw2-5r4mkhjndq-wl.a.run.app}"
    SANDBOX_BASE_URL="${SANDBOX_BASE_URL:-https://usw-sandbox.superserve.ai}"
    ;;
  *)
    : "${API_BASE_URL:?API_BASE_URL is required for ${ENVIRONMENT}/${REGION}}"
    : "${SANDBOX_BASE_URL:?SANDBOX_BASE_URL is required for ${ENVIRONMENT}/${REGION}}"
    ;;
esac

normalize_url() {
  case "$1" in
    http://*|https://*) printf '%s' "$1" ;;
    *) printf 'https://%s' "$1" ;;
  esac
}

SANDBOX_TEMPLATE="${SANDBOX_TEMPLATE:-superserve/base}"
SMOKE_TIMEOUT_S="${SMOKE_TIMEOUT_S:-30}"
POLL_TIMEOUT_S="${POLL_TIMEOUT_S:-300}"

API_BASE_URL="$(normalize_url "${API_BASE_URL%/}")"
SANDBOX_BASE_URL="$(normalize_url "${SANDBOX_BASE_URL%/}")"
RUN_ID="${GITHUB_RUN_ID:-local}-$(date +%s)"
SANDBOX_NAME="terraform-smoke-${ENVIRONMENT}-${REGION}-${RUN_ID}"
EXPECTED="superserve-smoke-ok-${RUN_ID}"

SANDBOX_ID=""
ACCESS_TOKEN=""

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "required tool not found: $1" >&2
    exit 1
  fi
}

require_tool curl
require_tool jq

api_curl() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  local output
  output="$(mktemp)"

  local status
  if [[ -n "$body" ]]; then
    status="$(curl -sSL -o "$output" -w '%{http_code}' \
      -X "$method" \
      -H "X-API-Key: ${API_KEY}" \
      -H 'Content-Type: application/json' \
      --data "$body" \
      "${API_BASE_URL}${path}")"
  else
    status="$(curl -sSL -o "$output" -w '%{http_code}' \
      -X "$method" \
      -H "X-API-Key: ${API_KEY}" \
      "${API_BASE_URL}${path}")"
  fi

  printf '%s\n' "$status"
  cat "$output"
  rm -f "$output"
}

exec_curl() {
  local command="$1"
  local output
  output="$(mktemp)"

  local status
  status="$(curl -sSL -o "$output" -w '%{http_code}' \
    -X POST \
    -H "X-Access-Token: ${ACCESS_TOKEN}" \
    -H "X-Superserve-Sandbox-Id: ${SANDBOX_ID}" \
    -H 'Content-Type: application/json' \
    --data "$(jq -cn --arg command "$command" --argjson timeout_s "$SMOKE_TIMEOUT_S" '{command: $command, timeout_s: $timeout_s}')" \
    "${SANDBOX_BASE_URL}/exec")"

  printf '%s\n' "$status"
  cat "$output"
  rm -f "$output"
}

cleanup() {
  if [[ -n "$SANDBOX_ID" ]]; then
    echo "Cleaning up sandbox ${SANDBOX_ID}"
    curl -sSL -o /dev/null -X DELETE \
      -H "X-API-Key: ${API_KEY}" \
      "${API_BASE_URL}/sandboxes/${SANDBOX_ID}" || true
  fi
}
trap cleanup EXIT

expect_status() {
  local actual="$1"
  local expected="$2"
  local body="$3"
  if [[ "$actual" != "$expected" ]]; then
    echo "expected HTTP ${expected}, got ${actual}" >&2
    echo "$body" >&2
    exit 1
  fi
}

wait_for_status() {
  local wanted="$1"
  local deadline=$((SECONDS + POLL_TIMEOUT_S))

  while (( SECONDS < deadline )); do
    local response status body current
    response="$(api_curl GET "/sandboxes/${SANDBOX_ID}")"
    status="$(head -n1 <<<"$response")"
    body="$(tail -n +2 <<<"$response")"
    expect_status "$status" "200" "$body"
    current="$(jq -r '.status // empty' <<<"$body")"
    if [[ "$current" == "$wanted" ]]; then
      return 0
    fi
    sleep 5
  done

  echo "sandbox ${SANDBOX_ID} did not reach status ${wanted} within ${POLL_TIMEOUT_S}s" >&2
  exit 1
}

run_hello_world() {
  local label="$1"
  local response status body exit_code stdout
  response="$(exec_curl "printf '${EXPECTED}'")"
  status="$(head -n1 <<<"$response")"
  body="$(tail -n +2 <<<"$response")"
  expect_status "$status" "200" "$body"

  exit_code="$(jq -r '.exit_code // empty' <<<"$body")"
  stdout="$(jq -r '.stdout // empty' <<<"$body")"
  if [[ "$exit_code" != "0" || "$stdout" != "$EXPECTED" ]]; then
    echo "${label}: hello-world command failed" >&2
    echo "$body" >&2
    exit 1
  fi
  echo "${label}: hello-world command passed"
}

echo "Creating smoke-test sandbox ${SANDBOX_NAME} in ${ENVIRONMENT}/${REGION}"
create_body="$(jq -cn \
  --arg name "$SANDBOX_NAME" \
  --arg template "$SANDBOX_TEMPLATE" \
  --arg environment "$ENVIRONMENT" \
  --arg region "$REGION" \
  --arg run_id "$RUN_ID" \
  '{name: $name, from_template: $template, timeout_seconds: 1800, metadata: {"terraform_smoke": "true", "environment": $environment, "region": $region, "run_id": $run_id}}')"

response="$(api_curl POST /sandboxes "$create_body")"
status="$(head -n1 <<<"$response")"
body="$(tail -n +2 <<<"$response")"
expect_status "$status" "201" "$body"

SANDBOX_ID="$(jq -r '.id // empty' <<<"$body")"
ACCESS_TOKEN="$(jq -r '.access_token // empty' <<<"$body")"
if [[ -z "$SANDBOX_ID" || -z "$ACCESS_TOKEN" ]]; then
  echo "create response did not include id and access_token" >&2
  echo "$body" >&2
  exit 1
fi

run_hello_world "initial"

echo "Pausing sandbox ${SANDBOX_ID}"
response="$(api_curl POST "/sandboxes/${SANDBOX_ID}/pause")"
status="$(head -n1 <<<"$response")"
body="$(tail -n +2 <<<"$response")"
expect_status "$status" "204" "$body"
wait_for_status paused

echo "Resuming sandbox ${SANDBOX_ID}"
response="$(api_curl POST "/sandboxes/${SANDBOX_ID}/resume")"
status="$(head -n1 <<<"$response")"
body="$(tail -n +2 <<<"$response")"
expect_status "$status" "200" "$body"
ACCESS_TOKEN="$(jq -r '.access_token // empty' <<<"$body")"
if [[ -z "$ACCESS_TOKEN" ]]; then
  echo "resume response did not include access_token" >&2
  echo "$body" >&2
  exit 1
fi
wait_for_status active

run_hello_world "after-resume"

echo "Deleting sandbox ${SANDBOX_ID}"
response="$(api_curl DELETE "/sandboxes/${SANDBOX_ID}")"
status="$(head -n1 <<<"$response")"
body="$(tail -n +2 <<<"$response")"
expect_status "$status" "204" "$body"
SANDBOX_ID=""

echo "Sandbox smoke validation passed for ${ENVIRONMENT}/${REGION}"
