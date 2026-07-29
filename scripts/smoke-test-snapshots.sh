#!/usr/bin/env bash
# End-to-end canary for immutable saved snapshots.
#
# This script is intentionally not part of the default regional smoke test.
# The target team must have sandbox_snapshots_v1 enabled, a provisioned
# snapshot-storage quota, and capacity for one source plus four active forks.
# This is a staging ship gate, not a degraded lifecycle smoke. It requires
# secret write access, direct shadow-ledger verification, and a restart hook.
# EXIT cleanup always forces the canary team's feature override off before
# deleting resources; the orchestrating workflow restores the exact prior row
# and quota after this process returns.
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: RUN_SNAPSHOT_CANARY=1 API_BASE_URL=https://api.example.test \
  SANDBOX_BASE_URL=https://sandbox.example.test API_KEY=... \
  SNAPSHOT_RESTART_HOOK=./restart-staging-snapshot-services.sh \
  ./scripts/smoke-test-snapshots.sh

Required environment variables:
  RUN_SNAPSHOT_CANARY  Must be exactly 1. Prevents accidental production runs.
  API_BASE_URL         Control-plane API base URL.
  SANDBOX_BASE_URL     Data-plane base URL used by /exec.
  API_KEY              Team API key used as X-API-Key.
  SNAPSHOT_RESTART_HOOK
                       Executable invoked after each capture to restart the
                       staging control plane and VMD at the exact tested SHA.
  SNAPSHOT_SHADOW_DATABASE_URL
                       PostgreSQL URL used to verify the shadow storage ledger.
  SNAPSHOT_TEAM_ID     UUID for the otherwise-quiescent canary team.

Optional environment variables:
  SANDBOX_TEMPLATE     Source template. Defaults to superserve/base.
  API_TIMEOUT_S        Timeout for create/capture API calls. Defaults to 180.
  EXEC_TIMEOUT_S       Timeout requested for each sandbox command. Defaults to 30.
  POLL_TIMEOUT_S       Lifecycle polling timeout. Defaults to 300.
  POLL_INTERVAL_S      Seconds between lifecycle polls. Defaults to 3.
  CANARY_EGRESS_TEST_URL
                       Public URL used to prove that the source's deny-all
                       egress policy is inherited by every fork. Defaults to
                       https://example.com.

The restart hook is invoked as:
  HOOK <phase> <sandbox_id> <snapshot_id>
where phase is `after-active-capture` or `after-paused-capture`. It must
return only after both staging services are ready for API traffic.
USAGE
}

if [[ "${RUN_SNAPSHOT_CANARY:-}" != "1" ]]; then
  usage
  exit 2
fi

: "${API_BASE_URL:?API_BASE_URL is required}"
: "${SANDBOX_BASE_URL:?SANDBOX_BASE_URL is required}"
: "${API_KEY:?API_KEY is required}"
: "${SNAPSHOT_RESTART_HOOK:?SNAPSHOT_RESTART_HOOK is required}"
: "${SNAPSHOT_SHADOW_DATABASE_URL:?SNAPSHOT_SHADOW_DATABASE_URL is required}"
: "${SNAPSHOT_TEAM_ID:?SNAPSHOT_TEAM_ID is required}"

normalize_url() {
  case "$1" in
    http://*|https://*) printf '%s' "$1" ;;
    *) printf 'https://%s' "$1" ;;
  esac
}

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "required tool not found: $1" >&2
    exit 1
  fi
}

require_positive_integer() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
    echo "${name} must be a positive integer, got: ${value}" >&2
    exit 2
  fi
}

require_boolean() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "${name} must be 0 or 1, got: ${value}" >&2
    exit 2
  fi
}

require_tool curl
require_tool jq
require_tool base64

SANDBOX_TEMPLATE="${SANDBOX_TEMPLATE:-superserve/base}"
API_TIMEOUT_S="${API_TIMEOUT_S:-180}"
EXEC_TIMEOUT_S="${EXEC_TIMEOUT_S:-30}"
POLL_TIMEOUT_S="${POLL_TIMEOUT_S:-300}"
POLL_INTERVAL_S="${POLL_INTERVAL_S:-3}"
SNAPSHOT_RESTART_HOOK="${SNAPSHOT_RESTART_HOOK:-}"
REQUIRE_SNAPSHOT_RESTART_HOOK="${REQUIRE_SNAPSHOT_RESTART_HOOK:-1}"
SKIP_SNAPSHOT_SECRET_CHECKS="${SKIP_SNAPSHOT_SECRET_CHECKS:-0}"
CANARY_EGRESS_TEST_URL="${CANARY_EGRESS_TEST_URL:-https://example.com}"
SNAPSHOT_SHADOW_DATABASE_URL="${SNAPSHOT_SHADOW_DATABASE_URL:-}"
SNAPSHOT_TEAM_ID="${SNAPSHOT_TEAM_ID:-}"

require_positive_integer API_TIMEOUT_S "$API_TIMEOUT_S"
require_positive_integer EXEC_TIMEOUT_S "$EXEC_TIMEOUT_S"
require_positive_integer POLL_TIMEOUT_S "$POLL_TIMEOUT_S"
require_positive_integer POLL_INTERVAL_S "$POLL_INTERVAL_S"
require_boolean REQUIRE_SNAPSHOT_RESTART_HOOK "$REQUIRE_SNAPSHOT_RESTART_HOOK"
require_boolean SKIP_SNAPSHOT_SECRET_CHECKS "$SKIP_SNAPSHOT_SECRET_CHECKS"

if [[ "$REQUIRE_SNAPSHOT_RESTART_HOOK" != "1" ]]; then
  echo "REQUIRE_SNAPSHOT_RESTART_HOOK must remain 1; restart recovery is a required ship gate" >&2
  exit 2
fi
if [[ "$SKIP_SNAPSHOT_SECRET_CHECKS" != "0" ]]; then
  echo "SKIP_SNAPSHOT_SECRET_CHECKS must remain 0; degraded canaries are not accepted for staging sign-off" >&2
  exit 2
fi

case "$CANARY_EGRESS_TEST_URL" in
  http://*|https://*) ;;
  *)
    echo "CANARY_EGRESS_TEST_URL must use http:// or https://" >&2
    exit 2
    ;;
esac
if [[ "$CANARY_EGRESS_TEST_URL" == *"'"* || "$CANARY_EGRESS_TEST_URL" =~ [[:space:]] ]]; then
  echo "CANARY_EGRESS_TEST_URL must not contain single quotes or whitespace" >&2
  exit 2
fi

if [[ ! -x "$SNAPSHOT_RESTART_HOOK" ]]; then
  echo "SNAPSHOT_RESTART_HOOK must name an executable file: ${SNAPSHOT_RESTART_HOOK}" >&2
  exit 2
fi
if [[ ! "$SNAPSHOT_TEAM_ID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
  echo "SNAPSHOT_TEAM_ID must be a UUID" >&2
  exit 2
fi
require_tool psql

API_BASE_URL="$(normalize_url "${API_BASE_URL%/}")"
SANDBOX_BASE_URL="$(normalize_url "${SANDBOX_BASE_URL%/}")"

RUN_ID="$(date +%s)-$$"
SOURCE_NAME="snapshot-canary-source-${RUN_ID}"
SNAPSHOT_NAME="snapshot-canary-${RUN_ID}"
PAUSED_SNAPSHOT_NAME="snapshot-canary-paused-${RUN_ID}"
STATE_PATH="/tmp/superserve-snapshot-canary-${RUN_ID}"
SOURCE_MARKER="snapshot-canary-source-${RUN_ID}"
SOURCE_MUTATED_MARKER="snapshot-canary-source-mutated-${RUN_ID}"
MEMORY_MARKER="snapshot-canary-memory-${RUN_ID}"
SOURCE_MEMORY_MARKER="snapshot-canary-memory-source-${RUN_ID}"
MEMORY_REQUEST_PATH="/tmp/superserve-snapshot-memory-${RUN_ID}.request"
MEMORY_RESPONSE_PATH="/tmp/superserve-snapshot-memory-${RUN_ID}.response"
MEMORY_INPUT_PATH="/tmp/superserve-snapshot-memory-${RUN_ID}.input"
MEMORY_PID_PATH="/tmp/superserve-snapshot-memory-${RUN_ID}.pid"
MEMORY_SERVER_PATH="/tmp/superserve-snapshot-memory-${RUN_ID}.sh"
MEMORY_LOG_PATH="/tmp/superserve-snapshot-memory-${RUN_ID}.log"
IDEMPOTENCY_KEY="snapshot-canary-capture-${RUN_ID}"
PAUSED_IDEMPOTENCY_KEY="snapshot-canary-paused-capture-${RUN_ID}"
SECRET_NAME="snapshot-canary-secret-${RUN_ID}"
SECRET_VALUE="snapshot-canary-value-${RUN_ID}"
SECRET_CREATED=0
SOURCE_SECRET_TOKEN=""

SOURCE_ID=""
SOURCE_TOKEN=""
SNAPSHOT_ID=""
SNAPSHOT_EXCLUSIVE_BYTES=""
PAUSED_SNAPSHOT_ID=""
PAUSED_SNAPSHOT_EXCLUSIVE_BYTES=""
NESTED_FORK_ID=""
NESTED_FORK_TOKEN=""
FORK_IDS=("" "" "")
FORK_TOKENS=("" "" "")
FORK_SECRET_TOKENS=("" "" "")
FORK_FILE_MARKERS=(
  "snapshot-canary-fork-1-${RUN_ID}"
  "snapshot-canary-fork-2-${RUN_ID}"
  "snapshot-canary-fork-3-${RUN_ID}"
)
FORK_MEMORY_MARKERS=(
  "snapshot-canary-memory-fork-1-${RUN_ID}"
  "snapshot-canary-memory-fork-2-${RUN_ID}"
  "snapshot-canary-memory-fork-3-${RUN_ID}"
)
BACKGROUND_PIDS=()
TEMP_DIR="$(mktemp -d)"
SHADOW_STORAGE_BASELINE=""
SHADOW_STORAGE_AFTER_ROOT=""
SHADOW_STORAGE_AFTER_SOURCE_PAUSE=""
SHADOW_STORAGE_BEFORE_PAUSED_SNAPSHOT=""
SHADOW_STORAGE_AFTER_PAUSED=""
SHADOW_STORAGE_BEFORE_DELETE=""
SHADOW_STORAGE_BEFORE_PAUSED_DELETE=""
SHADOW_STORAGE_AFTER_PAUSED_DELETE=""
SHADOW_STORAGE_BEFORE_ROOT_DELETE=""

api_request() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  local idempotency_key="${4:-}"
  local output status rc
  output="$(mktemp "${TEMP_DIR}/api-response.XXXXXX")"
  local args=(
    --silent --show-error --location
    --connect-timeout 15
    --max-time "$API_TIMEOUT_S"
    --output "$output"
    --write-out '%{http_code}'
    --request "$method"
    --header "X-API-Key: ${API_KEY}"
  )
  if [[ -n "$idempotency_key" ]]; then
    args+=(--header "Idempotency-Key: ${idempotency_key}")
  fi
  if [[ -n "$body" ]]; then
    args+=(
      --header 'Content-Type: application/json'
      --data "$body"
    )
  fi

  if status="$(curl "${args[@]}" "${API_BASE_URL}${path}")"; then
    rc=0
  else
    rc=$?
  fi
  if (( rc != 0 )); then
    echo "curl failed for ${method} ${path} (exit ${rc})" >&2
    if [[ -s "$output" ]]; then
      cat "$output" >&2
      echo >&2
    fi
    rm -f "$output"
    return "$rc"
  fi

  printf '%s\n' "$status"
  cat "$output"
  rm -f "$output"
}

exec_request() {
  local sandbox_id="$1"
  local access_token="$2"
  local command="$3"
  local output status rc body
  output="$(mktemp "${TEMP_DIR}/exec-response.XXXXXX")"
  body="$(jq -cn \
    --arg command "$command" \
    --argjson timeout_s "$EXEC_TIMEOUT_S" \
    '{command: $command, timeout_s: $timeout_s}')"

  if status="$(curl --silent --show-error --location \
    --connect-timeout 15 \
    --max-time "$((EXEC_TIMEOUT_S + 15))" \
    --output "$output" \
    --write-out '%{http_code}' \
    --request POST \
    --header "X-Access-Token: ${access_token}" \
    --header "X-Superserve-Sandbox-Id: ${sandbox_id}" \
    --header 'Content-Type: application/json' \
    --data "$body" \
    "${SANDBOX_BASE_URL}/exec")"; then
    rc=0
  else
    rc=$?
  fi
  if (( rc != 0 )); then
    echo "curl failed for sandbox ${sandbox_id} /exec (exit ${rc})" >&2
    if [[ -s "$output" ]]; then
      cat "$output" >&2
      echo >&2
    fi
    rm -f "$output"
    return "$rc"
  fi

  printf '%s\n' "$status"
  cat "$output"
  rm -f "$output"
}

response_status() {
  head -n 1 <<<"$1"
}

response_body() {
  tail -n +2 <<<"$1"
}

fatal() {
  echo "snapshot canary failed: $*" >&2
  exit 1
}

expect_status() {
  local actual="$1"
  local expected="$2"
  local body="$3"
  local operation="$4"
  if [[ "$actual" != "$expected" ]]; then
    echo "${operation}: expected HTTP ${expected}, got ${actual}" >&2
    if [[ -n "$body" ]]; then
      echo "$body" >&2
    fi
    exit 1
  fi
}

expect_dependency_conflict() {
  local body="$1"
  local expected_code="$2"
  local expected_sandbox_count="$3"
  local expected_snapshot_count="$4"
  local operation="$5"
  local code sandbox_count snapshot_count

  code="$(jq -r '.error.code // empty' <<<"$body")"
  sandbox_count="$(jq -er '.error.dependencies.sandbox_count | numbers' <<<"$body")" ||
    fatal "${operation}: dependency response omitted sandbox_count: ${body}"
  snapshot_count="$(jq -er '.error.dependencies.snapshot_count | numbers' <<<"$body")" ||
    fatal "${operation}: dependency response omitted snapshot_count: ${body}"
  if [[ "$code" != "$expected_code" ||
        "$sandbox_count" != "$expected_sandbox_count" ||
        "$snapshot_count" != "$expected_snapshot_count" ]]; then
    fatal "${operation}: got code=${code:-<none>} sandbox_count=${sandbox_count} snapshot_count=${snapshot_count}; want ${expected_code}/${expected_sandbox_count}/${expected_snapshot_count}: ${body}"
  fi
  echo "${operation}: dependency contract passed"
}

wait_for_sandbox_status() {
  local sandbox_id="$1"
  local wanted="$2"
  local deadline=$((SECONDS + POLL_TIMEOUT_S))
  local response status body current

  while (( SECONDS < deadline )); do
    if ! response="$(api_request GET "/sandboxes/${sandbox_id}")"; then
      sleep "$POLL_INTERVAL_S"
      continue
    fi
    status="$(response_status "$response")"
    body="$(response_body "$response")"
    if [[ "$status" != "200" ]]; then
      case "$status" in
        429|500|502|503|504)
          sleep "$POLL_INTERVAL_S"
          continue
          ;;
        *) fatal "get sandbox ${sandbox_id}: expected HTTP 200, got ${status}: ${body}" ;;
      esac
    fi
    current="$(jq -r '.status // empty' <<<"$body")"
    if [[ "$current" == "$wanted" ]]; then
      return 0
    fi
    if [[ "$current" == "failed" || "$current" == "deleted" ]]; then
      fatal "sandbox ${sandbox_id} reached terminal status ${current} while waiting for ${wanted}"
    fi
    sleep "$POLL_INTERVAL_S"
  done

  fatal "sandbox ${sandbox_id} did not reach ${wanted} within ${POLL_TIMEOUT_S}s"
}

wait_for_snapshot_ready() {
  local snapshot_id="$1"
  local expected_source_id="$2"
  local expected_parent_id="${3:-}"
  local deadline=$((SECONDS + POLL_TIMEOUT_S))
  local response status body current source_id parent_id

  while (( SECONDS < deadline )); do
    if ! response="$(api_request GET "/snapshots/${snapshot_id}")"; then
      sleep "$POLL_INTERVAL_S"
      continue
    fi
    status="$(response_status "$response")"
    body="$(response_body "$response")"
    if [[ "$status" != "200" ]]; then
      case "$status" in
        429|500|502|503|504)
          sleep "$POLL_INTERVAL_S"
          continue
          ;;
        *) fatal "get snapshot ${snapshot_id}: expected HTTP 200, got ${status}: ${body}" ;;
      esac
    fi
    current="$(jq -r '.status // empty' <<<"$body")"
    source_id="$(jq -r '.sandbox_id // empty' <<<"$body")"
    parent_id="$(jq -r '.parent_snapshot_id // empty' <<<"$body")"
    if [[ "$current" == "ready" ]]; then
      if [[ "$source_id" != "$expected_source_id" ]]; then
        fatal "snapshot ${snapshot_id} source is ${source_id}, want ${expected_source_id}"
      fi
      if [[ "$parent_id" != "$expected_parent_id" ]]; then
        fatal "snapshot ${snapshot_id} parent is ${parent_id:-<none>}, want ${expected_parent_id:-<none>}"
      fi
      return 0
    fi
    if [[ "$current" == "failed" || "$current" == "unavailable" || "$current" == "deleting" ]]; then
      fatal "snapshot ${snapshot_id} reached terminal status ${current} while waiting for ready"
    fi
    sleep "$POLL_INTERVAL_S"
  done

  fatal "snapshot ${snapshot_id} did not remain ready within ${POLL_TIMEOUT_S}s"
}

pause_sandbox() {
  local sandbox_id="$1"
  local label="$2"
  local response status body

  if ! response="$(api_request POST "/sandboxes/${sandbox_id}/pause")"; then
    fatal "${label}: pause request failed"
  fi
  status="$(response_status "$response")"
  body="$(response_body "$response")"
  expect_status "$status" 204 "$body" "pause ${label}"
  wait_for_sandbox_status "$sandbox_id" paused
}

RESUMED_TOKEN=""
resume_sandbox() {
  local sandbox_id="$1"
  local label="$2"
  local response status body

  if ! response="$(api_request POST "/sandboxes/${sandbox_id}/resume")"; then
    fatal "${label}: resume request failed"
  fi
  status="$(response_status "$response")"
  body="$(response_body "$response")"
  expect_status "$status" 200 "$body" "resume ${label}"
  RESUMED_TOKEN="$(jq -r '.access_token // empty' <<<"$body")"
  if [[ -z "$RESUMED_TOKEN" ]]; then
    fatal "${label}: resume response omitted access_token: ${body}"
  fi
  wait_for_sandbox_status "$sandbox_id" active
}

run_restart_hook() {
  local phase="$1"
  local sandbox_id="$2"
  local snapshot_id="$3"

  if [[ -z "$SNAPSHOT_RESTART_HOOK" ]]; then
    echo "Restart hook skipped for ${phase}; set SNAPSHOT_RESTART_HOOK to exercise infrastructure restarts"
    return 0
  fi
  echo "Running staging restart hook for ${phase}"
  if ! "$SNAPSHOT_RESTART_HOOK" "$phase" "$sandbox_id" "$snapshot_id"; then
    fatal "restart hook failed for ${phase}"
  fi
}

shadow_scalar() {
  local query="$1"
  local description="$2"
  local value
  if [[ -z "$SNAPSHOT_SHADOW_DATABASE_URL" ]]; then
    return 1
  fi
  value="$(psql "$SNAPSHOT_SHADOW_DATABASE_URL" \
    --no-psqlrc --set=ON_ERROR_STOP=1 --tuples-only --no-align \
    --command "$query")" || fatal "could not query ${description}"
  value="${value//$'\n'/}"
  value="${value//[[:space:]]/}"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    fatal "${description} returned an invalid value: ${value:-<empty>}"
  fi
  printf '%s' "$value"
}

shadow_storage_bytes() {
  shadow_scalar \
    "SELECT snapshot_storage_bytes::text FROM team WHERE id = '${SNAPSHOT_TEAM_ID}'::uuid" \
    "team shadow snapshot-storage usage"
}

shadow_layer_total_bytes() {
  shadow_scalar \
    "SELECT COALESCE(sum(retained_exclusive_size_bytes + current_exclusive_size_bytes), 0)::text FROM snapshot_storage_layer WHERE team_id = '${SNAPSHOT_TEAM_ID}'::uuid AND ended_at IS NULL" \
    "active snapshot-storage layer usage"
}

shadow_snapshot_layer_bytes() {
  local snapshot_id="$1"
  if [[ ! "$snapshot_id" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
    fatal "snapshot API returned a non-UUID id: ${snapshot_id}"
  fi
  shadow_scalar \
    "SELECT (retained_exclusive_size_bytes + current_exclusive_size_bytes)::text FROM snapshot_storage_layer WHERE team_id = '${SNAPSHOT_TEAM_ID}'::uuid AND owner_snapshot_id = '${snapshot_id}'::uuid AND ended_at IS NULL" \
    "saved snapshot layer usage for ${snapshot_id}"
}

assert_shadow_storage_bytes() {
  local expected="$1"
  local phase="$2"
  local actual
  if [[ -z "$SNAPSHOT_SHADOW_DATABASE_URL" ]]; then
    return 0
  fi
  actual="$(shadow_storage_bytes)"
  if [[ "$actual" != "$expected" ]]; then
    fatal "${phase}: team shadow storage is ${actual} bytes, want ${expected}"
  fi
  echo "${phase}: team shadow storage is ${actual} bytes"
}

assert_shadow_storage_at_least() {
  local minimum="$1"
  local phase="$2"
  local actual
  if [[ -z "$SNAPSHOT_SHADOW_DATABASE_URL" ]]; then
    return 0
  fi
  actual="$(shadow_storage_bytes)"
  if (( actual < minimum )); then
    fatal "${phase}: team shadow storage is ${actual} bytes, want at least ${minimum}"
  fi
  echo "${phase}: team shadow storage is ${actual} bytes (minimum ${minimum})"
}

assert_shadow_ledger_consistent() {
  local phase="$1"
  local counter layer_total
  if [[ -z "$SNAPSHOT_SHADOW_DATABASE_URL" ]]; then
    return 0
  fi
  counter="$(shadow_storage_bytes)"
  layer_total="$(shadow_layer_total_bytes)"
  if [[ "$counter" != "$layer_total" ]]; then
    fatal "${phase}: team counter is ${counter} bytes but active layers sum to ${layer_total}"
  fi
  echo "${phase}: shadow counter matches active-layer total (${counter} bytes)"
}

assert_shadow_snapshot_layer_bytes() {
  local snapshot_id="$1"
  local expected="$2"
  local phase="$3"
  local actual
  if [[ -z "$SNAPSHOT_SHADOW_DATABASE_URL" ]]; then
    return 0
  fi
  actual="$(shadow_snapshot_layer_bytes "$snapshot_id")"
  if [[ "$actual" != "$expected" ]]; then
    fatal "${phase}: snapshot layer is ${actual} bytes, want ${expected}"
  fi
  echo "${phase}: saved-snapshot layer is ${actual} bytes"
}

exec_expect_stdout() {
  local label="$1"
  local sandbox_id="$2"
  local access_token="$3"
  local command="$4"
  local expected="$5"
  local response status body exit_code stdout

  if ! response="$(exec_request "$sandbox_id" "$access_token" "$command")"; then
    fatal "${label}: /exec request failed"
  fi
  status="$(response_status "$response")"
  body="$(response_body "$response")"
  expect_status "$status" 200 "$body" "${label}"
  if ! exit_code="$(jq -er '.exit_code' <<<"$body")"; then
    fatal "${label}: exec response omitted exit_code: ${body}"
  fi
  stdout="$(jq -r '.stdout // empty' <<<"$body")"
  if [[ "$exit_code" != "0" || "$stdout" != "$expected" ]]; then
    echo "${label}: expected exit 0 and stdout ${expected}" >&2
    echo "$body" >&2
    exit 1
  fi
  echo "${label}: passed"
}

EXEC_STDOUT=""
exec_read_stdout() {
  local label="$1"
  local sandbox_id="$2"
  local access_token="$3"
  local command="$4"
  local response status body exit_code

  if ! response="$(exec_request "$sandbox_id" "$access_token" "$command")"; then
    fatal "${label}: /exec request failed"
  fi
  status="$(response_status "$response")"
  body="$(response_body "$response")"
  expect_status "$status" 200 "$body" "$label"
  if ! exit_code="$(jq -er '.exit_code' <<<"$body")"; then
    fatal "${label}: exec response omitted exit_code: ${body}"
  fi
  if [[ "$exit_code" != "0" ]]; then
    fatal "${label}: expected exit 0: ${body}"
  fi
  EXEC_STDOUT="$(jq -r '.stdout // empty' <<<"$body")"
  echo "${label}: passed"
}

exec_expect_blocked_egress() {
  local label="$1"
  local sandbox_id="$2"
  local access_token="$3"
  exec_expect_stdout \
    "$label" \
    "$sandbox_id" \
    "$access_token" \
    "if curl --silent --show-error --fail --connect-timeout 3 --max-time 5 '${CANARY_EGRESS_TEST_URL}' >/dev/null 2>&1; then printf allowed; else printf blocked; fi" \
    blocked
}

exec_expect_access_token_rejected() {
  local label="$1"
  local sandbox_id="$2"
  local wrong_access_token="$3"
  local response status body

  if ! response="$(exec_request "$sandbox_id" "$wrong_access_token" 'printf should-not-run')"; then
    fatal "${label}: /exec request failed"
  fi
  status="$(response_status "$response")"
  body="$(response_body "$response")"
  case "$status" in
    401|403) echo "${label}: passed" ;;
    *) fatal "${label}: expected HTTP 401/403, got ${status}: ${body}" ;;
  esac
}

memory_request_command() {
  local request="$1"
  printf '%s' "printf '%s\\n' '${request}' > '${MEMORY_REQUEST_PATH}'; cat '${MEMORY_RESPONSE_PATH}'"
}

exec_expect_memory() {
  local label="$1"
  local sandbox_id="$2"
  local access_token="$3"
  local expected="$4"
  exec_expect_stdout \
    "$label" \
    "$sandbox_id" \
    "$access_token" \
    "$(memory_request_command GET)" \
    "$expected"
}

exec_set_memory() {
  local label="$1"
  local sandbox_id="$2"
  local access_token="$3"
  local value="$4"
  exec_expect_stdout \
    "$label" \
    "$sandbox_id" \
    "$access_token" \
    "$(memory_request_command "SET ${value}")" \
    "$value"
}

start_memory_process() {
  local server_code server_b64 command
  server_code="$(printf '%s\n' \
    '#!/bin/sh' \
    'set -eu' \
    'request_path=$1' \
    'response_path=$2' \
    'marker_path=$3' \
    'pid_path=$4' \
    'marker=$(cat "$marker_path")' \
    'rm -f "$marker_path"' \
    'mkfifo "$request_path" "$response_path"' \
    'printf "%s" "$$" > "$pid_path"' \
    'while true; do' \
    '    request=' \
    '    IFS= read -r request < "$request_path" || true' \
    '    case "$request" in' \
    '        "SET "*) marker=${request#SET } ;;' \
    '    esac' \
    '    printf "%s" "$marker" > "$response_path"' \
    'done')"
  server_b64="$(printf '%s' "$server_code" | base64 | tr -d '\n')"
  command="set -eu; rm -f '${MEMORY_REQUEST_PATH}' '${MEMORY_RESPONSE_PATH}' '${MEMORY_PID_PATH}' '${MEMORY_INPUT_PATH}'; printf '%s' '${MEMORY_MARKER}' > '${MEMORY_INPUT_PATH}'; printf '%s' '${server_b64}' | base64 -d > '${MEMORY_SERVER_PATH}'; nohup sh '${MEMORY_SERVER_PATH}' '${MEMORY_REQUEST_PATH}' '${MEMORY_RESPONSE_PATH}' '${MEMORY_INPUT_PATH}' '${MEMORY_PID_PATH}' </dev/null >'${MEMORY_LOG_PATH}' 2>&1 & i=0; while { [ ! -p '${MEMORY_REQUEST_PATH}' ] || [ ! -p '${MEMORY_RESPONSE_PATH}' ]; } && [ \"\$i\" -lt 100 ]; do i=\$((i + 1)); sleep 0.1; done; if [ ! -p '${MEMORY_REQUEST_PATH}' ] || [ ! -p '${MEMORY_RESPONSE_PATH}' ] || [ ! -s '${MEMORY_PID_PATH}' ]; then cat '${MEMORY_LOG_PATH}' >&2 || true; exit 1; fi; pid=\$(cat '${MEMORY_PID_PATH}'); if ! kill -0 \"\$pid\"; then cat '${MEMORY_LOG_PATH}' >&2 || true; exit 1; fi; $(memory_request_command GET)"
  exec_expect_stdout \
    "start source in-memory process" \
    "$SOURCE_ID" \
    "$SOURCE_TOKEN" \
    "$command" \
    "$MEMORY_MARKER"
}

best_effort_delete() {
  local resource="$1"
  local id="$2"
  local path status attempt
  case "$resource" in
    sandbox) path="/sandboxes/${id}" ;;
    snapshot) path="/snapshots/${id}" ;;
    secret) path="/secrets/${id}" ;;
    *) return 0 ;;
  esac

  for attempt in 1 2 3; do
    status="$(curl --silent --show-error \
      --connect-timeout 10 \
      --max-time 30 \
      --output /dev/null \
      --write-out '%{http_code}' \
      --request DELETE \
      --header "X-API-Key: ${API_KEY}" \
      "${API_BASE_URL}${path}" 2>/dev/null || true)"
    if [[ "$status" == "204" || "$status" == "404" ]]; then
      echo "cleanup: deleted ${resource} ${id}"
      return 0
    fi
    sleep "$attempt"
  done
  echo "cleanup: could not delete ${resource} ${id} (last HTTP status: ${status:-curl-error})" >&2
}

force_canary_team_dark() {
  local observed
  observed="$(PGCONNECT_TIMEOUT=3 psql "$SNAPSHOT_SHADOW_DATABASE_URL" \
    --no-psqlrc --quiet --tuples-only --no-align \
    --set=ON_ERROR_STOP=1 \
    --set=team_id="$SNAPSHOT_TEAM_ID" <<'SQL'
BEGIN;
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '5s';
UPDATE public.team_feature_flag
SET enabled = false,
    updated_at = now()
WHERE team_id = :'team_id'::uuid
  AND key = 'sandbox_snapshots_v1'
  AND enabled;
SELECT NOT EXISTS (
  SELECT 1
  FROM public.team_feature_flag
  WHERE team_id = :'team_id'::uuid
    AND key = 'sandbox_snapshots_v1'
    AND enabled
)::text;
COMMIT;
SQL
  )" || return 1
  [[ "$observed" == "true" ]]
}

cleanup() {
  local exit_code=$?
  local pid response status body id
  local darkened=0 attempt
  local recovered_forks=()
  local recovered_nested_forks=()
  local recovered_sources=()
  local recovered_root_snapshots=()
  local recovered_paused_snapshots=()

  trap - EXIT INT TERM
  set +e
  # Bash 3.2 treats an initialized-but-empty array expansion as unbound under
  # nounset. Cleanup is best-effort, so disable nounset before walking arrays.
  set +u

  # Disable snapshot creation before any potentially slow API cleanup. This is
  # deliberately the first side effect in EXIT handling: cancellation grace
  # must make the rollout dark even if host/API cleanup later stalls.
  for attempt in 1 2 3; do
    if force_canary_team_dark; then
      darkened=1
      break
    fi
    echo "cleanup: priority team-disable attempt ${attempt}/3 failed" >&2
    sleep "$attempt"
  done
  if (( darkened == 0 )); then
    echo "cleanup: CRITICAL: could not force sandbox_snapshots_v1 dark for ${SNAPSHOT_TEAM_ID}; skipping slow resource cleanup so the outer workflow can retry immediately" >&2
    rm -rf "$TEMP_DIR"
    exit 1
  fi
  echo "cleanup: canary team feature flag is dark"

  # Let any in-flight fork request finish before discovering tagged resources.
  for pid in "${BACKGROUND_PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
  done

  response="$(api_request GET "/sandboxes?metadata.snapshot_canary_run_id=${RUN_ID}" 2>/dev/null)"
  status="$(response_status "$response")"
  body="$(response_body "$response")"
  if [[ "$status" == "200" ]] && jq -e 'type == "array"' >/dev/null 2>&1 <<<"$body"; then
    while IFS= read -r id; do
      [[ -n "$id" ]] && recovered_forks+=("$id")
    done <<<"$(jq -r '.[] | select(.metadata.snapshot_canary_role == "fork") | .id' <<<"$body")"
    while IFS= read -r id; do
      [[ -n "$id" ]] && recovered_nested_forks+=("$id")
    done <<<"$(jq -r '.[] | select(.metadata.snapshot_canary_role == "nested-fork") | .id' <<<"$body")"
    while IFS= read -r id; do
      [[ -n "$id" ]] && recovered_sources+=("$id")
    done <<<"$(jq -r '.[] | select(.metadata.snapshot_canary_role == "source") | .id' <<<"$body")"
  fi

  # Delete the deepest branch first. Fork 1 owns PAUSED_SNAPSHOT_ID, so that
  # snapshot must be gone before the first-level forks can be deleted.
  for id in "$NESTED_FORK_ID" "${recovered_nested_forks[@]}"; do
    [[ -n "$id" ]] && best_effort_delete sandbox "$id"
  done

  response="$(api_request GET '/snapshots?limit=100' 2>/dev/null)"
  status="$(response_status "$response")"
  body="$(response_body "$response")"
  if [[ "$status" == "200" ]] && jq -e 'type == "array"' >/dev/null 2>&1 <<<"$body"; then
    while IFS= read -r id; do
      [[ -n "$id" ]] && recovered_root_snapshots+=("$id")
    done <<<"$(jq -r --arg name "$SNAPSHOT_NAME" '.[] | select(.name == $name) | .id' <<<"$body")"
    while IFS= read -r id; do
      [[ -n "$id" ]] && recovered_paused_snapshots+=("$id")
    done <<<"$(jq -r --arg name "$PAUSED_SNAPSHOT_NAME" '.[] | select(.name == $name) | .id' <<<"$body")"
  fi

  [[ -n "$PAUSED_SNAPSHOT_ID" ]] && best_effort_delete snapshot "$PAUSED_SNAPSHOT_ID"
  for id in "${recovered_paused_snapshots[@]}"; do
    [[ -n "$id" && "$id" != "$PAUSED_SNAPSHOT_ID" ]] && best_effort_delete snapshot "$id"
  done

  for id in "${FORK_IDS[@]}" "${recovered_forks[@]}"; do
    [[ -n "$id" ]] && best_effort_delete sandbox "$id"
  done

  [[ -n "$SNAPSHOT_ID" ]] && best_effort_delete snapshot "$SNAPSHOT_ID"
  for id in "${recovered_root_snapshots[@]}"; do
    [[ -n "$id" && "$id" != "$SNAPSHOT_ID" ]] && best_effort_delete snapshot "$id"
  done

  [[ -n "$SOURCE_ID" ]] && best_effort_delete sandbox "$SOURCE_ID"
  for id in "${recovered_sources[@]}"; do
    [[ -n "$id" && "$id" != "$SOURCE_ID" ]] && best_effort_delete sandbox "$id"
  done

  if [[ "$SECRET_CREATED" == "1" ]]; then
    best_effort_delete secret "$SECRET_NAME"
  fi

  rm -rf "$TEMP_DIR"
  exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

SHADOW_STORAGE_BASELINE="$(shadow_storage_bytes)"
echo "Initial team shadow snapshot storage: ${SHADOW_STORAGE_BASELINE} bytes"

source_secrets='{}'
if [[ "$SKIP_SNAPSHOT_SECRET_CHECKS" == "0" ]]; then
  echo "Creating canary secret binding ${SECRET_NAME}"
  secret_body="$(jq -cn \
    --arg name "$SECRET_NAME" \
    --arg value "$SECRET_VALUE" \
    '{name: $name, value: $value, provider: "openai"}')"
  if ! response="$(api_request POST /secrets "$secret_body")"; then
    fatal "canary secret create request failed"
  fi
  status="$(response_status "$response")"
  body="$(response_body "$response")"
  expect_status "$status" 201 "$body" "create canary secret"
  SECRET_CREATED=1
  source_secrets="$(jq -cn --arg secret_name "$SECRET_NAME" '{SNAPSHOT_CANARY_SECRET: $secret_name}')"
fi

echo "Creating active source sandbox ${SOURCE_NAME}"
source_body="$(jq -cn \
  --arg name "$SOURCE_NAME" \
  --arg template "$SANDBOX_TEMPLATE" \
  --arg run_id "$RUN_ID" \
  --argjson source_secrets "$source_secrets" \
  '{
    name: $name,
    from_template: $template,
    timeout_seconds: 1800,
    network: {
      allow_out: [],
      deny_out: ["0.0.0.0/0"]
    },
    metadata: {
      snapshot_canary: "true",
      snapshot_canary_role: "source",
      snapshot_canary_run_id: $run_id
    }
  } + if ($source_secrets | length) > 0 then {secrets: $source_secrets} else {} end')"
if ! response="$(api_request POST /sandboxes "$source_body")"; then
  fatal "source sandbox create request failed"
fi
status="$(response_status "$response")"
body="$(response_body "$response")"
expect_status "$status" 201 "$body" "create source sandbox"
SOURCE_ID="$(jq -r '.id // empty' <<<"$body")"
SOURCE_TOKEN="$(jq -r '.access_token // empty' <<<"$body")"
if [[ -z "$SOURCE_ID" || -z "$SOURCE_TOKEN" ]]; then
  fatal "source create response omitted id or access_token: ${body}"
fi
if ! jq -e '.network.deny_out | index("0.0.0.0/0") != null' >/dev/null <<<"$body"; then
  fatal "source response omitted the deny-all egress policy: ${body}"
fi
wait_for_sandbox_status "$SOURCE_ID" active

if [[ "$SKIP_SNAPSHOT_SECRET_CHECKS" == "0" ]]; then
  exec_read_stdout \
    "read source secret proxy token" \
    "$SOURCE_ID" \
    "$SOURCE_TOKEN" \
    'test -n "$SNAPSHOT_CANARY_SECRET" && printf "%s" "$SNAPSHOT_CANARY_SECRET"'
  SOURCE_SECRET_TOKEN="$EXEC_STDOUT"
  if [[ -z "$SOURCE_SECRET_TOKEN" || "$SOURCE_SECRET_TOKEN" == "$SECRET_VALUE" ]]; then
    fatal "source did not receive an opaque proxy token for its secret binding"
  fi
fi
exec_expect_blocked_egress \
  "source deny-all egress policy" \
  "$SOURCE_ID" \
  "$SOURCE_TOKEN"

write_source_command="printf '%s' '${SOURCE_MARKER}' > '${STATE_PATH}'"
exec_expect_stdout \
  "write source state" \
  "$SOURCE_ID" \
  "$SOURCE_TOKEN" \
  "${write_source_command} && cat '${STATE_PATH}'" \
  "$SOURCE_MARKER"
start_memory_process

echo "Capturing active source sandbox ${SOURCE_ID}"
snapshot_body="$(jq -cn --arg name "$SNAPSHOT_NAME" '{name: $name}')"
if ! response="$(api_request POST "/sandboxes/${SOURCE_ID}/snapshots" "$snapshot_body" "$IDEMPOTENCY_KEY")"; then
  fatal "saved snapshot capture request failed"
fi
status="$(response_status "$response")"
body="$(response_body "$response")"
expect_status "$status" 201 "$body" "capture saved snapshot"
SNAPSHOT_ID="$(jq -r '.id // empty' <<<"$body")"
snapshot_status="$(jq -r '.status // empty' <<<"$body")"
snapshot_source_id="$(jq -r '.sandbox_id // empty' <<<"$body")"
if [[ -z "$SNAPSHOT_ID" || "$snapshot_status" != "ready" || "$snapshot_source_id" != "$SOURCE_ID" ]]; then
  fatal "capture response did not describe a ready snapshot of the source: ${body}"
fi
if ! SNAPSHOT_EXCLUSIVE_BYTES="$(jq -er '.exclusive_size_bytes | numbers' <<<"$body")" ||
   ! snapshot_logical_bytes="$(jq -er '.logical_size_bytes | numbers' <<<"$body")"; then
  fatal "capture response omitted layer-byte observability: ${body}"
fi
if (( SNAPSHOT_EXCLUSIVE_BYTES < 0 || snapshot_logical_bytes < 0 )); then
  fatal "capture returned invalid logical/exclusive byte accounting: ${body}"
fi
if [[ -n "$SNAPSHOT_SHADOW_DATABASE_URL" ]]; then
  # The ledger retains both the source's newly shared generation and the
  # snapshot-owned layer. Source bytes are host-private metadata, so observe
  # the committed counter instead of deriving it only from the public
  # snapshot.exclusive_size_bytes field.
  SHADOW_STORAGE_AFTER_ROOT="$(shadow_storage_bytes)"
  assert_shadow_storage_at_least "$((SHADOW_STORAGE_BASELINE + SNAPSHOT_EXCLUSIVE_BYTES))" "active snapshot commit"
  assert_shadow_snapshot_layer_bytes "$SNAPSHOT_ID" "$SNAPSHOT_EXCLUSIVE_BYTES" "active snapshot commit"
  assert_shadow_ledger_consistent "active snapshot commit"
fi

echo "Retrying active capture with the same Idempotency-Key"
if ! response="$(api_request POST "/sandboxes/${SOURCE_ID}/snapshots" "$snapshot_body" "$IDEMPOTENCY_KEY")"; then
  fatal "idempotent saved snapshot retry failed"
fi
status="$(response_status "$response")"
body="$(response_body "$response")"
expect_status "$status" 201 "$body" "retry saved snapshot capture"
retry_snapshot_id="$(jq -r '.id // empty' <<<"$body")"
retry_exclusive_bytes="$(jq -er '.exclusive_size_bytes | numbers' <<<"$body")" ||
  fatal "idempotent retry omitted exclusive byte accounting: ${body}"
retry_logical_bytes="$(jq -er '.logical_size_bytes | numbers' <<<"$body")" ||
  fatal "idempotent retry omitted logical byte accounting: ${body}"
if [[ "$retry_snapshot_id" != "$SNAPSHOT_ID" ||
      "$retry_exclusive_bytes" != "$SNAPSHOT_EXCLUSIVE_BYTES" ||
      "$retry_logical_bytes" != "$snapshot_logical_bytes" ]]; then
  fatal "idempotent retry changed snapshot identity or byte accounting: ${body}"
fi
assert_shadow_storage_bytes "$SHADOW_STORAGE_AFTER_ROOT" "idempotent capture retry"
assert_shadow_snapshot_layer_bytes "$SNAPSHOT_ID" "$SNAPSHOT_EXCLUSIVE_BYTES" "idempotent capture retry"
assert_shadow_ledger_consistent "idempotent capture retry"

echo "Proving the source cannot be deleted while its saved snapshot exists"
response="$(api_request DELETE "/sandboxes/${SOURCE_ID}")"
status="$(response_status "$response")"
body="$(response_body "$response")"
expect_status "$status" 409 "$body" "delete source with saved snapshot"
expect_dependency_conflict "$body" sandbox_has_snapshots 0 1 "delete source with saved snapshot"
if ! jq -e --arg snapshot_id "$SNAPSHOT_ID" \
  '.error.dependencies.snapshot_ids | index($snapshot_id) != null' >/dev/null <<<"$body"; then
  fatal "source dependency response omitted saved snapshot ${SNAPSHOT_ID}: ${body}"
fi

# Active capture must return the source to active and leave it usable.
wait_for_sandbox_status "$SOURCE_ID" active
exec_expect_stdout \
  "source after active capture" \
  "$SOURCE_ID" \
  "$SOURCE_TOKEN" \
  "cat '${STATE_PATH}'" \
  "$SOURCE_MARKER"
exec_expect_memory \
  "source live process after active capture" \
  "$SOURCE_ID" \
  "$SOURCE_TOKEN" \
  "$MEMORY_MARKER"

run_restart_hook after-active-capture "$SOURCE_ID" "$SNAPSHOT_ID"
wait_for_snapshot_ready "$SNAPSHOT_ID" "$SOURCE_ID"
wait_for_sandbox_status "$SOURCE_ID" active
exec_expect_stdout \
  "source file after active-capture restart hook" \
  "$SOURCE_ID" \
  "$SOURCE_TOKEN" \
  "cat '${STATE_PATH}'" \
  "$SOURCE_MARKER"
exec_expect_memory \
  "source live process after active-capture restart hook" \
  "$SOURCE_ID" \
  "$SOURCE_TOKEN" \
  "$MEMORY_MARKER"

echo "Creating three forks concurrently from snapshot ${SNAPSHOT_ID}"
for i in 0 1 2; do
  fork_preview_access=""
  if (( i == 0 )); then
    fork_preview_access="private"
  fi
  fork_body="$(jq -cn \
    --arg name "snapshot-canary-fork-$((i + 1))-${RUN_ID}" \
    --arg snapshot_id "$SNAPSHOT_ID" \
    --arg run_id "$RUN_ID" \
    --arg fork_index "$((i + 1))" \
    --arg preview_access "$fork_preview_access" \
    '{
      name: $name,
      from_snapshot: $snapshot_id,
      metadata: {
        snapshot_canary: "true",
        snapshot_canary_role: "fork",
        snapshot_canary_run_id: $run_id,
        snapshot_canary_fork_index: $fork_index
      }
    } + if $preview_access != "" then {preview_access: $preview_access} else {} end')"
  api_request POST /sandboxes "$fork_body" >"${TEMP_DIR}/fork-${i}.response" &
  BACKGROUND_PIDS+=("$!")
done

fork_request_failed=0
for pid in "${BACKGROUND_PIDS[@]}"; do
  if ! wait "$pid"; then
    fork_request_failed=1
  fi
done
BACKGROUND_PIDS=()

for i in 0 1 2; do
  fork_response_file="${TEMP_DIR}/fork-${i}.response"
  if [[ ! -s "$fork_response_file" ]]; then
    echo "fork $((i + 1)): request returned no response" >&2
    fork_request_failed=1
    continue
  fi
  response="$(<"$fork_response_file")"
  status="$(response_status "$response")"
  body="$(response_body "$response")"
  if [[ "$status" != "201" ]]; then
    echo "fork $((i + 1)): expected HTTP 201, got ${status}" >&2
    echo "$body" >&2
    fork_request_failed=1
    continue
  fi
  FORK_IDS[$i]="$(jq -r '.id // empty' <<<"$body")"
  FORK_TOKENS[$i]="$(jq -r '.access_token // empty' <<<"$body")"
  fork_source_snapshot="$(jq -r '.source_snapshot_id // empty' <<<"$body")"
  if [[ -z "${FORK_IDS[$i]}" || -z "${FORK_TOKENS[$i]}" || "$fork_source_snapshot" != "$SNAPSHOT_ID" ]]; then
    echo "fork $((i + 1)): response omitted identity/token/lineage" >&2
    echo "$body" >&2
    fork_request_failed=1
  fi
  if (( i == 0 )) && [[ "$(jq -r '.preview_access // empty' <<<"$body")" != "private" ]]; then
    echo "fork 1: explicit private preview_access was not preserved" >&2
    echo "$body" >&2
    fork_request_failed=1
  fi
  if ! jq -e '.network.deny_out | index("0.0.0.0/0") != null' >/dev/null <<<"$body"; then
    echo "fork $((i + 1)): response omitted inherited deny-all egress policy" >&2
    echo "$body" >&2
    fork_request_failed=1
  fi
done
if (( fork_request_failed != 0 )); then
  fatal "one or more concurrent fork creates failed"
fi

# Fan-out references the same immutable layers. Creating three forks must not
# mutate either the public snapshot measurement or the team shadow counter.
response="$(api_request GET "/snapshots/${SNAPSHOT_ID}")"
status="$(response_status "$response")"
body="$(response_body "$response")"
expect_status "$status" 200 "$body" "read snapshot after fan-out"
fanout_exclusive_bytes="$(jq -er '.exclusive_size_bytes | numbers' <<<"$body")" ||
  fatal "snapshot read omitted exclusive byte accounting: ${body}"
if [[ "$fanout_exclusive_bytes" != "$SNAPSHOT_EXCLUSIVE_BYTES" ]]; then
  fatal "fan-out changed shared-layer exclusive bytes from ${SNAPSHOT_EXCLUSIVE_BYTES} to ${fanout_exclusive_bytes}"
fi
if [[ -n "$SNAPSHOT_SHADOW_DATABASE_URL" ]]; then
  assert_shadow_storage_bytes "$SHADOW_STORAGE_AFTER_ROOT" "three-fork fan-out"
  assert_shadow_ledger_consistent "three-fork fan-out"
fi

for i in 0 1 2; do
  wait_for_sandbox_status "${FORK_IDS[$i]}" active
  if (( i == 0 )); then
    response="$(api_request GET "/sandboxes/${FORK_IDS[$i]}")"
    status="$(response_status "$response")"
    body="$(response_body "$response")"
    expect_status "$status" 200 "$body" "read explicit private fork"
    if [[ "$(jq -r '.preview_access // empty' <<<"$body")" != "private" ]]; then
      fatal "fork 1 lost explicit private preview_access after restore: ${body}"
    fi
  fi
  if [[ "$SKIP_SNAPSHOT_SECRET_CHECKS" == "0" ]]; then
    exec_read_stdout \
      "fork $((i + 1)) fresh secret proxy token" \
      "${FORK_IDS[$i]}" \
      "${FORK_TOKENS[$i]}" \
      'test -n "$SNAPSHOT_CANARY_SECRET" && printf "%s" "$SNAPSHOT_CANARY_SECRET"'
    FORK_SECRET_TOKENS[$i]="$EXEC_STDOUT"
    if [[ -z "${FORK_SECRET_TOKENS[$i]}" ||
          "${FORK_SECRET_TOKENS[$i]}" == "$SOURCE_SECRET_TOKEN" ||
          "${FORK_SECRET_TOKENS[$i]}" == "$SECRET_VALUE" ]]; then
      fatal "fork $((i + 1)) reused a source/plaintext secret credential"
    fi
    for previous in 0 1 2; do
      if (( previous < i )) && [[ "${FORK_SECRET_TOKENS[$i]}" == "${FORK_SECRET_TOKENS[$previous]}" ]]; then
        fatal "fork $((i + 1)) reused fork $((previous + 1))'s secret proxy token"
      fi
    done
  fi
  exec_expect_access_token_rejected \
    "fork $((i + 1)) rejects source access token" \
    "${FORK_IDS[$i]}" \
    "$SOURCE_TOKEN"
  exec_expect_blocked_egress \
    "fork $((i + 1)) inherited deny-all egress policy" \
    "${FORK_IDS[$i]}" \
    "${FORK_TOKENS[$i]}"
  exec_expect_stdout \
    "fork $((i + 1)) restored source state" \
    "${FORK_IDS[$i]}" \
    "${FORK_TOKENS[$i]}" \
    "cat '${STATE_PATH}'" \
    "$SOURCE_MARKER"
  exec_expect_memory \
    "fork $((i + 1)) restored live process state" \
    "${FORK_IDS[$i]}" \
    "${FORK_TOKENS[$i]}" \
    "$MEMORY_MARKER"
done

echo "Mutating source and every fork independently"
exec_expect_stdout \
  "source file mutation" \
  "$SOURCE_ID" \
  "$SOURCE_TOKEN" \
  "printf '%s' '${SOURCE_MUTATED_MARKER}' > '${STATE_PATH}' && cat '${STATE_PATH}'" \
  "$SOURCE_MUTATED_MARKER"
exec_set_memory \
  "source in-memory mutation" \
  "$SOURCE_ID" \
  "$SOURCE_TOKEN" \
  "$SOURCE_MEMORY_MARKER"

for i in 0 1 2; do
  exec_expect_stdout \
    "fork $((i + 1)) file mutation" \
    "${FORK_IDS[$i]}" \
    "${FORK_TOKENS[$i]}" \
    "printf '%s' '${FORK_FILE_MARKERS[$i]}' > '${STATE_PATH}' && cat '${STATE_PATH}'" \
    "${FORK_FILE_MARKERS[$i]}"
  exec_set_memory \
    "fork $((i + 1)) in-memory mutation" \
    "${FORK_IDS[$i]}" \
    "${FORK_TOKENS[$i]}" \
    "${FORK_MEMORY_MARKERS[$i]}"
done

exec_expect_stdout "source file isolation" "$SOURCE_ID" "$SOURCE_TOKEN" "cat '${STATE_PATH}'" "$SOURCE_MUTATED_MARKER"
exec_expect_memory "source memory isolation" "$SOURCE_ID" "$SOURCE_TOKEN" "$SOURCE_MEMORY_MARKER"
for i in 0 1 2; do
  exec_expect_stdout \
    "fork $((i + 1)) file isolation" \
    "${FORK_IDS[$i]}" \
    "${FORK_TOKENS[$i]}" \
    "cat '${STATE_PATH}'" \
    "${FORK_FILE_MARKERS[$i]}"
  exec_expect_memory \
    "fork $((i + 1)) memory isolation" \
    "${FORK_IDS[$i]}" \
    "${FORK_TOKENS[$i]}" \
    "${FORK_MEMORY_MARKERS[$i]}"
done

echo "Pausing and resuming the original source"
pause_sandbox "$SOURCE_ID" source
resume_sandbox "$SOURCE_ID" source
SOURCE_TOKEN="$RESUMED_TOKEN"
if [[ -n "$SNAPSHOT_SHADOW_DATABASE_URL" ]]; then
  SHADOW_STORAGE_AFTER_SOURCE_PAUSE="$(shadow_storage_bytes)"
  if (( SHADOW_STORAGE_AFTER_SOURCE_PAUSE < SHADOW_STORAGE_AFTER_ROOT )); then
    fatal "source pause measurement reduced shadow storage from ${SHADOW_STORAGE_AFTER_ROOT} to ${SHADOW_STORAGE_AFTER_SOURCE_PAUSE}"
  fi
  assert_shadow_ledger_consistent "source pause-time writable measurement"
fi
exec_expect_stdout "source file after pause/resume" "$SOURCE_ID" "$SOURCE_TOKEN" "cat '${STATE_PATH}'" "$SOURCE_MUTATED_MARKER"
exec_expect_memory "source process after pause/resume" "$SOURCE_ID" "$SOURCE_TOKEN" "$SOURCE_MEMORY_MARKER"

echo "Capturing a saved snapshot while fork 1 is paused"
pause_sandbox "${FORK_IDS[0]}" "fork 1"
if [[ -n "$SNAPSHOT_SHADOW_DATABASE_URL" ]]; then
  SHADOW_STORAGE_BEFORE_PAUSED_SNAPSHOT="$(shadow_storage_bytes)"
  if (( SHADOW_STORAGE_BEFORE_PAUSED_SNAPSHOT < SHADOW_STORAGE_AFTER_SOURCE_PAUSE )); then
    fatal "fork pause measurement reduced shadow storage from ${SHADOW_STORAGE_AFTER_SOURCE_PAUSE} to ${SHADOW_STORAGE_BEFORE_PAUSED_SNAPSHOT}"
  fi
  assert_shadow_ledger_consistent "fork 1 pause-time writable measurement"
fi
paused_snapshot_body="$(jq -cn --arg name "$PAUSED_SNAPSHOT_NAME" '{name: $name}')"
if ! response="$(api_request POST "/sandboxes/${FORK_IDS[0]}/snapshots" "$paused_snapshot_body" "$PAUSED_IDEMPOTENCY_KEY")"; then
  fatal "paused-source saved snapshot capture request failed"
fi
status="$(response_status "$response")"
body="$(response_body "$response")"
expect_status "$status" 201 "$body" "capture paused-source saved snapshot"
PAUSED_SNAPSHOT_ID="$(jq -r '.id // empty' <<<"$body")"
paused_snapshot_status="$(jq -r '.status // empty' <<<"$body")"
paused_snapshot_source_id="$(jq -r '.sandbox_id // empty' <<<"$body")"
paused_snapshot_parent_id="$(jq -r '.parent_snapshot_id // empty' <<<"$body")"
if [[ -z "$PAUSED_SNAPSHOT_ID" || "$paused_snapshot_status" != "ready" ||
      "$paused_snapshot_source_id" != "${FORK_IDS[0]}" || "$paused_snapshot_parent_id" != "$SNAPSHOT_ID" ]]; then
  fatal "paused capture response has incorrect state or lineage: ${body}"
fi
if ! PAUSED_SNAPSHOT_EXCLUSIVE_BYTES="$(jq -er '.exclusive_size_bytes | numbers' <<<"$body")" ||
   ! paused_snapshot_logical_bytes="$(jq -er '.logical_size_bytes | numbers' <<<"$body")"; then
  fatal "paused capture response omitted layer-byte accounting: ${body}"
fi
if (( PAUSED_SNAPSHOT_EXCLUSIVE_BYTES < 0 || paused_snapshot_logical_bytes < 0 )); then
  fatal "paused capture returned invalid logical/exclusive byte accounting: ${body}"
fi
wait_for_sandbox_status "${FORK_IDS[0]}" paused
if [[ -n "$SNAPSHOT_SHADOW_DATABASE_URL" ]]; then
  # Sealing fork 1 transfers its already measured current generation into
  # retained bytes without charging it twice; only the new snapshot-owned
  # layer should increase the observed team counter.
  SHADOW_STORAGE_AFTER_PAUSED=$((SHADOW_STORAGE_BEFORE_PAUSED_SNAPSHOT + PAUSED_SNAPSHOT_EXCLUSIVE_BYTES))
  assert_shadow_storage_bytes "$SHADOW_STORAGE_AFTER_PAUSED" "paused snapshot commit"
  assert_shadow_snapshot_layer_bytes "$PAUSED_SNAPSHOT_ID" "$PAUSED_SNAPSHOT_EXCLUSIVE_BYTES" "paused snapshot commit"
  assert_shadow_ledger_consistent "paused snapshot commit"
fi

run_restart_hook after-paused-capture "${FORK_IDS[0]}" "$PAUSED_SNAPSHOT_ID"
wait_for_snapshot_ready "$PAUSED_SNAPSHOT_ID" "${FORK_IDS[0]}" "$SNAPSHOT_ID"
wait_for_sandbox_status "${FORK_IDS[0]}" paused
resume_sandbox "${FORK_IDS[0]}" "fork 1 after paused capture"
FORK_TOKENS[0]="$RESUMED_TOKEN"
exec_expect_stdout \
  "fork 1 file after paused capture/resume" \
  "${FORK_IDS[0]}" \
  "${FORK_TOKENS[0]}" \
  "cat '${STATE_PATH}'" \
  "${FORK_FILE_MARKERS[0]}"
exec_expect_memory \
  "fork 1 process after paused capture/resume" \
  "${FORK_IDS[0]}" \
  "${FORK_TOKENS[0]}" \
  "${FORK_MEMORY_MARKERS[0]}"

echo "Creating a nested fork from paused-source snapshot ${PAUSED_SNAPSHOT_ID}"
nested_body="$(jq -cn \
  --arg name "snapshot-canary-nested-${RUN_ID}" \
  --arg snapshot_id "$PAUSED_SNAPSHOT_ID" \
  --arg run_id "$RUN_ID" \
  '{
    name: $name,
    from_snapshot: $snapshot_id,
    metadata: {
      snapshot_canary: "true",
      snapshot_canary_role: "nested-fork",
      snapshot_canary_run_id: $run_id
    }
  }')"
if ! response="$(api_request POST /sandboxes "$nested_body")"; then
  fatal "nested fork create request failed"
fi
status="$(response_status "$response")"
body="$(response_body "$response")"
expect_status "$status" 201 "$body" "create nested fork"
NESTED_FORK_ID="$(jq -r '.id // empty' <<<"$body")"
NESTED_FORK_TOKEN="$(jq -r '.access_token // empty' <<<"$body")"
nested_source_snapshot="$(jq -r '.source_snapshot_id // empty' <<<"$body")"
if [[ -z "$NESTED_FORK_ID" || -z "$NESTED_FORK_TOKEN" || "$nested_source_snapshot" != "$PAUSED_SNAPSHOT_ID" ]]; then
  fatal "nested fork response omitted identity/token/lineage: ${body}"
fi
if ! jq -e '.network.deny_out | index("0.0.0.0/0") != null' >/dev/null <<<"$body"; then
  fatal "nested fork response omitted inherited deny-all egress policy: ${body}"
fi
wait_for_sandbox_status "$NESTED_FORK_ID" active
if [[ "$SKIP_SNAPSHOT_SECRET_CHECKS" == "0" ]]; then
  exec_read_stdout \
    "nested fork fresh secret proxy token" \
    "$NESTED_FORK_ID" \
    "$NESTED_FORK_TOKEN" \
    'test -n "$SNAPSHOT_CANARY_SECRET" && printf "%s" "$SNAPSHOT_CANARY_SECRET"'
  NESTED_SECRET_TOKEN="$EXEC_STDOUT"
  if [[ -z "$NESTED_SECRET_TOKEN" || "$NESTED_SECRET_TOKEN" == "$SOURCE_SECRET_TOKEN" ||
        "$NESTED_SECRET_TOKEN" == "${FORK_SECRET_TOKENS[0]}" || "$NESTED_SECRET_TOKEN" == "$SECRET_VALUE" ]]; then
    fatal "nested fork reused an ancestor/plaintext secret credential"
  fi
fi
exec_expect_access_token_rejected \
  "nested fork rejects parent access token" \
  "$NESTED_FORK_ID" \
  "${FORK_TOKENS[0]}"
exec_expect_blocked_egress \
  "nested fork inherited deny-all egress policy" \
  "$NESTED_FORK_ID" \
  "$NESTED_FORK_TOKEN"
if [[ -n "$SNAPSHOT_SHADOW_DATABASE_URL" ]]; then
  assert_shadow_storage_bytes "$SHADOW_STORAGE_AFTER_PAUSED" "nested-fork fan-out"
  assert_shadow_ledger_consistent "nested-fork fan-out"
fi

echo "Proving the root snapshot cannot be deleted with child sandboxes and snapshots"
response="$(api_request DELETE "/snapshots/${SNAPSHOT_ID}")"
status="$(response_status "$response")"
body="$(response_body "$response")"
expect_status "$status" 409 "$body" "delete root snapshot with descendants"
expect_dependency_conflict "$body" snapshot_has_dependents 3 1 "delete root snapshot with descendants"
if ! jq -e --arg snapshot_id "$PAUSED_SNAPSHOT_ID" \
  '.error.dependencies.snapshot_ids | index($snapshot_id) != null' >/dev/null <<<"$body"; then
  fatal "root dependency response omitted child snapshot ${PAUSED_SNAPSHOT_ID}: ${body}"
fi
for id in "${FORK_IDS[@]}"; do
  if ! jq -e --arg sandbox_id "$id" \
    '.error.dependencies.sandbox_ids | index($sandbox_id) != null' >/dev/null <<<"$body"; then
    fatal "root dependency response omitted child sandbox ${id}: ${body}"
  fi
done

exec_expect_stdout \
  "nested fork restored fork 1 file state" \
  "$NESTED_FORK_ID" \
  "$NESTED_FORK_TOKEN" \
  "cat '${STATE_PATH}'" \
  "${FORK_FILE_MARKERS[0]}"
exec_expect_memory \
  "nested fork restored fork 1 in-memory state" \
  "$NESTED_FORK_ID" \
  "$NESTED_FORK_TOKEN" \
  "${FORK_MEMORY_MARKERS[0]}"

NESTED_FILE_MARKER="snapshot-canary-nested-${RUN_ID}"
NESTED_MEMORY_MARKER="snapshot-canary-memory-nested-${RUN_ID}"
exec_expect_stdout \
  "nested fork file mutation" \
  "$NESTED_FORK_ID" \
  "$NESTED_FORK_TOKEN" \
  "printf '%s' '${NESTED_FILE_MARKER}' > '${STATE_PATH}' && cat '${STATE_PATH}'" \
  "$NESTED_FILE_MARKER"
exec_set_memory \
  "nested fork in-memory mutation" \
  "$NESTED_FORK_ID" \
  "$NESTED_FORK_TOKEN" \
  "$NESTED_MEMORY_MARKER"
exec_expect_stdout \
  "fork 1 remains isolated from nested fork" \
  "${FORK_IDS[0]}" \
  "${FORK_TOKENS[0]}" \
  "cat '${STATE_PATH}'" \
  "${FORK_FILE_MARKERS[0]}"
exec_expect_memory \
  "fork 1 memory remains isolated from nested fork" \
  "${FORK_IDS[0]}" \
  "${FORK_TOKENS[0]}" \
  "${FORK_MEMORY_MARKERS[0]}"

echo "Pausing and resuming every remaining fork"
for i in 1 2; do
  pause_sandbox "${FORK_IDS[$i]}" "fork $((i + 1))"
  resume_sandbox "${FORK_IDS[$i]}" "fork $((i + 1))"
  FORK_TOKENS[$i]="$RESUMED_TOKEN"
  exec_expect_stdout \
    "fork $((i + 1)) file after pause/resume" \
    "${FORK_IDS[$i]}" \
    "${FORK_TOKENS[$i]}" \
    "cat '${STATE_PATH}'" \
    "${FORK_FILE_MARKERS[$i]}"
  exec_expect_memory \
    "fork $((i + 1)) process after pause/resume" \
    "${FORK_IDS[$i]}" \
    "${FORK_TOKENS[$i]}" \
    "${FORK_MEMORY_MARKERS[$i]}"
done
pause_sandbox "$NESTED_FORK_ID" "nested fork"
resume_sandbox "$NESTED_FORK_ID" "nested fork"
NESTED_FORK_TOKEN="$RESUMED_TOKEN"
exec_expect_stdout \
  "nested fork file after pause/resume" \
  "$NESTED_FORK_ID" \
  "$NESTED_FORK_TOKEN" \
  "cat '${STATE_PATH}'" \
  "$NESTED_FILE_MARKER"
exec_expect_memory \
  "nested fork process after pause/resume" \
  "$NESTED_FORK_ID" \
  "$NESTED_FORK_TOKEN" \
  "$NESTED_MEMORY_MARKER"

if [[ -n "$SNAPSHOT_SHADOW_DATABASE_URL" ]]; then
  SHADOW_STORAGE_BEFORE_DELETE="$(shadow_storage_bytes)"
  if (( SHADOW_STORAGE_BEFORE_DELETE < SHADOW_STORAGE_AFTER_PAUSED )); then
    fatal "pause-time fork measurements reduced shadow storage from ${SHADOW_STORAGE_AFTER_PAUSED} to ${SHADOW_STORAGE_BEFORE_DELETE}"
  fi
  assert_shadow_ledger_consistent "all fork pause-time writable measurements"
fi

echo "Deleting the nested branch, first-level forks, snapshots, and source"
response="$(api_request DELETE "/sandboxes/${NESTED_FORK_ID}")"
status="$(response_status "$response")"
body="$(response_body "$response")"
expect_status "$status" 204 "$body" "delete nested fork"
NESTED_FORK_ID=""
if [[ -n "$SNAPSHOT_SHADOW_DATABASE_URL" ]]; then
  SHADOW_STORAGE_BEFORE_PAUSED_DELETE="$(shadow_storage_bytes)"
  if (( SHADOW_STORAGE_BEFORE_PAUSED_DELETE > SHADOW_STORAGE_BEFORE_DELETE )); then
    fatal "nested-fork deletion increased shadow storage from ${SHADOW_STORAGE_BEFORE_DELETE} to ${SHADOW_STORAGE_BEFORE_PAUSED_DELETE}"
  fi
  assert_shadow_ledger_consistent "nested-fork layer release"
fi

response="$(api_request DELETE "/snapshots/${PAUSED_SNAPSHOT_ID}")"
status="$(response_status "$response")"
body="$(response_body "$response")"
expect_status "$status" 204 "$body" "delete paused-source snapshot"
PAUSED_SNAPSHOT_ID=""
if [[ -n "$SNAPSHOT_SHADOW_DATABASE_URL" ]]; then
  SHADOW_STORAGE_AFTER_PAUSED_DELETE=$((SHADOW_STORAGE_BEFORE_PAUSED_DELETE - PAUSED_SNAPSHOT_EXCLUSIVE_BYTES))
  if (( SHADOW_STORAGE_AFTER_PAUSED_DELETE < 0 )); then
    fatal "paused snapshot deletion accounting underflow"
  fi
  assert_shadow_storage_bytes "$SHADOW_STORAGE_AFTER_PAUSED_DELETE" "paused snapshot deletion"
  assert_shadow_ledger_consistent "paused snapshot deletion"
fi

for i in 0 1 2; do
  response="$(api_request DELETE "/sandboxes/${FORK_IDS[$i]}")"
  status="$(response_status "$response")"
  body="$(response_body "$response")"
  expect_status "$status" 204 "$body" "delete fork $((i + 1))"
  FORK_IDS[$i]=""
done

if [[ -n "$SNAPSHOT_SHADOW_DATABASE_URL" ]]; then
  SHADOW_STORAGE_BEFORE_ROOT_DELETE="$(shadow_storage_bytes)"
  if (( SHADOW_STORAGE_BEFORE_ROOT_DELETE > SHADOW_STORAGE_AFTER_PAUSED_DELETE )); then
    fatal "first-level fork deletion increased shadow storage from ${SHADOW_STORAGE_AFTER_PAUSED_DELETE} to ${SHADOW_STORAGE_BEFORE_ROOT_DELETE}"
  fi
  assert_shadow_ledger_consistent "first-level fork layer release"
fi

response="$(api_request DELETE "/snapshots/${SNAPSHOT_ID}")"
status="$(response_status "$response")"
body="$(response_body "$response")"
expect_status "$status" 204 "$body" "delete saved snapshot"
SNAPSHOT_ID=""
if [[ -n "$SNAPSHOT_SHADOW_DATABASE_URL" ]]; then
  root_delete_expected=$((SHADOW_STORAGE_BEFORE_ROOT_DELETE - SNAPSHOT_EXCLUSIVE_BYTES))
  if (( root_delete_expected < 0 )); then
    fatal "root snapshot deletion accounting underflow"
  fi
  assert_shadow_storage_bytes "$root_delete_expected" "root snapshot deletion"
  assert_shadow_ledger_consistent "root snapshot deletion"
fi

response="$(api_request DELETE "/sandboxes/${SOURCE_ID}")"
status="$(response_status "$response")"
body="$(response_body "$response")"
expect_status "$status" 204 "$body" "delete source sandbox"
SOURCE_ID=""
if [[ -n "$SNAPSHOT_SHADOW_DATABASE_URL" ]]; then
  # The source retains its own writable generation after its snapshots are
  # deleted. Releasing the source is the final reference and must restore the
  # team's pre-canary shadow usage.
  assert_shadow_storage_bytes "$SHADOW_STORAGE_BASELINE" "source final-reference deletion"
  assert_shadow_ledger_consistent "source final-reference deletion"
fi

if [[ "$SKIP_SNAPSHOT_SECRET_CHECKS" == "0" ]]; then
  response="$(api_request DELETE "/secrets/${SECRET_NAME}")"
  status="$(response_status "$response")"
  body="$(response_body "$response")"
  expect_status "$status" 204 "$body" "delete canary secret"
  SECRET_CREATED=0
fi

echo "Saved-snapshot staging canary passed: exact-SHA restart recovery, idempotent byte accounting, private preview policy, mandatory shadow-ledger and secret checks, live process/memory capture, inherited restricted egress, active and paused sources, nested lineage, four independent forks, pause/resume, and dependency-safe deletion"
