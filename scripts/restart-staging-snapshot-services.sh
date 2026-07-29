#!/usr/bin/env bash
# Restart both staging saved-snapshot service tiers at the exact main commit
# under canary. The caller blocks until both workflow runs conclude.
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: SNAPSHOT_CANARY_MAIN_SHA=<40-hex-main-sha> \
  ./scripts/restart-staging-snapshot-services.sh \
  <after-active-capture|after-paused-capture> <sandbox_id> <snapshot_id>

Required:
  SNAPSHOT_CANARY_MAIN_SHA  Exact origin/main commit being tested.
  GH_TOKEN                  Token with Actions write/read access.

Optional:
  GITHUB_REPOSITORY         owner/repo; inferred with `gh repo view` otherwise.
  SNAPSHOT_RESTART_RUN_TIMEOUT_S        Defaults to 3600.
  SNAPSHOT_RESTART_POLL_INTERVAL_S      Defaults to 10.
USAGE
}

if [[ "$#" -ne 3 ]]; then
  usage
  exit 2
fi

phase="$1"
sandbox_id="$2"
snapshot_id="$3"
case "$phase" in
  after-active-capture|after-paused-capture) ;;
  *)
    echo "unsupported restart phase: ${phase}" >&2
    exit 2
    ;;
esac

: "${SNAPSHOT_CANARY_MAIN_SHA:?SNAPSHOT_CANARY_MAIN_SHA is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"

if [[ ! "$SNAPSHOT_CANARY_MAIN_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "SNAPSHOT_CANARY_MAIN_SHA must be a lowercase 40-character commit SHA" >&2
  exit 2
fi
for value in "$sandbox_id" "$snapshot_id"; do
  if [[ ! "$value" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
    echo "restart hook received a non-UUID resource id: ${value}" >&2
    exit 2
  fi
done

for tool in gh jq; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required tool not found: ${tool}" >&2
    exit 1
  fi
done

run_timeout="${SNAPSHOT_RESTART_RUN_TIMEOUT_S:-3600}"
poll_interval="${SNAPSHOT_RESTART_POLL_INTERVAL_S:-10}"
for pair in \
  "SNAPSHOT_RESTART_RUN_TIMEOUT_S:${run_timeout}" \
  "SNAPSHOT_RESTART_POLL_INTERVAL_S:${poll_interval}"; do
  name="${pair%%:*}"
  value="${pair#*:}"
  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
    echo "${name} must be a positive integer, got: ${value}" >&2
    exit 2
  fi
done

repository="${GITHUB_REPOSITORY:-}"
if [[ -z "$repository" ]]; then
  repository="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
fi
if [[ ! "$repository" =~ ^[^/]+/[^/]+$ ]]; then
  echo "could not determine a valid GitHub owner/repository: ${repository}" >&2
  exit 2
fi

main_sha() {
  gh api "repos/${repository}/git/ref/heads/main" --jq .object.sha
}

assert_main_sha() {
  local observed
  observed="$(main_sha)"
  if [[ "$observed" != "$SNAPSHOT_CANARY_MAIN_SHA" ]]; then
    echo "origin/main moved to ${observed}; refusing to restart or sign off stale ${SNAPSHOT_CANARY_MAIN_SHA}" >&2
    return 1
  fi
}

dispatch_staging_workflow() {
  local workflow="$1"
  local inputs_json="$2"
  local payload response run_id run_url

  # The dispatch API only accepts a branch/tag. The 2026-03-10 response binds
  # this invocation to its exact child run, eliminating ambiguous run-list
  # discovery (including same-SHA production dispatches).
  assert_main_sha
  payload="$(jq -cn \
    --arg ref main \
    --argjson inputs "$inputs_json" \
    '{ref: $ref, inputs: $inputs, return_run_details: true}')"
  response="$(gh api \
    --method POST \
    --header 'Accept: application/vnd.github+json' \
    --header 'X-GitHub-Api-Version: 2026-03-10' \
    "repos/${repository}/actions/workflows/${workflow}/dispatches" \
    --input - <<<"$payload")" || return 1
  run_id="$(jq -er '
    .workflow_run_id
    | select(type == "number" or type == "string")
    | tostring
    | select(test("^[1-9][0-9]*$"))
  ' <<<"$response")" || {
    echo "${workflow} dispatch did not return workflow_run_id; refusing ambiguous run discovery" >&2
    return 1
  }
  run_url="$(jq -er '.run_url | strings | select(length > 0)' <<<"$response")" || {
    echo "${workflow} dispatch did not return run_url; refusing ambiguous run discovery" >&2
    return 1
  }
  echo "${workflow} dispatched as run ${run_id}: ${run_url}" >&2
  printf '%s' "$run_id"
}

wait_for_run() {
  local workflow="$1"
  local run_id="$2"
  local deadline=$((SECONDS + run_timeout))
  local view status conclusion head_sha url

  while (( SECONDS < deadline )); do
    if ! view="$(gh run view "$run_id" \
      --repo "$repository" \
      --json status,conclusion,headSha,url)"; then
      sleep "$poll_interval"
      continue
    fi
    status="$(jq -r .status <<<"$view")"
    conclusion="$(jq -r '.conclusion // ""' <<<"$view")"
    head_sha="$(jq -r .headSha <<<"$view")"
    url="$(jq -r .url <<<"$view")"
    if [[ "$head_sha" != "$SNAPSHOT_CANARY_MAIN_SHA" ]]; then
      echo "${workflow} run ${run_id} uses ${head_sha}, want exact ${SNAPSHOT_CANARY_MAIN_SHA}: ${url}" >&2
      return 1
    fi
    if [[ "$status" == "completed" ]]; then
      if [[ "$conclusion" == "success" ]]; then
        echo "${workflow} run ${run_id} succeeded at ${head_sha}: ${url}"
        return 0
      fi
      echo "${workflow} run ${run_id} concluded ${conclusion:-unknown}: ${url}" >&2
      return 1
    fi
    sleep "$poll_interval"
  done

  echo "timed out waiting for ${workflow} run ${run_id}" >&2
  return 1
}

assert_main_sha
echo "Dispatching exact-main staging restarts for ${phase} (${sandbox_id}/${snapshot_id})"
# GitHub's workflow-dispatch API accepts a branch or tag, not a raw commit SHA.
# Dispatch `main`, bind directly to the returned run IDs, then require both
# runs' headSha to equal the canary SHA. Any missing direct ID or main movement
# fails closed; there is deliberately no run-list fallback.
api_inputs="$(jq -cn '{environment: "staging"}')"
vmd_inputs="$(jq -cn '{environment: "staging", activate_staging_snapshot_storage: false}')"
api_run_id="$(dispatch_staging_workflow deploy-api.yml "$api_inputs")"
vmd_run_id="$(dispatch_staging_workflow deploy-vmd.yml "$vmd_inputs")"
assert_main_sha

set +e
wait_for_run deploy-api.yml "$api_run_id" &
api_wait_pid=$!
wait_for_run deploy-vmd.yml "$vmd_run_id" &
vmd_wait_pid=$!
wait "$api_wait_pid"
api_result=$?
wait "$vmd_wait_pid"
vmd_result=$?
set -e

if (( api_result != 0 || vmd_result != 0 )); then
  echo "staging restart failed: deploy-api=${api_result}, deploy-vmd=${vmd_result}" >&2
  exit 1
fi

assert_main_sha
echo "Both staging service tiers restarted successfully at ${SNAPSHOT_CANARY_MAIN_SHA}"
