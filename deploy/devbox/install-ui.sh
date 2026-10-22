#!/usr/bin/env bash
# Build the console from the checked-out UI revision and (re)start it on
# 127.0.0.1:3000 as the superserve-devbox-console systemd service.
#
# Runs as root on a devbox after services-up.sh and install-api.sh; safe to
# re-run (create and upgrade both call it). A failed build leaves the running
# console untouched.
#
# Inputs:
#   /etc/superserve-devbox/devbox.env    non-secret settings from CI
#                                        (DEVBOX_UI_SHA; RECAPTCHA_SITE_KEY,
#                                        RECAPTCHA_PROJECT_ID and
#                                        RECAPTCHA_SCORE_THRESHOLD, optional)
#   /etc/superserve-devbox/secrets.env   CI secrets (RECAPTCHA_API_KEY,
#                                        optional)
#   /etc/superserve-devbox/local-secrets.env  plain KEY=value keys and the
#   $DATA_DIR/promotion-account-key.pem       signing key that services-up.sh
#                                             generates and shares with the API
#   /opt/superserve-devbox/src/superserve  UI checkout
#
# Console-only secrets are generated once into $DATA_DIR/console-secrets.env.
#
# Public values (NEXT_PUBLIC_*) are compiled into the browser bundle at build
# time; everything else is only given to the server at runtime. The browser
# reaches the box through SSH port forwarding on the same ports; see the
# console README ("Private single-box environments").
#
# Usage: install-ui.sh [--dry-run]
#   --dry-run  print the build arguments, runtime variable names and unit
#              without building, writing or restarting anything.
set -euo pipefail

CONFIG_DIR="${DEVBOX_CONFIG_DIR:-/etc/superserve-devbox}"
UI_SRC="${DEVBOX_UI_SRC:-/opt/superserve-devbox/src/superserve}"
DATA_DIR="${DEVBOX_DATA_DIR:-/mnt/sandbox-data/superserve-devbox}"
RUNTIME_DIR="${DEVBOX_CONSOLE_RUNTIME_DIR:-/var/lib/superserve-devbox/console}"
UNIT_FILE="${DEVBOX_CONSOLE_UNIT_FILE:-/etc/systemd/system/superserve-devbox-console.service}"
READY_TIMEOUT="${DEVBOX_CONSOLE_READY_TIMEOUT:-180}"
DEVBOX_ENV="$CONFIG_DIR/devbox.env"
CI_SECRETS="$CONFIG_DIR/secrets.env"
LOCAL_SECRETS="$CONFIG_DIR/local-secrets.env"
PROMOTION_KEY="$DATA_DIR/promotion-account-key.pem"
CONSOLE_SECRETS="$DATA_DIR/console-secrets.env"

SERVICE=superserve-devbox-console
IMAGE=superserve-devbox-console:current
CONSOLE_URL=http://localhost:3000
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DRY_RUN=0
case "${1:-}" in
  "") ;;
  --dry-run) DRY_RUN=1 ;;
  *) echo "usage: $0 [--dry-run]" >&2; exit 2 ;;
esac

die() {
  echo "install-ui: $*" >&2
  exit 1
}

log() {
  echo "install-ui: $*"
}

require_file() {
  if [[ -L "$1" && ! -e "$1" ]]; then
    die "$1 points to $(readlink "$1"), which is missing (is the data disk mounted?)"
  fi
  [[ -r "$1" ]] || die "$1 is missing or unreadable ($2)"
}

# Reads one key from a shell-quoted env file written by CI, in a clean
# environment so neither the file's other keys nor this script's variables
# leak across. Parse errors are silenced so they can't echo secret values.
env_get() {
  # shellcheck disable=SC2016
  env -i bash -c 'set -a; . "$1" >/dev/null 2>&1; printf "%s" "${!2:-}"' _ "$1" "$2"
}

# Reads one key from a plain KEY=value file, taking the value verbatim.
env_literal() {
  awk -v key="$2" 'index($0, key "=") == 1 { value = substr($0, length(key) + 2); sub(/\r$/, "", value) }
    END { printf "%s", value }' "$1"
}

shared() {
  local value
  value="$(env_literal "$LOCAL_SECRETS" "$1")"
  [[ -n "$value" ]] || die "$1 is not set in $LOCAL_SECRETS (re-run services-up.sh)"
  printf '%s' "$value"
}

ensure_console_secrets() {
  local proxy="" proof=""
  if [[ -r "$CONSOLE_SECRETS" ]]; then
    proxy="$(env_literal "$CONSOLE_SECRETS" CONSOLE_PROXY_SECRET)"
    proof="$(env_literal "$CONSOLE_SECRETS" GOOGLE_SIGNUP_PROOF_SECRET)"
  fi
  if ((${#proxy} < 32 || ${#proof} < 32)); then
    log "generating missing console secrets in $CONSOLE_SECRETS"
    if ((${#proxy} < 32)); then proxy="$(openssl rand -hex 32)"; fi
    if ((${#proof} < 32)); then proof="$(openssl rand -hex 32)"; fi
    local tmp
    tmp="$(mktemp "$CONSOLE_SECRETS.XXXXXX")"
    printf 'CONSOLE_PROXY_SECRET=%s\nGOOGLE_SIGNUP_PROOF_SECRET=%s\n' "$proxy" "$proof" >"$tmp"
    mv -f "$tmp" "$CONSOLE_SECRETS"
  fi
  RUNTIME_VARS+=("CONSOLE_PROXY_SECRET=$proxy" "GOOGLE_SIGNUP_PROOF_SECRET=$proof")
}

require_file "$DEVBOX_ENV" "written by the create workflow"
require_file "$CI_SECRETS" "written by the create workflow"
for file in "$DEVBOX_ENV" "$CI_SECRETS"; do
  bash -n "$file" 2>/dev/null || die "$file is not valid shell syntax (check the create workflow's quoting)"
done
require_file "$LOCAL_SECRETS" "run services-up.sh first"
require_file "$PROMOTION_KEY" "run services-up.sh first"
[[ -s "$PROMOTION_KEY" ]] || die "$PROMOTION_KEY is empty (re-run services-up.sh)"
[[ -f "$UI_SRC/apps/console/package.json" ]] || die "$UI_SRC is not a superserve checkout"

anon_key="$(shared ANON_KEY)"
service_role_key="$(shared SERVICE_ROLE_KEY)"
internal_api_token="$(shared INTERNAL_API_TOKEN)"
promotion_capture_token="$(shared PROMOTION_CAPTURE_TOKEN)"
promotion_account_token="$(shared PROMOTION_ACCOUNT_TOKEN)"

BUILD_ARGS=(
  "NEXT_PUBLIC_APP_URL=$CONSOLE_URL"
  "NEXT_PUBLIC_WEBSITE_URL=https://www.superserve.ai"
  "NEXT_PUBLIC_SUPABASE_URL=http://localhost:54321"
  "NEXT_PUBLIC_SUPABASE_ANON_KEY=$anon_key"
  "NEXT_PUBLIC_SANDBOX_SCHEME=http"
  "NEXT_PUBLIC_SANDBOX_HOST=sandbox.localhost"
  "NEXT_PUBLIC_SANDBOX_PORT=8090"
  "NEXT_PUBLIC_RECAPTCHA_SITE_KEY=$(env_get "$DEVBOX_ENV" RECAPTCHA_SITE_KEY)"
)

RUNTIME_VARS=(
  SANDBOX_API_URL=http://127.0.0.1:8080
  EMAIL_TRANSPORT=smtp
  SMTP_HOST=127.0.0.1
  SMTP_PORT=1025
  "RESEND_FROM_ADDRESS=Superserve <team@superserve.localhost>"
  "SUPABASE_SERVICE_ROLE_KEY=$service_role_key"
  "INTERNAL_API_TOKEN=$internal_api_token"
  "PROMOTION_CAPTURE_TOKEN=$promotion_capture_token"
  "PROMOTION_ACCOUNT_TOKEN=$promotion_account_token"
  "PROMOTION_ACCOUNT_PRIVATE_KEY=$(<"$PROMOTION_KEY")"
  "RECAPTCHA_PROJECT_ID=$(env_get "$DEVBOX_ENV" RECAPTCHA_PROJECT_ID)"
  "RECAPTCHA_SCORE_THRESHOLD=$(env_get "$DEVBOX_ENV" RECAPTCHA_SCORE_THRESHOLD)"
  "RECAPTCHA_API_KEY=$(env_get "$CI_SECRETS" RECAPTCHA_API_KEY)"
)

DOCKER="$(command -v docker || echo /usr/bin/docker)"
UNIT="[Unit]
Description=Superserve devbox console
Requires=docker.service
After=docker.service

[Service]
ExecStartPre=-$DOCKER rm -f $SERVICE
ExecStart=$DOCKER run --rm --pull=never --name $SERVICE --network host --mount type=bind,src=$RUNTIME_DIR/runtime.env,dst=/run/superserve/console.env,readonly $IMAGE
ExecStop=$DOCKER stop $SERVICE
Restart=always
SuccessExitStatus=143
RestartSec=5

[Install]
WantedBy=multi-user.target
"

if ((DRY_RUN)); then
  printf 'build-arg %s\n' "${BUILD_ARGS[@]}"
  printf 'runtime %s=…\n' "${RUNTIME_VARS[@]%%=*}" CONSOLE_PROXY_SECRET GOOGLE_SIGNUP_PROOF_SECRET
  printf '%s' "$UNIT"
  exit 0
fi

[[ $EUID -eq 0 ]] || die "must run as root"
for tool in docker curl openssl; do
  command -v "$tool" >/dev/null || die "$tool is not installed"
done

ensure_console_secrets

revision="$(env_get "$DEVBOX_ENV" DEVBOX_UI_SHA)"
revision="${revision:-$(git -C "$UI_SRC" rev-parse HEAD 2>/dev/null || echo unknown)}"
log "building console at $revision"
docker_args=()
for arg in "${BUILD_ARGS[@]}"; do
  docker_args+=(--build-arg "$arg")
done
DOCKER_BUILDKIT=1 docker build --progress=plain --network host \
  -f "$SCRIPT_DIR/console.Dockerfile" \
  --build-arg "UI_REVISION=$revision" "${docker_args[@]}" \
  -t "$IMAGE" "$UI_SRC" || die "console build failed; the previous console is still running"

install -d -m 0700 "$RUNTIME_DIR"
(
  umask 077
  for var in "${RUNTIME_VARS[@]}"; do
    printf '%s=%q\n' "${var%%=*}" "${var#*=}"
  done >"$RUNTIME_DIR/runtime.env.tmp"
)
mv "$RUNTIME_DIR/runtime.env.tmp" "$RUNTIME_DIR/runtime.env"

printf '%s' "$UNIT" >"$UNIT_FILE"
systemctl daemon-reload
systemctl enable --quiet "$SERVICE" || die "could not enable $SERVICE"
log "restarting $SERVICE"
systemctl restart "$SERVICE"

deadline=$((SECONDS + READY_TIMEOUT))
until status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:3000/)" &&
  [[ "$status" =~ ^[23] ]]; do
  if ((SECONDS >= deadline)); then
    journalctl -u "$SERVICE" -n 50 --no-pager >&2 || true
    die "console did not become ready on 127.0.0.1:3000 within ${READY_TIMEOUT}s"
  fi
  sleep 2
done

docker image prune -f --filter label=superserve-devbox=console >/dev/null || true
log "console $revision ready at $CONSOLE_URL"
