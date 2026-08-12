#!/bin/sh
# Watches the GCE metadata server for an upcoming host-maintenance notice.
# Bare metal hosts cannot live-migrate: host maintenance terminates and
# restarts the machine, so the advance notice is the only window to drain
# the host first. Posts one webhook message when a notice appears, changes,
# or clears; the notice is also logged to the journal either way.
set -u

# Overridable for tests only; production runs use the defaults.
ENDPOINT="${MAINTENANCE_WATCH_ENDPOINT:-http://metadata.google.internal/computeMetadata/v1/instance/upcoming-maintenance?alt=json}"
STATE_FILE="${MAINTENANCE_WATCH_STATE:-/var/lib/sandbox/maintenance-notice}"

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
code=$(curl -s -o "$tmp" -w '%{http_code}' -H "Metadata-Flavor: Google" \
    --connect-timeout 5 --max-time 30 "$ENDPOINT") || code=000

# Only a 200 decides: its body is either the literal NONE (nothing scheduled)
# or the pending notice. Any other code is a transient metadata-server problem
# — skip the poll rather than misread it as "notice cleared".
case "$code" in
200)
    notice=$(cat "$tmp")
    [ "$notice" = "NONE" ] && notice=""
    ;;
*)
    echo "metadata server unreachable (http $code), skipping poll" >&2
    exit 0
    ;;
esac

prev=""
[ -f "$STATE_FILE" ] && prev=$(cat "$STATE_FILE")
[ "$notice" = "$prev" ] && exit 0

host=$(hostname)
if [ -n "$notice" ]; then
    msg="GCE host maintenance notice on ${host}: ${notice}"
else
    msg="GCE host maintenance notice on ${host} cleared (window passed or maintenance completed)"
fi
echo "$msg"

# State is only written after a successful delivery, so an unset webhook or a
# failed POST re-fires on the next poll instead of dropping the notice.
if [ -z "${MAINTENANCE_ALERT_WEBHOOK:-}" ]; then
    echo "MAINTENANCE_ALERT_WEBHOOK is not set, notice logged to journal only" >&2
    exit 1
fi

esc=$(printf '%s' "$msg" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr '\n' ' ')
if ! curl -sf -X POST -H "Content-Type: application/json" \
    -d "{\"text\":\"${esc}\"}" \
    --connect-timeout 5 --max-time 30 "$MAINTENANCE_ALERT_WEBHOOK" >/dev/null; then
    echo "webhook delivery failed, will retry next poll" >&2
    exit 1
fi

mkdir -p "$(dirname "$STATE_FILE")"
printf '%s' "$notice" >"$STATE_FILE"
