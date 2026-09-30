#!/usr/bin/env bash
# Runner-owned Linux qualification using the same image/mounts as VM unit tests.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${DATABASE_URL:?Set DATABASE_URL to the migrated disposable integration database}"
db_container="${CODEX_SANDBOX_DB_CONTAINER:-${DB_CONTAINER:-}}"
: "${db_container:?Set CODEX_SANDBOX_DB_CONTAINER or DB_CONTAINER to the runner-owned PostgreSQL container}"

# Share the test DB's network namespace, avoiding Docker Desktop's host port
# forwarding. Keep credentials/database from the runner's disposable URL.
linux_database_url="$(python3 - <<'PY'
import os
from urllib.parse import urlsplit, urlunsplit
u = urlsplit(os.environ['DATABASE_URL'])
if u.hostname not in ('localhost', '127.0.0.1'):
    raise SystemExit('Docker qualification requires the runner-owned local test database')
credentials = u.netloc.rsplit('@', 1)[0] + '@' if '@' in u.netloc else ''
print(urlunsplit(u._replace(netloc=credentials + '127.0.0.1:5432')))
PY
)"
export DATABASE_URL="$linux_database_url"
# This disposable test container needs privilege to mount its own loop-backed
# XFS image. The script never selects a pre-existing disk or loop device.
docker run --rm --privileged \
  --network "container:$db_container" \
  -v "$PWD:/src:ro" -v "$HOME/go/pkg/mod:/go/pkg/mod" -w /src \
  -e DATABASE_URL -e RETAINED_STORAGE_TEST_DIR=/mnt/retained-qualification \
  golang:1.26 bash -euo pipefail -c '
    echo "BEGIN: storage-report-refresh-race (Docker Linux)"
    go test -v -race -tags integration -count=1 -timeout 1m -run "^TestIntegration_StorageReportPeriodicRefresh$" ./internal/vm
    echo "PASS: storage-report-refresh-race"

    apt-get update -qq
    apt-get install -y --no-install-recommends xfsprogs util-linux
    image=$(mktemp /tmp/retained-xfs.XXXXXX)
    loop=""
    cleanup() {
      status=$?
      if mountpoint -q "$RETAINED_STORAGE_TEST_DIR"; then umount "$RETAINED_STORAGE_TEST_DIR" || status=1; fi
      if [[ -n "$loop" ]]; then losetup -d "$loop" || status=1; fi
      rm -f "$image" || status=1
      exit "$status"
    }
    trap cleanup EXIT
    truncate -s 1G "$image"
    mkfs.xfs -f -m reflink=1 "$image"
    loop=$(losetup --find --show "$image")
    mkdir -p "$RETAINED_STORAGE_TEST_DIR"
    mount -t xfs "$loop" "$RETAINED_STORAGE_TEST_DIR"
    [[ "$(findmnt -n -o FSTYPE --target "$RETAINED_STORAGE_TEST_DIR")" == xfs ]]
    xfs_info "$RETAINED_STORAGE_TEST_DIR"
    xfs_info "$RETAINED_STORAGE_TEST_DIR" | grep -Eq "reflink=1"
    findmnt --target "$RETAINED_STORAGE_TEST_DIR"
    echo "BEGIN: retained-storage-physical-race (disposable XFS, reflink=1)"
    go test -v -race -count=1 -timeout 5m -run "^TestRetainedPhysical" ./internal/vm
    echo "PASS: retained-storage-physical-race"
    echo "BEGIN: retained-storage-filesystem-billing-race (Docker Linux, disposable XFS)"
    billing_log=$(mktemp /tmp/retained-billing.XXXXXX)
    go test -v -race -tags integration -count=1 -timeout 5m -run "^TestRetainedStorageRealFilesystemReachesBillingConsumer$" ./internal/integration | tee "$billing_log"
    grep -q -- "--- PASS: TestRetainedStorageRealFilesystemReachesBillingConsumer " "$billing_log"
    rm -f "$billing_log"
    echo "PASS: retained-storage-filesystem-billing-race"
  '
