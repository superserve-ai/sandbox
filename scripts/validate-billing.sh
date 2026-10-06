#!/usr/bin/env bash
# Outer-runner entry point. DATABASE_URL must be a disposable integration DB:
# the setup command drops the test schemas and reapplies every migration.
set -euo pipefail
: "${DATABASE_URL:?Set DATABASE_URL to the disposable integration database}"
cd "$(dirname "$0")/.."

suite() {
  local name="$1"
  shift
  echo "BEGIN: $name"
  if "$@"; then
    echo "PASS: $name"
  else
    local status=$?
    echo "FAIL: $name (exit $status)" >&2
    return "$status"
  fi
}

suite billing-unit-race go test -v -race -short -count=1 ./internal/billing ./internal/api
suite billing-controlplane-startup go test -v -race -short -count=1 -run '^TestControlplaneStartsStripeCheckoutAssociationMonitor$' ./cmd/controlplane
suite sentrylog-unit go test -v -count=1 ./internal/sentrylog
suite billing-migrations go run -tags integration ./cmd/setup-integration-db
suite R16-billing-worker-load-race go test -v -race -tags integration -count=1 -timeout 5m -run '^TestIntegration_IncrementalWorkerLoad$' ./internal/api
suite retained-storage-api-race go test -v -race -tags integration -count=1 -timeout 2m -run '^TestIntegration_Retained' ./internal/api
suite storage-report-lease-race go test -v -race -tags integration -count=1 -timeout 1m -run '^TestIntegration_StorageReport(Lease|Reclaim|ChunkTimeout)' ./internal/api
suite storage-settlement-fence-race go test -v -race -tags integration -count=1 -timeout 1m -run '^TestIntegration_Storage(ReceiptFence|Settlement)' ./internal/billing
if [[ "$(go env GOOS)" == "linux" ]]; then
  suite storage-report-refresh-race go test -v -race -tags integration -count=1 -timeout 1m -run '^TestIntegration_StorageReportPeriodicRefresh$' ./internal/vm
  : "${RETAINED_STORAGE_TEST_DIR:?Set RETAINED_STORAGE_TEST_DIR to disposable reflink-capable storage}"
  suite retained-storage-physical-race go test -v -race -count=1 -timeout 5m -run '^TestRetainedPhysical' ./internal/vm
elif [[ "$(uname -s)" == "Darwin" ]]; then
  suite retained-storage-linux-docker bash scripts/validate-retained-docker.sh
else
  echo "FAIL: retained storage qualification requires Linux or the Docker route on macOS" >&2
  exit 1
fi
suite billing-integration-race go test -v -race -tags integration -count=1 -timeout 10m -run 'Billing|Incremental|RetainedStorage|StorageReportReceiptFencesSettlement|StripeAssociationMonitor' ./internal/integration

suite billing-sqlc-drift scripts/verify-sqlc.sh
