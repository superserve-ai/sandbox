#!/usr/bin/env bash
# Outer-runner entry point. DATABASE_URL must be a disposable integration DB:
# the existing integration TestMain drops public and reapplies every migration.
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
suite billing-migrations go test -v -tags integration -count=1 -run '^$' ./internal/integration
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
suite billing-integration-race go test -v -race -tags integration -count=1 -timeout 10m -run 'Billing|Incremental|StorageReportReceiptFencesSettlement|StripeAssociationMonitor' ./internal/integration

# Generate into a temporary directory so a failed drift check preserves the tree.
sqlc_dir="$(mktemp -d)"
trap 'rm -rf "$sqlc_dir"' EXIT
cp sqlc.yaml "$sqlc_dir/sqlc.yaml"
cp -R db supabase "$sqlc_dir/"
mkdir -p "$sqlc_dir/internal/db"
suite billing-sqlc-generate sqlc generate -f "$sqlc_dir/sqlc.yaml"
# The DB package also contains handwritten helpers.
suite billing-sqlc-drift diff -ru --exclude='*_test.go' --exclude='host_capabilities.go' --exclude='billing_lock.go' --exclude='stripe_checkout_association_alerts.go' --exclude='template_build_execution.go' --exclude='template_build_input.go' internal/db "$sqlc_dir/internal/db"
