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
suite billing-migrations go test -v -tags integration -count=1 -run '^$' ./internal/integration
suite R16-billing-worker-load-race go test -v -race -tags integration -count=1 -timeout 5m -run '^TestIntegration_IncrementalWorkerLoad$' ./internal/api
suite billing-integration-race go test -v -race -tags integration -count=1 -timeout 10m -run 'Billing|Incremental' ./internal/integration

# Generate into a temporary directory so a failed drift check preserves the tree.
sqlc_dir="$(mktemp -d)"
trap 'rm -rf "$sqlc_dir"' EXIT
cp sqlc.yaml "$sqlc_dir/sqlc.yaml"
cp -R db supabase "$sqlc_dir/"
mkdir -p "$sqlc_dir/internal/db"
suite billing-sqlc-generate sqlc generate -f "$sqlc_dir/sqlc.yaml"
# The DB package also contains a handwritten transaction helper.
suite billing-sqlc-drift diff -ru --exclude='*_test.go' --exclude='host_capabilities.go' --exclude='billing_lock.go' internal/db "$sqlc_dir/internal/db"
