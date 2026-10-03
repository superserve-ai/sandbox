#!/usr/bin/env bash
# Verify sqlc output without modifying the caller's working tree.
set -euo pipefail

cd "$(dirname "$0")/.."

sqlc_dir="$(mktemp -d "${TMPDIR:-/tmp}/verify-sqlc.XXXXXX")"
trap 'rm -rf "$sqlc_dir"' EXIT

cp sqlc.yaml "$sqlc_dir/sqlc.yaml"
cp -R db supabase "$sqlc_dir/"
mkdir -p "$sqlc_dir/internal/db"

echo "Generating sqlc output in $sqlc_dir"
sqlc generate -f "$sqlc_dir/sqlc.yaml"

# internal/db contains a small set of deliberately handwritten helpers and
# tests alongside generated files. They are excluded on both sides so the
# comparison still reports generated additions, changes, and deletions.
diff_args=(
  -ruN
  --exclude='*_test.go'
  --exclude='host_capabilities.go'
  --exclude='billing_lock.go'
  --exclude='stripe_checkout_association_alerts.go'
  --exclude='template_build_execution.go'
  --exclude='template_build_input.go'
  --exclude='routing_records.go'
)

set +e
diff_output="$(diff "${diff_args[@]}" internal/db "$sqlc_dir/internal/db")"
diff_status=$?
set -e

if (( diff_status != 0 )); then
  echo "::error::sqlc generated code is out of date. Run 'sqlc generate' and commit the generated output." >&2
  printf '%s\n' "$diff_output" >&2
  exit "$diff_status"
fi

echo "sqlc generated code is up to date"
