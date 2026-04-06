#!/usr/bin/env bash
# Regenerate sqlc types and queries from the current migration schema.
# Run this after adding or modifying a migration file.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

echo "Running sqlc generate..."
sqlc generate

echo "Done. Generated files in internal/db/"
