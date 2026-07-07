#!/usr/bin/env bash
set -euo pipefail

registry="${1:-deploy/environments.yaml}"

if [[ ! -f "$registry" ]]; then
  echo "missing deployment registry: $registry" >&2
  exit 1
fi

required_patterns=(
  "schema_version:"
  "environments:"
  "terraform_dir:"
  "regions:"
  "api:"
  "host_deployments:"
  "sandbox_status: ready"
)

for pattern in "${required_patterns[@]}"; do
  if ! grep -q "$pattern" "$registry"; then
    echo "deployment registry is missing required pattern: $pattern" >&2
    exit 1
  fi
done

# Keep accidental broad host selectors out of deployment configuration. The old
# component=vmd selector is too broad for multi-region/multi-state rollout.
if grep -Eq 'component:[[:space:]]*vmd|component=vmd' "$registry"; then
  echo "deployment registry must not use broad component=vmd host selectors" >&2
  exit 1
fi

# Production should remain gated until deployment approvals and a ledger exist.
if awk '
  $1 == "production:" { in_prod=1 }
  in_prod && $1 == "auto_deploy:" {
    if ($2 == "true") exit 42
  }
' "$registry"; then
  :
else
  code=$?
  if [[ "$code" -eq 42 ]]; then
    echo "production auto_deploy must remain false until approvals/ledger are in place" >&2
    exit 1
  fi
  exit "$code"
fi
