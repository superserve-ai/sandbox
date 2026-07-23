#!/usr/bin/env bash
set -euo pipefail

plan_file="${1:-tfplan}"

if [[ ! -f "$plan_file" ]]; then
  echo "plan file not found: $plan_file" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to produce a sanitized Terraform plan summary" >&2
  exit 1
fi

echo "Sanitized Terraform plan summary"
echo "Planned values, prior state, configuration, and variable values are omitted."
echo
terraform show -json "$plan_file" | jq -r '
  .resource_changes[]?
  | [.address, (.change.actions | join(","))]
  | @tsv
' | while IFS=$'\t' read -r address actions; do
  printf '%s: %s\n' "$address" "$actions"
done
