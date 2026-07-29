#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 TFPLAN" >&2
  exit 2
fi

plan=$1

if [[ ! -f "$plan" ]]; then
  echo "terraform plan file not found: $plan" >&2
  exit 2
fi

# Emit a strict allowlist rather than attempting to redact arbitrary Terraform
# values. Resource addresses and action lists are sufficient for reviewers to
# understand the scope of a plan without exposing configuration, state values,
# provider metadata, URLs, credentials, or other attributes.
terraform show -json "$plan" | jq -e '
  if (.resource_changes | type) != "array" then
    error("terraform plan JSON does not contain a resource_changes array")
  else
    {
      resource_changes: (
        [
          .resource_changes[]
          | {
              address: .address,
              actions: .change.actions
            }
        ]
        | sort_by(.address)
      )
    }
  end
'
