#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

terraform_dirs=(
  infra/envs/staging/us-central1
  infra/envs/production/us-central1
  infra/envs/production/us-west2
  infra/envs/production/us-east4
)

if [[ ${#terraform_dirs[@]} -eq 0 ]]; then
  echo "No Terraform directories found under infra/."
  exit 1
fi

# Validate the supported root modules; their shared modules are exercised as
# part of the root graph and do not need separate standalone initialization.
for dir in "${terraform_dirs[@]}"; do
  if [[ ! -d "$dir" ]]; then
    echo "Missing Terraform directory: ${dir}"
    exit 1
  fi

  echo "Validating ${dir}"
  (
    cd "$dir"
    TF_IN_AUTOMATION=true terraform init -backend=false -lockfile=readonly -input=false
    terraform validate
  )
done

bash infra/scripts/check-no-nonindividual-primitive-roles.sh infra
bash infra/scripts/verify-production-runtime-kms.test.sh
