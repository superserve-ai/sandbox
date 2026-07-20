#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_DIR="${ROOT_DIR}/infra/envs/production/us-west2"

cd "${ENV_DIR}"
terraform init
terraform validate
terraform plan -out=tfplan
terraform show -no-color tfplan > plan.txt

echo "Wrote ${ENV_DIR}/plan.txt"
