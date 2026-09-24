#!/usr/bin/env bash
set -euo pipefail

: "${PROJECT:?PROJECT is required}"
: "${STATE_BUCKET:?STATE_BUCKET is required}"
: "${DEPLOYMENT_SERVICE_ACCOUNT:?DEPLOYMENT_SERVICE_ACCOUNT is required}"
: "${GITHUB_ENV:?GITHUB_ENV is required}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"
: "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT is required}"
: "${GITHUB_JOB:?GITHUB_JOB is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export TF_VAR_project_id="$PROJECT"
export TF_VAR_deployment_service_account="$DEPLOYMENT_SERVICE_ACCOUNT"
cd "$root/infra/bootstrap/control-plane-evidence"
terraform init -input=false -reconfigure -lockfile=readonly \
  -backend-config="bucket=$STATE_BUCKET" \
  -backend-config="prefix=bootstrap/control-plane-evidence"
applied=false
for attempt in 1 2 3 4 5 6; do
  # Replan after a partial apply rather than replaying a stale plan.
  if terraform plan -input=false -out=tfplan && terraform apply -input=false -auto-approve tfplan; then
    applied=true
    break
  fi
  if [[ "$attempt" != 6 ]]; then sleep 10; fi
done
[[ "$applied" == true ]] || { echo 'Verification bootstrap did not complete.' >&2; exit 1; }
bucket=$(terraform output -raw bucket_name)

# Exercise the same create permission as evidence uploads before touching
# Cloud Run. Allow bounded propagation of the freshly applied bucket grant.
probe="$RUNNER_TEMP/evidence-preflight"
mkdir -p "$probe"
printf 'Evidence upload preflight\n' > "$probe/probe.txt"
for attempt in 1 2 3 4 5 6; do
  if gcloud storage cp --recursive "$probe" \
    "gs://${bucket}/preflight/${GITHUB_RUN_ID}/${GITHUB_RUN_ATTEMPT}/${GITHUB_JOB}-${attempt}/" \
    --if-generation-match=0; then
    echo "CONTROL_PLANE_EVIDENCE_BUCKET=$bucket" >> "$GITHUB_ENV"
    exit 0
  fi
  if [[ "$attempt" != 6 ]]; then sleep 10; fi
done
echo 'Cannot upload private rollout evidence; refusing identity migration.' >&2
exit 1
