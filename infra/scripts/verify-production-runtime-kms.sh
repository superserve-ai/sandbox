#!/usr/bin/env bash
set -euo pipefail

project="${1:-rayai-prod}"
keyring="${2:-superserve}"
key="${3:-credentials-kek}"
location="${4:-us-central1}"
member="serviceAccount:superserve-api-runtime@${project}.iam.gserviceaccount.com"
role="roles/cloudkms.cryptoKeyEncrypterDecrypter"

binding="$(
  gcloud kms keys get-iam-policy "$key" \
    --keyring="$keyring" \
    --location="$location" \
    --project="$project" \
    --flatten='bindings[].members' \
    --filter="bindings.role=${role} AND bindings.members=${member}" \
    --format='value(bindings.members)'
)"

if [[ "$binding" != "$member" ]]; then
  echo "::error title=Missing KMS grant::Grant ${member} ${role} on ${project}/${location}/${keyring}/${key} before deploying production regional revisions."
  echo "Run the documented gcloud kms keys add-iam-policy-binding bootstrap command, then rerun the workflow."
  exit 1
fi

echo "Verified ${role} for ${member} on ${key}."
