#!/usr/bin/env bash
# Verify runtime KMS and secret access before routing a new Cloud Run revision.
# Terraform owns IAM grants; this probe never changes policy.
set -euo pipefail

usage() {
  echo "usage: $0 --project PROJECT --region REGION --service SERVICE --runtime-service-account SERVICE_ACCOUNT --kms-key-resource RESOURCE --evidence-dir DIR [--secret SECRET_ID ...]" >&2
  exit 2
}

PROJECT=""
REGION=""
SERVICE=""
RUNTIME_IDENTITY=""
KMS_KEY_RESOURCE=""
EVIDENCE_DIR=""
SECRET_IDS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) PROJECT=${2:-}; shift 2 ;;
    --region) REGION=${2:-}; shift 2 ;;
    --service) SERVICE=${2:-}; shift 2 ;;
    --runtime-service-account) RUNTIME_IDENTITY=${2:-}; shift 2 ;;
    --kms-key-resource) KMS_KEY_RESOURCE=${2:-}; shift 2 ;;
    --evidence-dir) EVIDENCE_DIR=${2:-}; shift 2 ;;
    --secret) SECRET_IDS+=("${2:-}"); shift 2 ;;
    *) usage ;;
  esac
done

[[ -n "$PROJECT" && -n "$REGION" && -n "$SERVICE" && -n "$RUNTIME_IDENTITY" && -n "$KMS_KEY_RESOURCE" && -n "$EVIDENCE_DIR" ]] || usage
mkdir -p "$EVIDENCE_DIR"

observed_identity=$(gcloud run services describe "$SERVICE" \
  --region="$REGION" --project="$PROJECT" --format=json \
  | jq -r '[.spec.template.serviceAccount, .spec.template.serviceAccountName, .spec.template.spec.serviceAccountName]
    | map(select(type == "string" and length > 0)) | .[0] // empty')
[[ "$observed_identity" == "$RUNTIME_IDENTITY" ]] || {
  echo "Cloud Run service identity is '$observed_identity'; expected '$RUNTIME_IDENTITY'" >&2
  exit 1
}

if [[ "$KMS_KEY_RESOURCE" =~ ^projects/([^/]+)/locations/([^/]+)/keyRings/([^/]+)/cryptoKeys/([^/]+)$ ]]; then
  key_project=${BASH_REMATCH[1]}
  key_location=${BASH_REMATCH[2]}
  keyring=${BASH_REMATCH[3]}
  key_name=${BASH_REMATCH[4]}
else
  echo "invalid KMS crypto-key resource: $KMS_KEY_RESOURCE" >&2
  exit 1
fi

probe_dir=$(mktemp -d)
trap 'rm -rf "$probe_dir"' EXIT
printf '%s\n' 'control-plane-kms-access-probe-v1' >"$probe_dir/plaintext"
gcloud kms encrypt \
  --project="$key_project" --location="$key_location" --keyring="$keyring" --key="$key_name" \
  --plaintext-file="$probe_dir/plaintext" --ciphertext-file="$probe_dir/ciphertext" \
  --impersonate-service-account="$RUNTIME_IDENTITY" \
  >"$EVIDENCE_DIR/kms-encrypt.stdout" 2>"$EVIDENCE_DIR/kms-encrypt.stderr"
gcloud kms decrypt \
  --project="$key_project" --location="$key_location" --keyring="$keyring" --key="$key_name" \
  --ciphertext-file="$probe_dir/ciphertext" --plaintext-file="$probe_dir/decrypted" \
  --impersonate-service-account="$RUNTIME_IDENTITY" \
  >"$EVIDENCE_DIR/kms-decrypt.stdout" 2>"$EVIDENCE_DIR/kms-decrypt.stderr"
cmp -s "$probe_dir/plaintext" "$probe_dir/decrypted"

if ((${#SECRET_IDS[@]} > 0)); then
  : >"$EVIDENCE_DIR/secret-access.txt"
fi
for secret_id in "${SECRET_IDS[@]}"; do
  [[ -n "$secret_id" ]] || { echo "secret IDs must not be empty" >&2; exit 1; }
  gcloud secrets versions access latest \
    --secret="$secret_id" --project="$PROJECT" \
    --impersonate-service-account="$RUNTIME_IDENTITY" \
    >/dev/null \
    2>"$EVIDENCE_DIR/secret-${secret_id}.stderr"
  printf 'secret=%s status=passed\n' "$secret_id" >>"$EVIDENCE_DIR/secret-access.txt"
done

cat >"$EVIDENCE_DIR/kms-prerequisite.txt" <<EOF
status=passed-before-cutover
observed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
grant_owner=terraform
identity=$RUNTIME_IDENTITY
key=$KMS_KEY_RESOURCE
role=roles/cloudkms.cryptoKeyEncrypterDecrypter
verification=runtime-encrypt-decrypt-round-trip
secret_checks=${#SECRET_IDS[@]}
EOF
