#!/usr/bin/env bash
set -euo pipefail

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

cat > "$tmpdir/gcloud" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >> "${GCLOUD_LOG:?}"

if [[ "$*" == kms\ keys\ get-iam-policy* ]]; then
  echo "serviceAccount:superserve-api-runtime@example-project.iam.gserviceaccount.com"
fi
EOF

chmod +x "$tmpdir/gcloud"

GCLOUD_LOG="$tmpdir/gcloud.log" PATH="$tmpdir:$PATH" \
  bash infra/scripts/verify-production-runtime-kms.sh \
    example-project example-keyring example-key example-location >/dev/null

grep -F -- 'kms keys get-iam-policy example-key' "$tmpdir/gcloud.log"
grep -F -- '--keyring=example-keyring' "$tmpdir/gcloud.log"
grep -F -- '--location=example-location' "$tmpdir/gcloud.log"
grep -F -- '--project=example-project' "$tmpdir/gcloud.log"
grep -F -- 'bindings.role=roles/cloudkms.cryptoKeyEncrypterDecrypter' "$tmpdir/gcloud.log"
grep -F -- 'bindings.members=serviceAccount:superserve-api-runtime@example-project.iam.gserviceaccount.com' "$tmpdir/gcloud.log"
