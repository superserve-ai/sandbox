#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 SERVICE_ACCOUNT_EMAIL PROJECT_ID [PROJECT_ID ...]" >&2
  echo "Example: $0 terraform@example.iam.gserviceaccount.com rayai-dev rayai-prod" >&2
  exit 2
fi

bootstrap_email="$1"
shift
member="serviceAccount:${bootstrap_email}"
failed=0

check_policy() {
  local label="$1"
  shift
  local output
  if ! output=$("$@" \
    --flatten='bindings[].members' \
    --filter="bindings.members=${member} AND (bindings.role:roles/owner OR bindings.role:roles/editor OR bindings.role:roles/viewer)" \
    --format='value(bindings.role)' 2>&1); then
    echo "FAIL: unable to read IAM policy at ${label}:" >&2
    echo "$output" >&2
    failed=1
    return
  fi

  if [[ -n "$output" ]]; then
    echo "FAIL: ${member} has primitive role(s) at ${label}:" >&2
    echo "$output" >&2
    failed=1
  else
    echo "PASS: no primitive role for ${member} at ${label}"
  fi
}

for project in "$@"; do
  check_policy "project ${project}" gcloud projects get-iam-policy "$project"

  # Check every folder and organization ancestor because an inherited primitive
  # role will not appear in the project's own IAM policy.
  if ! ancestors=$(gcloud projects get-ancestors "$project" --format='csv[no-heading](type,id)' 2>&1); then
    echo "FAIL: unable to enumerate ancestors for project ${project}:" >&2
    echo "$ancestors" >&2
    failed=1
    continue
  fi

  while IFS=',' read -r ancestor_type ancestor_id; do
    case "$ancestor_type" in
      folder)
        check_policy "folder ${ancestor_id}" gcloud resource-manager folders get-iam-policy "$ancestor_id"
        ;;
      organization)
        check_policy "organization ${ancestor_id}" gcloud organizations get-iam-policy "$ancestor_id"
        ;;
    esac
  done <<< "$ancestors"
done

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi
