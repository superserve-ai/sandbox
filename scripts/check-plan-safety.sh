#!/usr/bin/env bash
set -euo pipefail

ENV_NAME="${1:?usage: check-plan-safety.sh <new-region|staging|production> [plan.txt]}"
PLAN_FILE="${2:-plan.txt}"

if [[ ! -f "${PLAN_FILE}" ]]; then
  echo "plan file not found: ${PLAN_FILE}" >&2
  exit 1
fi

if rg -q 'must be replaced|-/\+' "${PLAN_FILE}"; then
  echo "unsafe: replacement detected" >&2
  exit 1
fi

PLAN_LINE="$(rg '^Plan:' "${PLAN_FILE}" | tail -n1 || true)"
if [[ -z "${PLAN_LINE}" ]]; then
  if rg -q '^No changes\. Your infrastructure matches the configuration\.' "${PLAN_FILE}"; then
    ADDS=0
    CHANGES=0
    DESTROYS=0
  else
    echo "unsafe: unable to find Terraform plan summary or no-op message" >&2
    exit 1
  fi
else
  ADDS="$(echo "${PLAN_LINE}" | sed -E 's/Plan: ([0-9]+) to add, ([0-9]+) to change, ([0-9]+) to destroy.*/\1/')"
  CHANGES="$(echo "${PLAN_LINE}" | sed -E 's/Plan: ([0-9]+) to add, ([0-9]+) to change, ([0-9]+) to destroy.*/\2/')"
  DESTROYS="$(echo "${PLAN_LINE}" | sed -E 's/Plan: ([0-9]+) to add, ([0-9]+) to change, ([0-9]+) to destroy.*/\3/')"
fi

case "${ENV_NAME}" in
  new-region)
    if [[ "${CHANGES}" != "0" || "${DESTROYS}" != "0" ]]; then
      echo "unsafe: new-region only allows create-only plans by default" >&2
      exit 1
    fi
    ;;
  staging|production)
    if [[ "${ADDS}" != "0" || "${CHANGES}" != "0" || "${DESTROYS}" != "0" ]]; then
      echo "unsafe: ${ENV_NAME} expects no-op after import; any change fails safety check" >&2
      exit 1
    fi
    ;;
  *)
    echo "unknown environment policy: ${ENV_NAME}" >&2
    exit 1
    ;;
esac

echo "plan safety check passed for ${ENV_NAME}"