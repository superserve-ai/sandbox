#!/usr/bin/env bash
set -euo pipefail

PLAN_FILE="${1:-plan.txt}"

if [[ ! -f "${PLAN_FILE}" ]]; then
  echo "plan file not found: ${PLAN_FILE}" >&2
  exit 1
fi

echo "Plan summary:"
rg '^Plan:' "${PLAN_FILE}" || true
echo
echo "Planned resources:"
rg '^  # ' "${PLAN_FILE}" || true
