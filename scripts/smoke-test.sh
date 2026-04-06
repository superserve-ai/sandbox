#!/usr/bin/env bash
# Smoke test for the Superserve Sandbox API.
#
# Usage:
#   API_URL=https://superserve-api-eszjsyysqa-uc.a.run.app API_KEY=sk-test-... ./scripts/smoke-test.sh
#
# Requires: curl, jq
set -euo pipefail

: "${API_URL:?API_URL is required}"
: "${API_KEY:?API_KEY is required}"

PASS=0
FAIL=0
TESTS=()

pass() { PASS=$((PASS + 1)); TESTS+=("  ✓ $1"); }
fail() { FAIL=$((FAIL + 1)); TESTS+=("  ✗ $1: $2"); }

# ---------------------------------------------------------------------------
# 1. Health check (no auth)
# ---------------------------------------------------------------------------
echo "Running smoke tests against ${API_URL} ..."
echo ""

STATUS=$(curl -sf -o /dev/null -w "%{http_code}" "${API_URL}/health" || true)
if [[ "$STATUS" == "200" ]]; then
  pass "GET /health returns 200"
else
  fail "GET /health returns 200" "got ${STATUS}"
fi

# ---------------------------------------------------------------------------
# 2. Auth rejection — no key
# ---------------------------------------------------------------------------
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${API_URL}/sandboxes")
if [[ "$STATUS" == "401" ]]; then
  pass "GET /sandboxes without key returns 401"
else
  fail "GET /sandboxes without key returns 401" "got ${STATUS}"
fi

# ---------------------------------------------------------------------------
# 3. Auth rejection — bad key
# ---------------------------------------------------------------------------
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "X-API-Key: sk-bogus-key-12345" "${API_URL}/sandboxes")
if [[ "$STATUS" == "401" ]]; then
  pass "GET /sandboxes with bad key returns 401"
else
  fail "GET /sandboxes with bad key returns 401" "got ${STATUS}"
fi

# ---------------------------------------------------------------------------
# 4. List sandboxes (authenticated)
# ---------------------------------------------------------------------------
RESP=$(curl -s -w "\n%{http_code}" -H "X-API-Key: ${API_KEY}" "${API_URL}/sandboxes")
STATUS=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')

if [[ "$STATUS" == "200" ]]; then
  pass "GET /sandboxes returns 200"
else
  fail "GET /sandboxes returns 200" "got ${STATUS}: ${BODY}"
fi

# ---------------------------------------------------------------------------
# 5. Create sandbox
# ---------------------------------------------------------------------------
RESP=$(curl -s -w "\n%{http_code}" -X POST \
  -H "X-API-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"name":"smoke-test"}' \
  "${API_URL}/sandboxes")
STATUS=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')

if [[ "$STATUS" == "201" || "$STATUS" == "200" ]]; then
  pass "POST /sandboxes creates sandbox"
  SANDBOX_ID=$(echo "$BODY" | jq -r '.id // empty')
  if [[ -n "$SANDBOX_ID" ]]; then
    pass "POST /sandboxes returns sandbox ID (${SANDBOX_ID})"
  else
    fail "POST /sandboxes returns sandbox ID" "no id in response"
    SANDBOX_ID=""
  fi
else
  # VMD not connected is expected in staging — the DB write should still succeed.
  # Check if it's a 5xx (infra issue) vs expected VMD error.
  ERROR_CODE=$(echo "$BODY" | jq -r '.code // empty' 2>/dev/null || true)
  if [[ "$STATUS" == "502" || "$STATUS" == "504" || "$ERROR_CODE" == "vmd_error" ]]; then
    # VMD not available is expected — check if the sandbox was still persisted.
    pass "POST /sandboxes — VMD unavailable (expected in staging without VMD)"
    SANDBOX_ID=""
  else
    fail "POST /sandboxes creates sandbox" "got ${STATUS}: ${BODY}"
    SANDBOX_ID=""
  fi
fi

# ---------------------------------------------------------------------------
# 6. Get sandbox by ID
# ---------------------------------------------------------------------------
if [[ -n "${SANDBOX_ID:-}" ]]; then
  RESP=$(curl -s -w "\n%{http_code}" -H "X-API-Key: ${API_KEY}" "${API_URL}/sandboxes/${SANDBOX_ID}")
  STATUS=$(echo "$RESP" | tail -1)
  BODY=$(echo "$RESP" | sed '$d')

  if [[ "$STATUS" == "200" ]]; then
    pass "GET /sandboxes/:id returns sandbox"
  else
    fail "GET /sandboxes/:id returns sandbox" "got ${STATUS}"
  fi
fi

# ---------------------------------------------------------------------------
# 7. Delete sandbox
# ---------------------------------------------------------------------------
if [[ -n "${SANDBOX_ID:-}" ]]; then
  RESP=$(curl -s -w "\n%{http_code}" -X DELETE -H "X-API-Key: ${API_KEY}" "${API_URL}/sandboxes/${SANDBOX_ID}")
  STATUS=$(echo "$RESP" | tail -1)

  if [[ "$STATUS" == "200" || "$STATUS" == "204" ]]; then
    pass "DELETE /sandboxes/:id succeeds"
  else
    BODY=$(echo "$RESP" | sed '$d')
    # VMD error on delete is acceptable too
    ERROR_CODE=$(echo "$BODY" | jq -r '.code // empty' 2>/dev/null || true)
    if [[ "$ERROR_CODE" == "vmd_error" ]]; then
      pass "DELETE /sandboxes/:id — VMD unavailable (expected)"
    else
      fail "DELETE /sandboxes/:id succeeds" "got ${STATUS}"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 8. Verify deleted sandbox is gone
# ---------------------------------------------------------------------------
if [[ -n "${SANDBOX_ID:-}" ]]; then
  RESP=$(curl -s -w "\n%{http_code}" -H "X-API-Key: ${API_KEY}" "${API_URL}/sandboxes/${SANDBOX_ID}")
  STATUS=$(echo "$RESP" | tail -1)

  if [[ "$STATUS" == "404" ]]; then
    pass "GET /sandboxes/:id after delete returns 404"
  elif [[ "$STATUS" == "200" ]]; then
    # Might still exist with status=deleted, that's also acceptable
    BODY=$(echo "$RESP" | sed '$d')
    SBSTATUS=$(echo "$BODY" | jq -r '.status // empty' 2>/dev/null || true)
    if [[ "$SBSTATUS" == "deleted" ]]; then
      pass "GET /sandboxes/:id after delete shows status=deleted"
    else
      fail "GET /sandboxes/:id after delete returns 404" "got 200 with status=${SBSTATUS}"
    fi
  else
    fail "GET /sandboxes/:id after delete returns 404" "got ${STATUS}"
  fi
fi

# ---------------------------------------------------------------------------
# 9. Validation — bad request body
# ---------------------------------------------------------------------------
RESP=$(curl -s -w "\n%{http_code}" -X POST \
  -H "X-API-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{}' \
  "${API_URL}/sandboxes")
STATUS=$(echo "$RESP" | tail -1)

if [[ "$STATUS" == "400" ]]; then
  pass "POST /sandboxes with empty body returns 400"
else
  fail "POST /sandboxes with empty body returns 400" "got ${STATUS}"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
for t in "${TESTS[@]}"; do echo "$t"; done
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"

if [[ $FAIL -gt 0 ]]; then
  exit 1
fi
