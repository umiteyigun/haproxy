#!/usr/bin/env bash
set -euo pipefail

HOST_HEADER="${HOST_HEADER:-ssl.trtek.tr}"
TARGET_HOST="${TARGET_HOST:-localhost}"
GOOD_UA="${GOOD_USER_AGENT:-Mozilla/5.0 (Smoke Test)}"
BAD_UA="${BAD_USER_AGENT:-sqlmap}" # matches default bad_useragents list
PORT="${PORT:-80}"
SCHEME="http"

function curl_status() {
  local user_agent="$1"
  curl -s -o /dev/null -w "%{http_code}" \
    -H "Host: ${HOST_HEADER}" \
    -H "User-Agent: ${user_agent}" \
    "${SCHEME}://${TARGET_HOST}:${PORT}/"
}

# Warm up to make sure HAProxy is ready
for attempt in $(seq 1 10); do
  if nc -z ${TARGET_HOST} ${PORT} 2>/dev/null; then
    break
  fi
  sleep 1
done

GOOD_STATUS=$(curl_status "${GOOD_UA}")
BAD_STATUS=$(curl_status "${BAD_UA}")

if [[ "${GOOD_STATUS}" -ge 400 ]]; then
  echo "[ERROR] Expected benign request to be allowed, but received status ${GOOD_STATUS}." >&2
  exit 1
fi

echo "[INFO] Benign request (${GOOD_UA}) returned ${GOOD_STATUS}"

echo "[DEBUG] Triggering WAF with User-Agent '${BAD_UA}'"
if [[ "${BAD_STATUS}" -ne 403 ]]; then
  echo "[ERROR] Expected malicious request to be blocked with 403, got ${BAD_STATUS}." >&2
  exit 1
fi

echo "[INFO] Malicious request (${BAD_UA}) correctly blocked with 403"

if [[ "${CI:-}" == "true" ]]; then
  echo "[INFO] CI mode detected, skipping log tail"
else
  echo "[INFO] Last 5 HAProxy log entries:"
  docker logs haproxy --tail 5 || true
fi
