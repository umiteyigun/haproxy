#!/usr/bin/env bash
set -euo pipefail

aud_log="${1:-modsecurity/logs/audit.log}"

if [ ! -f "$aud_log" ]; then
  echo "[INFO] Audit log not found at $aud_log"
  exit 0
fi

if [ ! -s "$aud_log" ]; then
  echo "[INFO] Audit log exists but is empty. Enable MODSEC_AUDIT_ENGINE=On or switch SecDefaultAction to auditlog." 
  exit 0
fi

echo "# Rule hit counts (top 10)"
grep -o 'id "[0-9]\+"' "$aud_log" | cut -d'"' -f2 | sort | uniq -c | sort -nr | head -10 || true

echo
if command -v awk >/dev/null 2>&1; then
  echo "# Recent entries"
  awk 'BEGIN{RS="--[A-Z]--\n"}/Message:/{msg=$0; gsub(/\r/,"",msg); print msg"\n"}' "$aud_log" | tail -5
else
  echo "# Recent entries"
  grep -n 'Message:' "$aud_log" | tail -5
fi
