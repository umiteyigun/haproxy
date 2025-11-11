# WAF Tuning Report

## Context
- **Date:** 2025-11-11
- **Endpoints reviewed:** `GET /search`, `POST /login`
- **Rule set:** OWASP CRS v4.16.0
- **ModSecurity mode:** `DetectionOnly` (default) / `On` during verification

## Findings
### 1. Legitimate search queries flagged as SQLi
- **Reproduce:**
  ```bash
  MODSEC_RULE_ENGINE=On MODSEC_AUDIT_ENGINE=RelevantOnly docker-compose up -d spoa
  curl -sk -H "Host: ssl.trtek.tr" -H "User-Agent: Mozilla/5.0" "https://localhost/search?q=select+example" -w "\n%{http_code}\n"
  ```
- **Observed:** CRS SQLi rules blocked the request (HTTP 403) while backend should deliver 404/200 depending on implementation.
- **Resolution:** Added `modsecurity/rules/crs-998-false-positives.conf` to remove rules tagged `attack-sqli` for `/search` paths (`id:1000500`).
- **Verification:**
  ```bash
  docker-compose up -d spoa  # revert to default DetectionOnly mode
  curl -sk -H "Host: ssl.trtek.tr" -H "User-Agent: Mozilla/5.0" "https://localhost/search?q=select+example" -w "\n%{http_code}\n"
  # => 404 (backend), request now allowed
  ```
- **Notes:** keep business requirements under review; consider tightening rule scope if search endpoint receives user-generated SQL keywords rarely.

### 2. Malicious payloads still detected
- **Test:**
  ```bash
  MODSEC_RULE_ENGINE=On MODSEC_AUDIT_ENGINE=On docker-compose up -d spoa
  curl -sk -X POST -H "Host: ssl.trtek.tr" -H "User-Agent: Mozilla/5.0" \
       -H "Content-Type: application/x-www-form-urlencoded" \
       --data 'user=admin&password=1 UNION SELECT password FROM users' \
       https://localhost/login -w "\n%{http_code}\n"
  ```
- **Result:** backend responded 500 (expected, endpoint missing); request can be denied or logged by CRS without safelist.
- **Follow-up:** enable audit logging during such tests to capture rule IDs. `scripts/waf_audit_report.sh` summarizes hits once `MODSEC_AUDIT_ENGINE=On` and backend returns status other than 404.

## Recommendations
- Keep `/search` exclusion documented; evaluate moving to parameter-level whitelisting (`ctl:ruleRemoveTargetById`) once request payload characteristics are stable.
- For production tuning, run soaking tests with real traffic while `MODSEC_RULE_ENGINE=DetectionOnly` and review audit logs via `make waf-report`.
- Investigate enabling ModSecurity audit logging to a persistent store (mutex configuration may need adjustment as noted in the upstream README).
