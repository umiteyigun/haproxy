# HAProxy Advanced Security Dashboard — Agent Guide

## Project Purpose
Containerized reverse-proxy + security platform built on HAProxy. Core services: HAProxy, ModSecurity/SPOA (WAF), Guard (DDoS), API (Node.js), Web UI, PostgreSQL, Certbot.  
See [README.md](README.md) for a full feature overview.

---

## Quick Start

```bash
# Start all services
docker compose up -d --build

# Validate HAProxy config before applying
docker compose config >/dev/null

# Tail HAProxy + ModSecurity logs
make waf-logs

# Run WAF smoke test
make test-waf
```

See [Makefile](Makefile) for all available targets (`monitoring-up`, `waf-report`, etc.).

---

## Architecture

```
[Internet] → HAProxy (80/443) → [SPOA/ModSecurity WAF] ← OWASP CRS v4
                             ↓
                     API (Node.js :3000)  ←→  PostgreSQL (:5432)
                     Web UI (:8088)
                     Guard (Python, host net) → iptables bans
                     Certbot (ACME/DNS challenge)
```

- HAProxy and Guard run on **host network** for dynamic port binding and iptables access.
- All other services are on the `haproxy-network` bridge.
- SPOE filter connects HAProxy ↔ SPOA on port `12345`.
- ModSecurity is in **`DetectionOnly` mode** by default; set `MODSEC_RULE_ENGINE=On` to block.

---

## Key Files

| File | Purpose |
|---|---|
| [haproxy/haproxy.cfg](haproxy/haproxy.cfg) | HAProxy config: frontends, backends, rate limiting, ACLs |
| [haproxy/modsecurity.conf](haproxy/modsecurity.conf) | SPOE filter config (HAProxy ↔ ModSecurity) |
| [haproxy/config.d/ip_blacklist.lst](haproxy/config.d/ip_blacklist.lst) | Static IP blacklist |
| [haproxy/config.d/whitelist.lst](haproxy/config.d/whitelist.lst) | IP whitelist (bypasses rate limiting) |
| [haproxy/maps/bad_useragents.lst](haproxy/maps/bad_useragents.lst) | Blocked User-Agent strings |
| [modsecurity/crs-setup.conf](modsecurity/crs-setup.conf) | OWASP CRS v4 main config |
| [modsecurity/rules/](modsecurity/rules/) | Custom ModSecurity `.conf` rules |
| [guard/guard.py](guard/guard.py) | Python DDoS/brute-force monitor (log tail → iptables) |
| [guard/whitelist.txt](guard/whitelist.txt) | Guard-managed whitelist (auto-synced with API) |
| [api/server.js](api/server.js) | Express API: auth, rules CRUD, HAProxy reload, SSL, WAF |
| [api/ssl-manager.js](api/ssl-manager.js) | Certificate lifecycle + Certbot orchestration |
| [api/crs-manager.js](api/crs-manager.js) | OWASP CRS file management |
| [api/he-dns-manager.js](api/he-dns-manager.js) | DNS challenge automation (HE, Cloudflare, AXFR) |
| [db_import.js](db_import.js) | Bulk domain import from [dns_migration_list.json](dns_migration_list.json) |
| [monitoring/docker-compose.monitoring.yml](monitoring/docker-compose.monitoring.yml) | Loki/Promtail/Grafana stack |
| [docs/WAF_PLAN.md](docs/WAF_PLAN.md) | Phased WAF implementation plan |
| [docs/WAF_TUNING_REPORT.md](docs/WAF_TUNING_REPORT.md) | WAF rule tuning findings |

---

## API Service

- **Port:** 3000 (proxied by HAProxy; not exposed directly)
- **Auth:** JWT (12h expiry). All `/api/*` routes require `Authorization: Bearer <token>`. `/health` is open.
- **Error format:** `{ error: "message", details?: {} }`
- **DB migrations:** Run automatically on startup via `initDatabase()` in `api/server.js`.
- **Admin seeding:** First-start seeds admin user from `ADMIN_EMAIL` / `ADMIN_PASSWORD` env vars.

```bash
# Run API locally (requires DB)
cd api && npm start
# Dev mode with hot reload
cd api && npm run dev
```

---

## Database

PostgreSQL, database `haproxy`. Tables: `rules`, `rule_backends`, `port_forwarding`, `certificates`, `members`, `settings`.  
Connection pool with 30 retries (2 s interval). Credentials via env vars — **change defaults before production**.

---

## Environment Variables (critical)

| Variable | Default | Notes |
|---|---|---|
| `JWT_SECRET` | `change_this_secret` | **Must change in production** |
| `ADMIN_PASSWORD` | `admin12345` | **Must change in production** |
| `DB_PASSWORD` | `haproxy_password_change_me` | **Must change in production** |
| `MODSEC_RULE_ENGINE` | `DetectionOnly` | Set to `On` to enable WAF blocking |
| `HAPROXY_PUBLIC_IP` | `195.87.80.166` | Used for DNS challenge callbacks |

---

## Guard (DDoS / Brute-Force)

- Bans IP after **5 failures** (401/403/404/429) within **60 seconds** → 1-hour ban via iptables.
- **Critical paths** (`.env`, `.git`, `wp-admin`, `config.php`) → instant ban on first hit.
- Ignores media file 404s and ACME challenge paths to avoid false positives.
- Ban history stored at `/app/bans_history.json` inside container.
- Scripts: [guard/scripts/](guard/scripts/) (`list-bans.sh`, `unban-ip.sh`, `manual-ban.sh`).

---

## Conventions

- **JS:** async/await throughout; no callbacks. Snake_case for DB columns, camelCase for JS.
- **Config files:** lowercase with hyphens (e.g., `haproxy-rate-limit.conf`).
- **HAProxy reload:** triggered by API after any rule change — do not restart HAProxy container manually.
- **WAF rules:** place custom rules in [modsecurity/rules/](modsecurity/rules/); OWASP CRS lives in [modsecurity/crs/](modsecurity/crs/) (do not edit directly).
- **SSL certs:** managed via Certbot + `ssl-manager.js`; stored under `haproxy/certs/`.
- **Logs:** runtime logs in [logs/](logs/) — `haproxy/`, `api/`, `certbot/`, `modsecurity/`.

---

## Testing & Validation

```bash
# Full WAF + HAProxy integration test
make test-waf

# WAF audit report (top rule hits)
make waf-report

# Manual test scenarios
cat MANUAL_TEST_STEPS.md

# Volume / container health check
bash volume-validation.sh
```

See [scripts/waf_smoke_test.sh](scripts/waf_smoke_test.sh) and [scripts/waf_audit_report.sh](scripts/waf_audit_report.sh) for test details.
