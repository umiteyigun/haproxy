.PHONY: help test-waf waf-config waf-logs waf-report monitoring-up monitoring-down monitoring-logs

help:
	@echo "Available targets:"
	@echo "  make test-waf         # Build SPOA & HAProxy images, run syntax check and smoke test"
	@echo "  make waf-config       # Render docker compose config to ensure syntax is valid"
	@echo "  make waf-logs         # Tail HAProxy and ModSecurity logs"
	@echo "  make waf-report       # Summarize ModSecurity audit log"
	@echo "  make monitoring-up    # Start Loki/Promtail/Grafana stack"
	@echo "  make monitoring-down  # Stop monitoring stack"
	@echo "  make monitoring-logs  # Tail monitoring containers"

waf-config:
	docker compose config >/dev/null

waf-logs:
	@echo "# HAProxy (last 20 lines)" && docker logs haproxy --tail 20 || true
	@echo "# ModSecurity (last 20 lines)" && docker logs haproxy-spoa --tail 20 || true

waf-report:
	bash scripts/waf_audit_report.sh

monitoring-up:
	docker compose -f monitoring/docker-compose.monitoring.yml up -d

monitoring-down:
	docker compose -f monitoring/docker-compose.monitoring.yml down

monitoring-logs:
	@echo "# Loki" && docker logs loki --tail 20 || true
	@echo "# Promtail" && docker logs promtail --tail 20 || true
	@echo "# Grafana" && docker logs grafana --tail 20 || true

test-waf:
	docker compose build spoa haproxy
	docker compose up -d spoa haproxy
	bash scripts/waf_smoke_test.sh
