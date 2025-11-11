.PHONY: help test-waf waf-config waf-logs waf-report

help:
	@echo "Available targets:"
	@echo "  make test-waf   # Build SPOA & HAProxy images, run syntax check and smoke test"
	@echo "  make waf-config # Render docker compose config to ensure syntax is valid"
	@echo "  make waf-logs   # Tail HAProxy and ModSecurity logs"
	@echo "  make waf-report # Summarize ModSecurity audit log"

waf-config:
	docker compose config >/dev/null

waf-logs:
	@echo "# HAProxy (last 20 lines)" && docker logs haproxy --tail 20 || true
	@echo "# ModSecurity (last 20 lines)" && docker logs haproxy-spoa --tail 20 || true

waf-report:
	bash scripts/waf_audit_report.sh

test-waf:
	docker compose build spoa haproxy
	docker compose up -d spoa haproxy
	bash scripts/waf_smoke_test.sh
