#!/bin/sh
set -e

RULE_ENGINE=${MODSEC_RULE_ENGINE:-DetectionOnly}
AUDIT_ENGINE=${MODSEC_AUDIT_ENGINE:-RelevantOnly}

if [ -n "${RULE_ENGINE}" ]; then
    sed -i -E "s/^SecRuleEngine .*/SecRuleEngine ${RULE_ENGINE}/" /etc/modsecurity/modsecurity.conf
fi

if [ -n "${AUDIT_ENGINE}" ]; then
    sed -i -E "s/^SecAuditEngine .*/SecAuditEngine ${AUDIT_ENGINE}/" /etc/modsecurity/modsecurity.conf
fi

if [ "${RULE_ENGINE}" = "On" ]; then
    sed -i -E 's/^SecDefaultAction "phase:1.*$/SecDefaultAction "phase:1,log,auditlog,deny,status:403"/' /etc/modsecurity/owasp-modsecurity-crs/crs-setup.conf
    sed -i -E 's/^SecDefaultAction "phase:2.*$/SecDefaultAction "phase:2,log,auditlog,deny,status:403"/' /etc/modsecurity/owasp-modsecurity-crs/crs-setup.conf
else
    sed -i -E 's/^SecDefaultAction "phase:1.*$/SecDefaultAction "phase:1,log,noauditlog,pass"/' /etc/modsecurity/owasp-modsecurity-crs/crs-setup.conf
    sed -i -E 's/^SecDefaultAction "phase:2.*$/SecDefaultAction "phase:2,log,noauditlog,pass"/' /etc/modsecurity/owasp-modsecurity-crs/crs-setup.conf
fi

if [ $# -gt 0 ] && [ "$1" = "${1#-}" ]; then
    exec "$@"
    exit
fi

unset options configFiles
while [ $# -gt 0 ]; do
    case "$1" in
        -f)
            shift
            configFiles="$configFiles $1"
            ;;
        --)
            shift
            configFiles="$configFiles $@"
            break
            ;;
        *)
            options="$options $1"
            ;;
    esac
    shift
done

configFiles="${configFiles:-/etc/modsecurity/modsecurity.conf /etc/modsecurity/owasp-modsecurity-crs.conf}"

conf=$(mktemp)
for f in $configFiles; do
    if [ ! -f "$f" ]; then
        echo "File not found: $f" >&2
        exit 1
    fi
    echo "Include $f"
done > $conf

echo "Using options:${options:- <default>}"
echo "Using config files:"
sed -n 's/Include /  - /p' $conf

exec modsecurity $options -f $conf
