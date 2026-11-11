#!/bin/bash
# Tests of the Home Assistant detections through wazuh-logtest (run on the manager). Test lines follow the real log formats;
# addresses and names are placeholders.
# Returns 1 on failure.
set -u
LT=/var/ossec/bin/wazuh-logtest; failures=0
last_id() { sed -n "s/.*id: '\([0-9]*\)'.*/\1/p" | tail -1; }
check() { local expected="$1" id="$2" label="$3"; if [ "$id" = "$expected" ]; then echo "PASS $expected  $label"; else echo "FAIL expected $expected, got '${id:-none}'  $label"; failures=1; fi; }
test_line() { check "$1" "$(printf '%s\n' "$3" | $LT -l "$2" 2>&1 | last_id)" "${3:0:95}"; }
test_series() { local expected="$1" loc="$2"; shift 2; check "$expected" "$(printf '%s\n' "$@" | $LT -l "$loc" 2>&1 | last_id)" "series ${#}x ${1:0:70}"; }

# Home Assistant (ha-security-log collector)
HL='ha-security[ha-main]: 2026-10-23 20:28:59.905 WARNING (MainThread) [homeassistant.components.http.ban] Login attempt or request with invalid authentication from client-host (192.0.2.156). Requested URL: '"'"'/auth/login_flow/bd1c963ce44807b445323b6cc0a45c67'"'"'. (curl/8.7.1)'
test_line 100171 /var/log/ha-security.log "$HL"
test_series 100172 /var/log/ha-security.log "$HL" "$HL" "$HL" "$HL" "$HL"
test_line 100171 /var/log/ha-security.log "${HL/ha-main/ha-second}"
test_line 100173 /var/log/ha-security.log 'ha-security[ha-second]: 2026-10-23 20:30:00.000 WARNING (MainThread) [homeassistant.components.http.ban] Banned IP 203.0.113.9 for too many failed login attempts'
test_line 100174 /var/log/ha-security.log 'ha-security[ha-second]: 2026-10-23 20:31:00.000 WARNING (MainThread) [homeassistant.components.http.forwarded] Received X-Forwarded-For header from an untrusted proxy 192.0.2.10'
exit $failures
