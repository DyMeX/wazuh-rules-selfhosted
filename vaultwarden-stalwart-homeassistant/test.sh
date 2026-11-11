#!/bin/bash
# Tests of the Vaultwarden, Stalwart (with and without ANSI colours) and Home Assistant detections through wazuh-logtest
# (run on the manager). Test lines follow the real log formats; addresses and names are placeholders.
# FIM (syscheck) cannot be tested with wazuh-logtest (the syscheck location is handled like JSON) - verify it on a live agent.
# Returns 1 on failure.
set -u
LT=/var/ossec/bin/wazuh-logtest; failures=0; E=$'\033'
last_id() { sed -n "s/.*id: '\([0-9]*\)'.*/\1/p" | tail -1; }
check() { local expected="$1" id="$2" label="$3"; if [ "$id" = "$expected" ]; then echo "PASS $expected  $label"; else echo "FAIL expected $expected, got '${id:-none}'  $label"; failures=1; fi; }
test_line() { check "$1" "$(printf '%s\n' "$3" | $LT -l "$2" 2>&1 | last_id)" "${3:0:95}"; }
test_series() { local expected="$1" loc="$2"; shift 2; check "$expected" "$(printf '%s\n' "$@" | $LT -l "$loc" 2>&1 | last_id)" "series ${#}x ${1:0:70}"; }

# Vaultwarden (Docker json-file)
VL='{"log":"[2026-10-23 20:22:05.022][vaultwarden::api::identity][ERROR] Username or password is incorrect. Try again. IP: 198.51.100.23. Username: user@example.com.\n","stream":"stdout","time":"2026-10-23T18:22:05.023192586Z"}'
LOC=/var/lib/docker/containers/77386f6d/77386f6d-json.log
test_line 100151 $LOC "$VL"
test_series 100152 $LOC "$VL" "$VL" "$VL" "$VL" "$VL"
test_line 100153 $LOC '{"log":"[2026-10-23 20:24:28.043][vaultwarden::api::admin][ERROR] Invalid admin token. IP: 192.0.2.156\n","stream":"stdout","time":"2026-10-23T18:24:28.044461887Z"}'
test_line 100154 $LOC '{"log":"[2026-10-23 14:10:01.757][vaultwarden::ratelimit][ERROR] Too many login requests\n","stream":"stdout","time":"2026-10-23T12:10:01.758413349Z"}'
test_line 100155 $LOC '{"log":"[2026-10-23 20:30:00.000][vaultwarden::api::core::two_factor::authenticator][ERROR] Invalid TOTP code! Server time: 2026-10-23 18:30:00 UTC IP: 203.0.113.9\n","stream":"stdout","time":"2026-10-23T18:30:00.000000000Z"}'
test_line 100150 $LOC '{"log":"[2026-10-23 14:06:10.247][vaultwarden::api::core::ciphers::_][WARN] Data guard failed\n","stream":"stdout","time":"2026-10-23T12:06:10.000000000Z"}'

# Stalwart (with ANSI colours as in the file, and without)
SL=/var/log/stalwart/stalwart.2026-10-23
ban="${E}[37m2026-10-23T02:31:21Z${E}[0m ${E}[32;1mINFO${E}[0m ${E}[37;1mBanned due to scan${E}[0m (security.scan-ban) ${E}[36mlistenerId${E}[0m = \"submissions\", ${E}[36mlocalPort${E}[0m = 465, ${E}[36mremoteIp${E}[0m = 203.0.113.50, ${E}[36mremotePort${E}[0m = 43968, ${E}[36mreason${E}[0m = \"Invalid SMTP command\""
test_line 100191 $SL "$ban"
test_line 100191 $SL '2026-10-13T16:06:50Z INFO Banned due to scan (security.scan-ban) listenerId = "smtp", localPort = 25, remoteIp = 198.51.100.39, remotePort = 13350, remoteIp = 198.51.100.39, reason = "Invalid SMTP command"'
test_line 100192 $SL '2026-10-13T16:06:51Z INFO Blocked IP address (security.ip-blocked) listenerId = "smtp", localPort = 25, remoteIp = 198.51.100.39, remotePort = 13356'
test_line 100193 $SL "${E}[37m2026-10-23T03:00:00Z${E}[0m ${E}[32;1mINFO${E}[0m ${E}[37;1mBanned due to authentication failures${E}[0m (security.authentication-ban) ${E}[36mlistenerId${E}[0m = \"imap\", ${E}[36mremoteIp${E}[0m = 203.0.113.9, ${E}[36mremotePort${E}[0m = 1234"
test_line 100190 $SL "${E}[37m2026-10-23T18:22:59Z${E}[0m ${E}[32;1mINFO${E}[0m ${E}[37;1mMetrics collected${E}[0m (telemetry.metrics-collected) ${E}[36melapsed${E}[0m = 10ms"
bans=(); for i in $(seq 1 20); do bans+=("2026-10-23T02:31:$(printf %02d $i)Z INFO Banned due to scan (security.scan-ban) listenerId = \"smtp\", remoteIp = 198.51.100.$i, remotePort = 1"); done
test_series 100194 $SL "${bans[@]}"

# Home Assistant (ha-security-log collector)
HL='ha-security[ha-main]: 2026-10-23 20:28:59.905 WARNING (MainThread) [homeassistant.components.http.ban] Login attempt or request with invalid authentication from client-host (192.0.2.156). Requested URL: '"'"'/auth/login_flow/bd1c963ce44807b445323b6cc0a45c67'"'"'. (curl/8.7.1)'
test_line 100171 /var/log/ha-security.log "$HL"
test_series 100172 /var/log/ha-security.log "$HL" "$HL" "$HL" "$HL" "$HL"
test_line 100171 /var/log/ha-security.log "${HL/ha-main/ha-second}"
test_line 100173 /var/log/ha-security.log 'ha-security[ha-second]: 2026-10-23 20:30:00.000 WARNING (MainThread) [homeassistant.components.http.ban] Banned IP 203.0.113.9 for too many failed login attempts'
test_line 100174 /var/log/ha-security.log 'ha-security[ha-second]: 2026-10-23 20:31:00.000 WARNING (MainThread) [homeassistant.components.http.forwarded] Received X-Forwarded-For header from an untrusted proxy 192.0.2.10'
exit $failures
