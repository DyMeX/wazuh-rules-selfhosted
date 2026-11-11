#!/bin/bash
# Tests of the Vaultwarden detections through wazuh-logtest (run on the manager). Test lines follow the real log formats;
# addresses and names are placeholders.
# Returns 1 on failure.
set -u
LT=/var/ossec/bin/wazuh-logtest; failures=0
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

exit $failures
