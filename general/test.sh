#!/bin/bash
# Tests of the general rules through wazuh-logtest (run on the manager). Result: PASS/FAIL per case.
# Addresses are documentation ranges: 192.0.2.0/24 = example LAN and 198.51.100.0/24 = example home address (both in the trusted-ssh list
# as shipped), 203.0.113.0/24 = foreign. If you changed the list, change the addresses here too. Returns 1 if anything failed.
set -u
LT=/var/ossec/bin/wazuh-logtest; failures=0
rule_id() { sed -n "s/.*id: '\([0-9]*\)'.*/\1/p" | tail -1; }
check() { if [ "$2" = "$1" ]; then echo "PASS $1  $3"; else echo "FAIL expected $1, got '${2:-none}'  $3"; failures=1; fi; }
test_line() { check "$1" "$(printf '%s\n' "$3" | $LT -l "$2" 2>&1 | rule_id)" "${3:0:95}"; }
test_series() { local expected="$1" loc="$2" n="$3" line="$4"; check "$expected" "$(for i in $(seq 1 "$n"); do printf '%s\n' "$line"; done | $LT -l "$loc" 2>&1 | rule_id)" "series ${n}x ${line:0:60}"; }
SSH='Oct 23 21:00:00 host1 sshd-session[1234]: Accepted publickey for root from %s port 50000 ssh2: ED25519 SHA256:abcdef'
test_line 5715 journald "$(printf "$SSH" 192.0.2.74)"
test_line 5715 journald "$(printf "$SSH" 100.88.105.22)"
test_line 5715 journald "$(printf "$SSH" 127.0.0.1)"
test_line 100210 journald "$(printf "$SSH" 203.0.113.9)"
test_line 100210 journald "$(printf "$SSH" 100.200.1.1)"
test_line 5715 journald "$(printf "${SSH/host1/web1}" 198.51.100.43)"
test_line 5715 journald "$(printf "${SSH/host1/web1}" 198.51.100.200)"
test_line 100210 journald "$(printf "${SSH/host1/web1}" 203.0.113.77)"
# self-maintaining home address: entries of the custom-ssh-home integration in logs/ssh-home.log + a dry run of the integration (foreign address and home address)
test_line 100211 /var/ossec/logs/ssh-home.log 'ssh-home: foreign srcip=203.0.113.9 user=root target=web1 prefix=- home=198.51.100.1 reason=address outside the /24 of the current home address entry=Nov 11 12:39:35 web1 sshd-session[1]: Accepted publickey for root from 203.0.113.9'
test_line 100212 /var/ossec/logs/ssh-home.log 'ssh-home: home srcip=198.51.100.7 user=root target=web1 prefix=198.51.100. home=198.51.100.1 reason=address in the /24 of the current home address entry=x'
dry_run() { local t; t=$(mktemp); chmod 644 "$t"; printf '{"agent":{"name":"web1"},"full_log":"test","data":{"srcip":"%s","dstuser":"root"}}' "$2" > "$t"
  check "$1" "$(su -s /bin/sh wazuh -c "SSH_HOME_DRY_RUN=1 /var/ossec/integrations/custom-ssh-home $t x x" 2>&1 | sed -n 's/^ssh-home: \([a-z-]*\) .*/\1/p')" "integration custom-ssh-home: $2 ($3)"; rm -f "$t"; }
HOME_IP=$(curl -s -m 8 https://1.1.1.1/cdn-cgi/trace | sed -n 's/^ip=//p')
dry_run foreign 203.0.113.9 "foreign address"
dry_run foreign 10.1.2.3 "non-public address"
[ -n "$HOME_IP" ] && dry_run home-known "${HOME_IP%.*}.1" "neighbour of the home address, prefix already in the list"
WEB='203.0.113.38 - - [23/Oct/2026:18:16:14 +0200] "GET /.env HTTP/1.1" 404 0 "-" "Mozilla/5.0"'
test_series 31151 /var/log/nginx/access.log 14 "$WEB"
test_line 100200 /var/log/nginx/access.log '203.0.113.9 - - [23/Oct/2026:18:16:14 +0200] "GET /protected/ HTTP/1.1" 401 0 "-" "Mozilla/5.0"'
test_series 100201 /var/log/nginx/access.log 8 '203.0.113.9 - - [23/Oct/2026:18:16:14 +0200] "GET /protected/ HTTP/1.1" 401 0 "-" "Mozilla/5.0"'
# ports: check_diff alerts only on a CHANGE of the output (the first output is only remembered) - logtest shows 530; a live test is described in the README
check 530 "$(printf '%s\n' "ossec: output: 'listening-ports':" | $LT -l listening-ports 2>&1 | rule_id)" "ports - first output without an alert (check_diff)"
# 5108 at night (22:55-05:40 UTC, manager time) -> 100225 (level 8); during the day it stays 5108
OOM='Nov  2 01:35:00 host2 kernel: [123456.789] Out of Memory: Killed process 1234 (worker) total-vm:3000000kB'
m=$((10#$(date -u +%H) * 60 + 10#$(date -u +%M)))
if [ $m -ge 1375 ] || [ $m -le 340 ]; then test_line 100225 syslog "$OOM"; else test_line 5108 syslog "$OOM"; fi
exit $failures
