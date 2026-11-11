#!/bin/bash
# Deploy the general rules in Wazuh (quieter 31151, SSH from outside trusted networks with a self-maintaining home address list,
# listening ports, night OOM, Zabbix dashboard noise). Run ON THE MANAGER as root, with this directory next to it
# (rules.xml, decoders.xml, trusted-ssh, custom-ssh-home*, ssh-home-list.*, test.sh).
#
# Example: ./deploy.sh [--restart]
#
# Idempotent. Steps: backup -> rules block `general-rules` in local_rules.xml -> CDB list etc/lists/trusted-ssh (+ <list> entry in ossec.conf) ->
# decoder block `general-decoders` -> integration custom-ssh-home + list etc/lists/trusted-ssh-home (created once, never overwritten) ->
# log ssh-home.log -> systemd units ssh-home-list.path/.service -> `wazuh-analysisd -t` (error = restore backups) -> manager restart on change -> test.sh.
# The command that reports listening ports runs on the agents: ports-agents.sh (from a workstation).
# Rollback: backups in /root/pre-wazuh-rules-<date>/general-*, restart the manager.
set -euo pipefail
D=$(cd "$(dirname "$0")" && pwd); O=/var/ossec; B=/root/pre-wazuh-rules-$(date +%Y%m%d); mkdir -p "$B"
R=$O/etc/rules/local_rules.xml; C=$O/etc/ossec.conf; L=$O/etc/lists/trusted-ssh
cp -n "$R" "$B/general-local_rules.xml" || true; cp -n "$C" "$B/general-ossec.conf" || true
changed=0
if ! grep -q "<!-- /general-rules -->" "$R" || ! sed -n '/<!-- general-rules -->/,/<!-- \/general-rules -->/p' "$R" | cmp -s - "$D/rules.xml"; then
  python3 - "$R" "$D/rules.xml" <<'PY'
import re, sys
target, snip = sys.argv[1:]; s = open(target).read()
s = re.sub(r"\n*<!-- general-rules -->.*?<!-- /general-rules -->\n?", "\n", s, flags=re.S).rstrip("\n") + "\n\n" + open(snip).read()
open(target, "w").write(s)
PY
  changed=1; echo "local_rules.xml: block general-rules written"
fi
if ! cmp -s "$D/trusted-ssh" "$L"; then install -o root -g wazuh -m 660 "$D/trusted-ssh" "$L"; changed=1; echo "list trusted-ssh written"; fi
if ! grep -q "<list>etc/lists/trusted-ssh</list>" "$C"; then
  sed -i "s#\(\s*\)<list>etc/lists/malicious-ioc/malicious-domains</list>#&\n\1<list>etc/lists/trusted-ssh</list>   <!-- general ruleset: rule 100210 -->#" "$C"
  grep -q "<list>etc/lists/trusted-ssh</list>" "$C" || { echo "ossec.conf: <list> not added"; exit 1; }; changed=1; echo "ossec.conf: list trusted-ssh added"
fi
# --- self-maintaining home address (custom-ssh-home) ---
K=$O/etc/decoders/local_decoder.xml; cp -n "$K" "$B/general-local_decoder.xml" || true
if ! sed -n '/<!-- general-decoders -->/,/<!-- \/general-decoders -->/p' "$K" | cmp -s - "$D/decoders.xml"; then
  python3 - "$K" "$D/decoders.xml" <<'PY'
import re, sys
target, snip = sys.argv[1:]; s = open(target).read()
s = re.sub(r"\n*<!-- general-decoders -->.*?<!-- /general-decoders -->\n?", "\n", s, flags=re.S).rstrip("\n") + "\n\n" + open(snip).read()
open(target, "w").write(s)
PY
  changed=1; echo "local_decoder.xml: block general-decoders written"
fi
LD=$O/etc/lists/trusted-ssh-home; LG=$O/logs/ssh-home.log
for f in custom-ssh-home custom-ssh-home.py; do
  if ! cmp -s "$D/$f" "$O/integrations/$f"; then install -o root -g wazuh -m 750 "$D/$f" "$O/integrations/$f"; changed=1; echo "integration $f written"; fi
done
[ -e "$LG" ] || install -o wazuh -g wazuh -m 660 /dev/null "$LG"
if [ ! -s "$LD" ]; then   # an empty CDB list is an analysisd error; seed it with the current home address
  ip=$(curl -s -m 8 https://1.1.1.1/cdn-cgi/trace | sed -n 's/^ip=\([0-9]*\.[0-9]*\.[0-9]*\.\)[0-9]*$/\1/p')
  [ -n "$ip" ] || { echo "could not determine the home address for the trusted-ssh-home list"; exit 1; }
  echo "$ip:home - address at deploy time $(date +%F) (deploy.sh)" > "$LD"; chown wazuh:wazuh "$LD"; chmod 660 "$LD"; changed=1; echo "list trusted-ssh-home: $ip"
fi
python3 - "$C" <<'PY' && changed=1
import sys
c = sys.argv[1]; s = open(c).read(); before = s
if "<list>etc/lists/trusted-ssh-home</list>" not in s:
    s = s.replace("<list>etc/lists/trusted-ssh</list>", "<list>etc/lists/trusted-ssh</list>\n    <list>etc/lists/trusted-ssh-home</list>   <!-- general ruleset: self-maintaining home address (custom-ssh-home) -->", 1)
if "<name>custom-ssh-home</name>" not in s:
    block = """  <!-- ssh-home: rule 100210 -> check whether it is the new home address (general ruleset) -->
  <integration>
    <name>custom-ssh-home</name>
    <rule_id>100210</rule_id>
    <alert_format>json</alert_format>
  </integration>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/ssh-home.log</location>
  </localfile>
"""
    i = s.rindex("</ossec_config>"); s = s[:i] + block + s[i:]
if s == before: sys.exit(1)
assert "trusted-ssh-home</list>" in s and "custom-ssh-home" in s
open(c, "w").write(s); print("ossec.conf: list trusted-ssh-home, integration and ssh-home log added")
PY
for u in ssh-home-list.path ssh-home-list.service; do
  if ! cmp -s "$D/$u" "/etc/systemd/system/$u"; then install -m 644 "$D/$u" "/etc/systemd/system/$u"; systemctl daemon-reload; echo "unit $u written"; fi
done
# note: `-t` errors go to ossec.log (not stdout) - the exit code is what counts
if $O/bin/wazuh-analysisd -t >/dev/null 2>&1; then echo "analysisd -t: OK"; else
  echo "analysisd -t: ERROR - restoring backups"; grep -E "ERROR|CRITICAL" $O/logs/ossec.log | tail -5; cp "$B/general-local_rules.xml" "$R"; cp "$B/general-ossec.conf" "$C"; cp "$B/general-local_decoder.xml" "$K"; exit 1; fi
if [ "$changed" = 1 ] || [ "${1:-}" = "--restart" ]; then
  echo "restarting wazuh-manager..."; systemctl restart wazuh-manager; sleep 20; systemctl is-active wazuh-manager
fi
systemctl enable --now ssh-home-list.path >/dev/null 2>&1; systemctl is-active ssh-home-list.path
bash "$D/test.sh"
