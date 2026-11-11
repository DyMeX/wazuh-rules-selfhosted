#!/bin/bash
# Deploy the FIM (syscheck) detections 100180-100184 in Wazuh. Run ON THE MANAGER as root, with this directory
# (rules.xml, agent.conf-fim-default, test.sh) next to this script.
#
# Without arguments only the rules are installed. The rules alert only for paths that agents actually monitor:
#   - /root/.ssh and /var/spool/cron: optional FIM block in the "default" group (all agents), switch --fim-default
#   - /srv, /var/www (100182): syscheck in ../stalwart/agent.conf-stalwart, or your own syscheck on the web directories
#   - /opt/vaultwarden (100184): syscheck in ../vaultwarden/agent.conf-vaultwarden, or your own syscheck
#   - /usr/share/zabbix (100183): syscheck in ../php2shell/agent.conf-php-fpm, or your own syscheck
# Usage: ./deploy.sh [--fim-default|--restart]
# The FIM block in the default group is a separate switch; check the syntax on one agent first.
#
# Idempotent: blocks between markers (fim-rules, fim-default) are replaced. Steps: backups -> rules -> `wazuh-analysisd -t`
# (error = restore backups) -> [--fim-default: FIM block in the default group] -> manager restart (only when rules changed) -> test.sh.
# Rollback: backups from /root/pre-wazuh-rules-<date>/ (local_rules.xml, fim-default-agent.conf), restart the manager.
set -euo pipefail
D=$(cd "$(dirname "$0")" && pwd); O=/var/ossec; B=/root/pre-wazuh-rules-$(date +%Y%m%d); mkdir -p "$B"
R=$O/etc/rules/local_rules.xml; K=$O/etc/decoders/local_decoder.xml; DEF=$O/etc/shared/default/agent.conf
cp -n "$R" "$B/local_rules.xml" 2>/dev/null || true
cp -n "$DEF" "$B/fim-default-agent.conf" 2>/dev/null || true
changed=0

# The old combined directory used the marker attacks-rules; it defines the same rule IDs (100180-100184), so both must not coexist.
if grep -q "<!-- attacks-rules -->" "$R" 2>/dev/null; then
  echo "$R still has the old combined block (attacks-rules) - remove it first, see 'Migrating' in the top-level README"; exit 1
fi

replace_block() {   # <file> <snippet> <marker> [insert-before]: the block from "<!-- marker -->" to "<!-- /marker -->" is replaced; by default appended at the end of the file
  local target="$1" snip="$2" mk="$3" before="${4:-}"
  if grep -q "<!-- /$mk -->" "$target" && sed -n "/<!-- $mk -->/,/<!-- \/$mk -->/p" "$target" 2>/dev/null | cmp -s - "$snip"; then return 0; fi
  python3 - "$target" "$snip" "$mk" "$before" <<'PY'
import re, sys
target, snip, mk, before = sys.argv[1:]; s = open(target).read(); n = open(snip).read()
s2 = re.sub(r"[ \t]*<!-- %s -->.*?<!-- /%s -->[ \t]*\n?" % (re.escape(mk), re.escape(mk)), "", s, flags=re.S)
if before:
    i = s2.rindex(before); s2 = s2[:i] + n.rstrip("\n") + "\n" + s2[i:]
else:
    s2 = s2.rstrip("\n") + "\n\n" + n
open(target, "w").write(s2)
PY
  case "$target" in "$R"|"$K") changed=1;; esac   # restart the manager only after rule/decoder changes (group agent.conf is picked up by remoted)
  echo "$(basename "$target"): block $mk written"
}

replace_block "$R" "$D/rules.xml" fim-rules
chown root:wazuh "$R"; chmod 640 "$R"
if $O/bin/wazuh-analysisd -t >/dev/null 2>&1; then echo "analysisd -t: OK"; else
  echo "analysisd -t: ERROR - restoring backups"; grep -E "ERROR|CRITICAL" $O/logs/ossec.log | tail -5; cp "$B/local_rules.xml" "$R"; exit 1; fi

if [ "${1:-}" = "--fim-default" ]; then   # FIM in the default group (all agents)
  # the old combined directory called this block attacks-fim; drop it so the paths are not monitored twice
  if grep -q "<!-- attacks-fim -->" "$DEF"; then
    python3 - "$DEF" <<'PY'
import re, sys
s = open(sys.argv[1]).read()
open(sys.argv[1], "w").write(re.sub(r"[ \t]*<!-- attacks-fim -->.*?<!-- /attacks-fim -->[ \t]*\n?", "", s, flags=re.S))
PY
    echo "default agent.conf: old attacks-fim block removed"
  fi
  replace_block "$DEF" "$D/agent.conf-fim-default" fim-default "</agent_config>"
  $O/bin/verify-agent-conf -f "$DEF" >/dev/null || { echo "verify-agent-conf: ERROR in default - restoring"; cp "$B/fim-default-agent.conf" "$DEF"; exit 1; }
fi

if [ "$changed" = 1 ] || [ "${1:-}" = "--restart" ]; then
  echo "restarting wazuh-manager..."; systemctl restart wazuh-manager; sleep 20
  systemctl is-active wazuh-manager; grep -i -E "error|critical" $O/logs/ossec.log | grep -v "resource limit" | tail -3 || true
fi
bash "$D/test.sh"
