#!/bin/bash
# Deploy the PHP2Shell rules (CVE-2026-109618/109619) + nginx/NPM/php-fpm log decoding in Wazuh. Run ON THE MANAGER as root,
# with this directory next to it (decoders.xml, rules.xml, agent.conf-npm, agent.conf-php-fpm, test.sh).
#
# Agent IDs per group are space-separated lists in environment variables:
#   NPM_AGENT_IDS="001 002"   agents on hosts running Nginx Proxy Manager
#   PHPFPM_AGENT_IDS="003"    agents on hosts running php-fpm
# nginx hosts outside NPM: configure a <localfile> for the nginx access/error log in the agent's local ossec.conf.
# Example: NPM_AGENT_IDS="001 002" PHPFPM_AGENT_IDS="003" ./deploy.sh [--restart]
#
# Idempotent (markers in the files). Steps: backup -> append decoders/rules -> `wazuh-analysisd -t` (error = restore backups) ->
# disable the built-in Zeus decoder/rules -> agent groups npm and php-fpm -> manager restart -> test.sh.
# Rollback: backups in /root/pre-wazuh-rules-<date>/ (local_rules.xml, local_decoder.xml, ossec.conf), `agent_groups -r -g npm`, restart the manager.
set -euo pipefail
D=$(cd "$(dirname "$0")" && pwd); O=/var/ossec; B=/root/pre-wazuh-rules-$(date +%Y%m%d); mkdir -p "$B"
R=$O/etc/rules/local_rules.xml; K=$O/etc/decoders/local_decoder.xml
cp -n "$R" "$B/local_rules.xml" 2>/dev/null || true; cp -n "$K" "$B/local_decoder.xml" 2>/dev/null || true
changed=0
replace_block() {   # <target file> <snippet file> <marker> - the block from "<!-- marker -->" to "<!-- /marker -->" is replaced with the new one
  local target="$1" snip="$2" mk="$3"
  if grep -q "<!-- /$mk -->" "$target" && sed -n "/<!-- $mk -->/,/<!-- \/$mk -->/p" "$target" 2>/dev/null | cmp -s - "$snip"; then return 0; fi
  python3 - "$target" "$snip" "$mk" <<'PY'
import re, sys
target, snip, mk = sys.argv[1:]; s = open(target).read()
s = re.sub(r"\n*<!-- %s -->.*?<!-- /%s -->\n*" % (re.escape(mk), re.escape(mk)), "\n", s, flags=re.S).rstrip("\n") + "\n\n" + open(snip).read()
open(target, "w").write(s)
PY
  changed=1; echo "$(basename "$target"): block $mk written"
}
replace_block "$K" "$D/decoders.xml" php2shell-decoders
replace_block "$R" "$D/rules.xml" php2shell-rules
chown root:wazuh "$R" "$K"; chmod 640 "$R"; chmod 660 "$K"
# note: `-t` errors go to ossec.log (not stdout) - the exit code is what counts
if $O/bin/wazuh-analysisd -t >/dev/null 2>&1; then echo "analysisd -t: OK"; else
  echo "analysisd -t: ERROR - restoring backups"; grep -E "ERROR|CRITICAL" $O/logs/ossec.log | tail -5; cp "$B/local_rules.xml" "$R"; cp "$B/local_decoder.xml" "$K"; exit 1; fi

# The built-in "zeus" decoder (Zeus Web Server) matches every line starting with "[dd/Mon/yyyy:...]", including NPM access logs,
# before etc/decoders is reached - Zeus is not used here, so it is excluded.
# The Zeus rules must be excluded together with the decoder (0255-zeus_rules.xml has <decoded_as>zeus</decoded_as> - without the decoder the manager does not start).
C=$O/etc/ossec.conf; Z=$(basename "$(ls $O/ruleset/decoders/*zeus* 2>/dev/null | head -1)"); ZR=$(basename "$(ls $O/ruleset/rules/*zeus* 2>/dev/null | head -1)")
if [ -n "$Z" ] && [ -n "$ZR" ] && ! grep -q "decoder_exclude>ruleset/decoders/$Z" "$C"; then
  cp -n "$C" "$B/ossec.conf" 2>/dev/null || true
  sed -i "s#<decoder_dir>etc/decoders</decoder_dir>#<decoder_dir>etc/decoders</decoder_dir>\n    <!-- Zeus Web Server (unused) matched NPM access logs - php2shell ruleset -->\n    <decoder_exclude>ruleset/decoders/$Z</decoder_exclude>\n    <rule_exclude>$ZR</rule_exclude>#" "$C"
  grep -q "decoder_exclude>ruleset/decoders/$Z" "$C" && { changed=1; echo "ossec.conf: excluded $Z + $ZR"; } || { echo "ossec.conf: failed to add decoder_exclude"; exit 1; }
  $O/bin/wazuh-analysisd -t >/dev/null 2>&1 || { echo "analysisd -t after decoder_exclude: ERROR - restoring ossec.conf"; cp "$B/ossec.conf" "$C"; exit 1; }
fi

# agent groups (centralised configuration; an agent restarts itself after it fetches the new merged.mg)
for g in npm php-fpm; do
  [ -d "$O/etc/shared/$g" ] || { $O/bin/agent_groups -a -g "$g" -q >/dev/null; echo "group $g: created"; }
  if ! cmp -s "$D/agent.conf-$g" "$O/etc/shared/$g/agent.conf"; then install -o wazuh -g wazuh -m 660 "$D/agent.conf-$g" "$O/etc/shared/$g/agent.conf"; echo "group $g: agent.conf written"; fi
done
$O/bin/verify-agent-conf -f "$O/etc/shared/npm/agent.conf" >/dev/null && $O/bin/verify-agent-conf -f "$O/etc/shared/php-fpm/agent.conf" >/dev/null && echo "verify-agent-conf: OK"
assign() { local id="$1" g="$2"; $O/bin/agent_groups -s -i "$id" 2>/dev/null | grep -q "groups:.*\b$g\b" || { $O/bin/agent_groups -a -i "$id" -g "$g" -q >/dev/null; echo "agent $id -> group $g"; }; }
for id in ${NPM_AGENT_IDS:-}; do assign "$id" npm; done
for id in ${PHPFPM_AGENT_IDS:-}; do assign "$id" php-fpm; done

if [ "$changed" = 1 ] || [ "${1:-}" = "--restart" ]; then
  echo "restarting wazuh-manager..."; systemctl restart wazuh-manager; sleep 20
  systemctl is-active wazuh-manager; grep -i -E "error|critical" $O/logs/ossec.log | tail -3 || true
fi
bash "$D/test.sh"
