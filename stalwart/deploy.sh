#!/bin/bash
# Deploy the Stalwart detections in Wazuh. Run ON THE MANAGER as root, with this directory
# (decoders.xml, rules.xml, agent.conf-stalwart, test.sh) next to this script.
#
# Agent IDs are a space-separated list in an environment variable (empty = the group is created but nobody is assigned):
#   STALWART_AGENT_IDS="002"   agents running the Stalwart mail server
# Example: STALWART_AGENT_IDS="002" ./deploy.sh [--restart]
#
# Idempotent: blocks between markers (stalwart-rules, stalwart-decoders) are replaced. Steps: backups -> decoders + rules ->
# `wazuh-analysisd -t` (error = restore backups) -> agent group stalwart -> manager restart (only when rules/decoders changed) -> test.sh.
# Rollback: backups from /root/pre-wazuh-rules-<date>/ (local_rules.xml, local_decoder.xml), `agent_groups -r -g stalwart`, restart the manager.
set -euo pipefail
D=$(cd "$(dirname "$0")" && pwd); O=/var/ossec; B=/root/pre-wazuh-rules-$(date +%Y%m%d); mkdir -p "$B"
R=$O/etc/rules/local_rules.xml; K=$O/etc/decoders/local_decoder.xml
cp -n "$R" "$B/local_rules.xml" 2>/dev/null || true; cp -n "$K" "$B/local_decoder.xml" 2>/dev/null || true
changed=0

# The old combined directory used the markers attacks-rules / attacks-decoders; they define the same rule IDs, so both must not coexist.
for f in "$R" "$K"; do
  if grep -q -E "<!-- attacks-(rules|decoders) -->" "$f" 2>/dev/null; then
    echo "$f still has the old combined block (attacks-rules / attacks-decoders) - remove it first, see 'Migrating' in the top-level README"; exit 1
  fi
done

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

replace_block "$K" "$D/decoders.xml" stalwart-decoders
replace_block "$R" "$D/rules.xml" stalwart-rules
chown root:wazuh "$R" "$K"; chmod 640 "$R"; chmod 660 "$K"
if $O/bin/wazuh-analysisd -t >/dev/null 2>&1; then echo "analysisd -t: OK"; else
  echo "analysisd -t: ERROR - restoring backups"; grep -E "ERROR|CRITICAL" $O/logs/ossec.log | tail -5; cp "$B/local_rules.xml" "$R"; cp "$B/local_decoder.xml" "$K"; exit 1; fi

setup_group() {   # <group> <agent.conf file> <agent id>...
  local g="$1" f="$2"; shift 2
  [ -d "$O/etc/shared/$g" ] || { $O/bin/agent_groups -a -g "$g" -q >/dev/null; echo "group $g: created"; }
  if ! cmp -s "$f" "$O/etc/shared/$g/agent.conf"; then install -o wazuh -g wazuh -m 660 "$f" "$O/etc/shared/$g/agent.conf"; echo "group $g: agent.conf written"; fi
  $O/bin/verify-agent-conf -f "$O/etc/shared/$g/agent.conf" >/dev/null || { echo "verify-agent-conf: ERROR in group $g"; exit 1; }
  for id in "$@"; do $O/bin/agent_groups -s -i "$id" 2>/dev/null | grep -q "groups:.*\b$g\b" || { $O/bin/agent_groups -a -i "$id" -g "$g" -q >/dev/null; echo "agent $id -> group $g"; }; done
}
# word splitting of the STALWART_AGENT_IDS list is intentional
# shellcheck disable=SC2086
setup_group stalwart "$D/agent.conf-stalwart" ${STALWART_AGENT_IDS:-}

if [ "$changed" = 1 ] || [ "${1:-}" = "--restart" ]; then
  echo "restarting wazuh-manager..."; systemctl restart wazuh-manager; sleep 20
  systemctl is-active wazuh-manager; grep -i -E "error|critical" $O/logs/ossec.log | grep -v "resource limit" | tail -3 || true
fi
bash "$D/test.sh"
