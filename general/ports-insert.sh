#!/bin/bash
# On a host with a Wazuh agent (run by ports-agents.sh): inserts the block from /tmp/ports-block before the last </ossec_config>, restarts the agent,
# and restores the copy ossec.conf.pre-ports if the agent does not start.
f=/var/ossec/etc/ossec.conf
[ -f $f ] || { echo "no agent"; exit 0; }
if grep -q "ports-wazuh" $f; then
  if sed -n '/<!-- ports-wazuh:/,/<!-- \/ports-wazuh -->/p' $f | cmp -s - /tmp/ports-block; then echo "already present"; rm -f /tmp/ports-block /tmp/ports-insert.sh; exit 0; fi
  cp $f $f.pre-ports; perl -0pi -e 's#[ \t]*<!-- ports-wazuh:.*?<!-- /ports-wazuh -->\n##s' $f; echo "block differs from the repository - replacing"   # per-host exclusions
else cp -n $f $f.pre-ports; fi
perl -0pi -e 'BEGIN{local $/; open F, "/tmp/ports-block"; $b = <F>} s#(</ossec_config>\s*)\z#$b$1#' $f
grep -q "ports-wazuh" $f || { echo "ERROR inserting the block"; exit 0; }
systemctl restart wazuh-agent; sleep 3
if systemctl is-active -q wazuh-agent; then echo "added, agent active"; else cp $f.pre-ports $f; systemctl restart wazuh-agent; echo "ERROR: agent did not start - ossec.conf restored"; fi
rm -f /tmp/ports-block /tmp/ports-insert.sh
