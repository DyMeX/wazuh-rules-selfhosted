#!/bin/bash
# FIM (syscheck) rules cannot be tested with wazuh-logtest (the syscheck location is handled like JSON), so this script has no
# logtest cases. It only checks that the rules 100180-100184 are present in the manager's local_rules.xml (run on the manager).
# Verify the alerts themselves on a live agent: change a monitored file and look for the rule ID in /var/ossec/logs/alerts/alerts.json.
# Returns 1 on failure.
set -u
R=/var/ossec/etc/rules/local_rules.xml; failures=0
for id in 100180 100181 100182 100183 100184; do
  if grep -q "<rule id=\"$id\"" "$R" 2>/dev/null; then echo "PRESENT $id"; else echo "MISSING $id"; failures=1; fi
done
exit $failures
