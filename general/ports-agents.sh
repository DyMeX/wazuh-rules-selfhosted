#!/bin/bash
# From a workstation: adds to the local ossec.conf of every listed host with a Wazuh agent a command that lists listening TCP ports
# (rules 100220/100221) and restarts the agent. Idempotent (marker ports-wazuh; a block that differs from the one generated here is replaced).
# Local on purpose, not through agent.conf: commands from centralised configuration need logcollector.remote_commands=1 on the agents
# (the manager could then run any command on every host) - this is deliberately not enabled. ports-insert.sh runs on the target.
# Rollback: remove the ports-wazuh block from /var/ossec/etc/ossec.conf (the copy ossec.conf.pre-ports is next to it) and restart the agent.
#
# Targets (SSH destinations, root with a key), space-separated lists in environment variables:
#   PUBLIC_HOSTS="root@203.0.113.10"                    internet-facing hosts, alias public-ports -> rule 100221 (level 12)
#   HOSTS="root@192.0.2.80"                             other hosts with an agent, alias listening-ports -> rule 100220 (level 10)
#   PROXMOX_HOSTS="root@192.0.2.11 root@192.0.2.12"     Proxmox VE hosts: the host itself and every running container that has an agent
#   EXCLUDES  one line per exclusion: "<ssh destination>:<CTID> <grep -E pattern>" - listening addresses matching the pattern are dropped
#             for that container. Example (a port that opens and closes by itself, and an interface whose port changes):
#               EXCLUDES=$'root@192.0.2.11:211 :6099$\nroot@192.0.2.11:201 %wg[0-9]+:'
# Example: PUBLIC_HOSTS="root@203.0.113.10" HOSTS="root@192.0.2.80" PROXMOX_HOSTS="root@192.0.2.11" ./ports-agents.sh
set -uo pipefail
PUBLIC_HOSTS=${PUBLIC_HOSTS:-}; HOSTS=${HOSTS:-}; PROXMOX_HOSTS=${PROXMOX_HOSTS:-}; EXCLUDES=${EXCLUDES:-}
exclusion() {   # <ssh destination> <CTID> -> an extra grep -v -E pattern or empty
  printf '%s\n' "$EXCLUDES" | awk -v k="$1:$2" '$1 == k { sub(/^[^ ]+ +/, ""); print; exit }'
}
block() { cat <<XML
  <!-- ports-wazuh: ports-agents.sh - listening TCP ports without loopback and Tailscale -> rules 100220/100221 -->
  <localfile>
    <log_format>full_command</log_format>
    <command>ss -Htln | awk '{print \$4}' | grep -v -E '^(127\\.|\\[::1\\]|\\[::ffff:127\\.)|%lo:|%tailscale'${2:+ | grep -v -E '$2'} | sort -u</command>
    <alias>$1</alias>
    <frequency>300</frequency>
  </localfile>
  <!-- /ports-wazuh -->
XML
}
W="$(cd "$(dirname "$0")" && pwd)/ports-insert.sh"   # executed on the target
on_host() {   # <ssh destination> <alias>
  printf '%s\n' "== $1 (host)"
  { block "$2" > /tmp/ports-block-local; tar -C /tmp -cf - ports-block-local -C "$(dirname "$W")" ports-insert.sh 2>/dev/null; } | \
    ssh "$1" 'tar -xf - -C /tmp 2>/dev/null && mv /tmp/ports-block-local /tmp/ports-block && bash /tmp/ports-insert.sh' | sed 's/^/   /'
}
in_containers() {   # <ssh destination of a Proxmox host> - every running container with an agent
  for ct in $(ssh "$1" "pct list | awk 'NR>1 && \$2==\"running\" {print \$1}'"); do
    printf '%s\n' "== $1 CT $ct"
    { block listening-ports "$(exclusion "$1" "$ct")" > /tmp/ports-block-local; tar -C /tmp -cf - ports-block-local -C "$(dirname "$W")" ports-insert.sh 2>/dev/null; } | \
      ssh "$1" "d=\$(mktemp -d) && tar -xf - -C \$d 2>/dev/null && if pct exec $ct -- test -f /var/ossec/etc/ossec.conf; then pct push $ct \$d/ports-block-local /tmp/ports-block && pct push $ct \$d/ports-insert.sh /tmp/ports-insert.sh && pct exec $ct -- bash /tmp/ports-insert.sh; else echo 'no agent'; fi; rm -rf \$d" | sed 's/^/   /'
  done
}
for h in $PUBLIC_HOSTS; do on_host "$h" public-ports; done
for h in $HOSTS; do on_host "$h" listening-ports; done
for h in $PROXMOX_HOSTS; do on_host "$h" listening-ports; in_containers "$h"; done
