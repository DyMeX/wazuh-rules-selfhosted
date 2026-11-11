#!/bin/bash
# Install the ha-security-log collector on a host that can reach Home Assistant. Run ON THAT HOST as root, with the
# ha-security-log file next to this script.
# HA configuration is passed on stdin (the secret does not end up in process arguments):
#   printf 'URL=http://ha.example.lan:8123\nTOKEN=<long-lived access token>\n' | ./install-ha-security-collector.sh <label>
# (label: any short name of the HA instance, e.g. ha-main; it appears in alerts as $(label)).
# Idempotent - running again refreshes the script, the units and (if given) the env file.
set -euo pipefail
D=$(cd "$(dirname "$0")" && pwd); E="${1:?label}"
install -d -m 700 /etc/ha-security /var/lib/ha-security
[ -t 0 ] || { umask 077; cat > "/etc/ha-security/$E.env"; }
[ -s "/etc/ha-security/$E.env" ] || { echo "missing /etc/ha-security/$E.env"; exit 1; }
install -m 755 "$D/ha-security-log" /usr/local/sbin/ha-security-log
touch /var/log/ha-security.log; chmod 640 /var/log/ha-security.log
cat > /etc/logrotate.d/ha-security <<'LR'
/var/log/ha-security.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    copytruncate
}
LR
cat > /etc/systemd/system/ha-security-log.service <<'UN'
[Unit]
Description=Home Assistant intrusion attempts -> /var/log/ha-security.log (Wazuh)
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/ha-security-log
Nice=10
UN
cat > /etc/systemd/system/ha-security-log.timer <<'UN'
[Unit]
Description=Home Assistant intrusion attempt collector every minute

[Timer]
OnBootSec=2min
OnUnitActiveSec=60s
AccuracySec=5s

[Install]
WantedBy=timers.target
UN
systemctl daemon-reload; systemctl enable --now ha-security-log.timer >/dev/null
systemctl start ha-security-log.service && echo "collector: first run OK (state remembered)"; systemctl is-active ha-security-log.timer
