# Home Assistant

Detections for failed logins, wrong tokens, IP bans and untrusted proxy headers in Home Assistant. Home Assistant does not write a log file with these events, so a small collector reads the Core log through the API and appends the relevant lines to `/var/log/ha-security.log`. Rule IDs 100170-100174. One host can serve several Home Assistant instances.

## What it detects

| Rule | Level | Triggers on |
|---|---|---|
| 100170 | 0 | Any line of `/var/log/ha-security.log`; parent of the rules below |
| 100171 | 5 | Home Assistant "invalid authentication" warning (failed login or wrong token) |
| 100172 | 10 | 5 x rule 100171 from the same IP within 600 s |
| 100173 | 8 | Home Assistant IP ban message ("Banned IP") |
| 100174 | 5 | "untrusted proxy" (X-Forwarded-For from a proxy not in `trusted_proxies`) |

The alert description contains the instance label (`$(label)`), so several instances are told apart.

## Requirements

- Wazuh manager and an agent on the host that runs the collector. Tested on Wazuh 4.14.8.
- A host that can reach Home Assistant, with `python3` and `systemd`.
- A long-lived access token of an admin user (the collector reads `GET /api/hassio/core/logs`).
- The loggers `homeassistant.components.http.ban` and `homeassistant.components.http.forwarded` at WARNING level. In my instances the `homeassistant` logger was at CRITICAL, so the "Login attempt or request with invalid authentication" warning was never produced.

## Files

```
rules.xml                         rules 100170-100174 (block marker home-assistant-rules)
decoders.xml                      decoders ha-security, ha-security-login, ha-security-other (block marker home-assistant-decoders)
agent.conf-ha-security            group "ha-security": reads /var/log/ha-security.log
ha-security-log                   collector (Python)
install-ha-security-collector.sh  installs the collector, systemd timer and logrotate on the host
deploy.sh                         manager-side deployment
test.sh                           5 wazuh-logtest cases
```

## Deploy

Collector, on the host that can reach Home Assistant (as root; the configuration comes on stdin so the token is not in the process list):

```
printf 'URL=http://ha.example.lan:8123\nTOKEN=<long-lived access token>\n' | ./install-ha-security-collector.sh ha-main
```

The argument is a label for the instance. The collector reads the Core log every 60 s, keeps hashes of lines already seen in `/var/lib/ha-security/<label>.seen`, and appends matching lines to `/var/log/ha-security.log` (rotated weekly, 8 copies). The first run only records existing lines. For several instances put one `<label>.env` file per instance in `/etc/ha-security/`.

Rules, on the manager, as root:

```
HA_SECURITY_AGENT_IDS="003 004" ./deploy.sh [--restart]
```

`HA_SECURITY_AGENT_IDS` is a space-separated list of agent IDs; empty creates the group without assigning agents. Steps: backups to `/root/pre-wazuh-rules-<date>/`, replace the `home-assistant-decoders` and `home-assistant-rules` blocks, `wazuh-analysisd -t` (on failure the backups are restored), group `ha-security`, manager restart only if rules or decoders changed, `test.sh`. The common mechanism is described in the top-level README.

## Test

```
./test.sh     # 5 cases (second instance label, series of 5 failed logins)
```

## Adapting

- Output file `/var/log/ha-security.log`: `OUTPUT` in `ha-security-log`, the decoder prematch in `decoders.xml` and `agent.conf-ha-security` use the same name and the `ha-security[<label>]:` prefix.
- Which lines are collected: the `INTERESTING` regular expression in `ha-security-log`.
- The group name `ha-security` is only a label; change it in `agent.conf-ha-security` and `deploy.sh` together.
- Levels are set for my alerting; change `level=` as needed.

## Limitations

- The collector depends on the `/api/hassio/core/logs` endpoint; instances where it is not available are not covered.
- A wrong Bearer token on `/api/states` is not logged by Home Assistant (only login_flow and websocket failures are).
- A Python default User-Agent can be blocked by Cloudflare in front of Home Assistant (I got 403 from a Cloudflare-fronted instance); the collector does not set a custom one.
- Detection delay is up to one collector interval (60 s).
