# Stalwart

Detections for the Stalwart mail server log: bans imposed by Stalwart's own mechanisms (scan, loiter, authentication, brute force, abuse) and blocked connections. Rule IDs 100190-100194. The FIM rule for PHP files in web directories (100182) is in [`../fim`](../fim).

## What it detects

| Rule | Level | Triggers on |
|---|---|---|
| 100190 | 0 | Any Stalwart log line; parent of the rules below |
| 100192 | 3 | `security.ip-blocked` (connection from an already banned address) |
| 100191 | 5 | `security.scan-ban` or `security.loiter-ban` (scanner banned by Stalwart) |
| 100193 | 10 | `security.authentication-ban`, `security.brute-force-ban` or `security.abuse-ban` |
| 100194 | 10 | 20 x rule 100191 within 3600 s |

Stalwart at INFO level does not record failed authentications (`auth.failed` is a debug-level event), so the detection is based on ban events and blocked connections.

## Requirements

- Wazuh manager and an agent on the mail server. Tested on Wazuh 4.14.8.
- Stalwart with file logging at INFO level (`/var/log/stalwart/stalwart.<date>`, ANSI colours are handled).
- Root on the manager, `python3`, `systemd`.

## Files

```
rules.xml             rules 100190-100194 (block marker stalwart-rules)
decoders.xml          decoders stalwart and stalwart-security (block marker stalwart-decoders)
agent.conf-stalwart   group "stalwart": Stalwart log + syscheck of web directories for PHP files
deploy.sh             manager-side deployment
test.sh               6 wazuh-logtest cases
```

The syscheck part of `agent.conf-stalwart` (PHP files under `/srv` and `/var/www`, a server without PHP) only produces the file change events. The alert rule for them (100182, level 12) is in `../fim`. Remove the `<syscheck>` block if you do not want it.

## Deploy

On the manager, as root:

```
STALWART_AGENT_IDS="002" ./deploy.sh [--restart]
```

`STALWART_AGENT_IDS` is a space-separated list of agent IDs; empty creates the group without assigning agents. Steps: backups to `/root/pre-wazuh-rules-<date>/`, replace the `stalwart-decoders` and `stalwart-rules` blocks, `wazuh-analysisd -t` (on failure the backups are restored), group `stalwart`, manager restart only if rules or decoders changed, `test.sh`. The common mechanism is described in the top-level README.

## Test

```
./test.sh     # 6 cases (ANSI-coloured and plain lines, one series of 20 bans)
```

## Adapting

- Log path: `/var/log/stalwart/stalwart.%Y-%m-%d` in `agent.conf-stalwart`.
- The group name `stalwart` is only a label; change it in `agent.conf-stalwart` and `deploy.sh` together.
- Levels are set for my alerting; change `level=` as needed.

## Limitations

- Failed authentications are not visible at INFO level. Raising the log level to debug produced a flood of logs on a 1 vCPU server, so I did not do it.
- The rules see only the ban and block events; a slow password guesser that stays below Stalwart's own thresholds is not detected.
