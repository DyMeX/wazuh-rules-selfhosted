# Vaultwarden

Detections for failed logins, wrong admin tokens, rate limiting and failed second factor in the Vaultwarden container log (Docker json-file driver). Rule IDs 100150-100155. The FIM rule for the Vaultwarden configuration (100184) is in [`../fim`](../fim).

## What it detects

| Rule | Level | Triggers on |
|---|---|---|
| 100150 | 0 | Any Vaultwarden log line (`[vaultwarden::` in the Docker json-file log); parent of the rules below |
| 100151 | 5 | Failed login ("Username or password is incorrect"); account and source IP in the description |
| 100152 | 10 | 5 x rule 100151 from the same IP within 600 s |
| 100153 | 10 | "Invalid admin token" (wrong `/admin` panel token) |
| 100154 | 8 | `vaultwarden::ratelimit` (login rate limit exceeded) |
| 100155 | 8 | Failed second factor (TOTP, two-factor, recovery code, 2FA in the line) |

Level 10 is deliberate for the series rule: bots guess passwords constantly and an e-mail per series would flood the mailbox. In my setup level >= 12 sends e-mail and level 10 stays on the dashboard only; adjust to your own thresholds.

## Requirements

- Wazuh manager and an agent on the Vaultwarden host. Tested on Wazuh 4.14.8.
- Vaultwarden running in Docker with the json-file log driver (no Vaultwarden restart is needed to read the log).
- Root on the manager, `python3`, `systemd`.

## Files

```
rules.xml            rules 100150-100155 (block marker vaultwarden-rules)
decoders.xml         decoder vaultwarden-login, a child of the built-in json decoder (block marker vaultwarden-decoders)
agent.conf-vaultwarden  group "vaultwarden": Docker log + syscheck of configuration and key
deploy.sh            manager-side deployment
test.sh              6 wazuh-logtest cases
```

The syscheck part of `agent.conf-vaultwarden` only produces the file change events. The alert rule for them (100184, level 10) is in `../fim`; without it the changes are reported by the built-in syscheck rules at a lower level.

## Deploy

On the manager, as root:

```
VAULTWARDEN_AGENT_IDS="001" ./deploy.sh [--restart]
```

`VAULTWARDEN_AGENT_IDS` is a space-separated list of agent IDs; empty creates the group without assigning agents. The script backs up `local_rules.xml` and `local_decoder.xml` to `/root/pre-wazuh-rules-<date>/`, replaces the `vaultwarden-decoders` and `vaultwarden-rules` blocks, runs `wazuh-analysisd -t` (on failure the backups are restored), creates the group `vaultwarden`, restarts the manager only if rules or decoders changed, and runs `test.sh`. The common mechanism is described in the top-level README.

## Test

```
./test.sh     # 6 cases
```

## Adapting

- Log path: `/var/lib/docker/containers/*/*-json.log` in `agent.conf-vaultwarden`. All containers on that agent are read; the rules only match `[vaultwarden::`.
- FIM paths (`/opt/vaultwarden/data`, `/opt/vaultwarden/docker-compose.yml`) are in `agent.conf-vaultwarden` and in rule 100184 in `../fim/rules.xml`; change both.
- The group name `vaultwarden` is only a label; change it in `agent.conf-vaultwarden` and `deploy.sh` together.
- Levels are set for my alerting; change `level=` as needed.

## Limitations

- The source IP in the log is the real client IP only if the proxy in front passes it on (mine passes the Cloudflare client IP header).
- Lines start with `{"`, so the built-in json decoder takes them; the decoder is a child of `json` and a single decoder with a branch-reset group covers both log formats (see lessons in the top-level README).
