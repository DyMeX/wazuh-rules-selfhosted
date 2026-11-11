# FIM (file integrity monitoring)

Rules for syscheck events that indicate a compromise rather than an attempt: root SSH keys, user cron files, PHP files in web directories of a server without PHP, new PHP files in the Zabbix frontend, Vaultwarden configuration and key. Rule IDs 100180-100184. These rules have no decoder and no log file; they are children of the built-in syscheck rules 550, 553 and 554.

## What it detects

| Rule | Level | Triggers on |
|---|---|---|
| 100180 | 12 | FIM change (rules 550, 553, 554) of `/root/.ssh/authorized_keys` or `/root/.ssh/id_*` |
| 100181 | 10 | FIM change of files under `/var/spool/cron/` |
| 100182 | 12 | FIM change (rules 550, 554) of a `*php`, `*php<digit>`, `*phtml` or `*phar` file under `/srv` or `/var/www` (intended for servers that have no PHP at all) |
| 100183 | 10 | FIM new file (rule 554) with a PHP extension under `/usr/share/zabbix/` |
| 100184 | 10 | FIM change of `/opt/vaultwarden/data/config.json`, `rsa_key*` or `/opt/vaultwarden/docker-compose.yml` |

When you add your own SSH key, 100180 fires; that is expected. Changes to existing Zabbix files during a package upgrade stay at the built-in level 7.

## Requirements

- Wazuh manager and agents with syscheck. Tested on Wazuh 4.14.8.
- The agents must monitor the paths, otherwise the rules never fire. Where the monitoring comes from:

| Rule | Syscheck configuration |
|---|---|
| 100180, 100181 | `agent.conf-fim-default` in this directory (group "default", all agents, optional) |
| 100182 | `<syscheck>` in `../stalwart/agent.conf-stalwart` (`/srv`, `/var/www`), or your own |
| 100183 | `<syscheck>` in `../php2shell/agent.conf-php-fpm` (`/usr/share/zabbix`), or your own |
| 100184 | `<syscheck>` in `../vaultwarden/agent.conf-vaultwarden` (`/opt/vaultwarden`), or your own |

This directory does not depend on the other rulesets being installed; it only needs events from somewhere. Without the service directories you must configure syscheck for 100182-100184 yourself.

## Files

```
rules.xml               rules 100180-100184 (block marker fim-rules)
agent.conf-fim-default  FIM block for the "default" group (block marker fim-default)
deploy.sh               manager-side deployment
test.sh                 presence check of the rule IDs (no logtest cases)
```

## Deploy

On the manager, as root:

```
./deploy.sh                 # rules only
./deploy.sh --fim-default   # rules + FIM of /root/.ssh and /var/spool/cron on all agents (group "default")
```

Steps: backups to `/root/pre-wazuh-rules-<date>/`, replace the `fim-rules` block, `wazuh-analysisd -t` (on failure the backups are restored), with `--fim-default` insert the `fim-default` block before the closing `</agent_config>` of the default group's `agent.conf` and run `verify-agent-conf` (on failure the backup is restored), manager restart only if rules changed, `test.sh`. Check the syntax of the default-group block on one agent first, because it applies to every agent. The common mechanism is described in the top-level README.

## Test

wazuh-logtest cannot test syscheck rules (the syscheck location is handled like JSON), so there are no logtest cases. `test.sh` only checks that the five rule IDs are in `local_rules.xml`. Verify the alerts on a live agent: change a monitored file and look for the rule ID in `/var/ossec/logs/alerts/alerts.json`. Rules 100181, 100183 and 100184 were verified on a live agent, 100180 and 100182 only for syntax.

## Adapting

- Paths are hard-coded in `rules.xml` (`<field name="file">`) and in the matching `agent.conf-*` files (`restrict`, directories). Change them in both places.
- Rule 100182 assumes the server has no PHP at all. Remove it or narrow the paths if it does.
- Levels are set for my alerting; change `level=` as needed.

## Limitations

- FIM cannot be tested with logtest (see above).
- Realtime monitoring covers only what the agent configuration lists; the rules say nothing about paths nobody watches.
- 100182 and 100183 are specific to my hosts (no PHP on the mail server, Zabbix frontend on the monitoring host).
