# wazuh-rules-selfhosted

Custom Wazuh rules, decoders and agent group configuration for a small self-hosted setup. Two rulesets:

- `vaultwarden-stalwart-homeassistant/` - failed logins and bans for Vaultwarden, the Stalwart mail server and Home Assistant, plus FIM (file integrity monitoring) rules for SSH keys, cron, PHP files in web directories and Vaultwarden configuration.
- `php2shell/` - detections for PHP2Shell exploitation attempts (nginx and Nginx Proxy Manager access logs, nginx error log, php-fpm log, kernel segfaults) and decoders for the NPM access log and the php-fpm master log.

Rule IDs are in the 100120-100194 range of `local_rules.xml`. Check for collisions with your own local rules before deploying.

## Requirements

- Wazuh manager and agents. Written and tested on Wazuh 4.14.8 (all-in-one install). Other versions are untested.
- `wazuh-logtest`, `wazuh-analysisd`, `verify-agent-conf` and `agent_groups` available on the manager (standard in `/var/ossec/bin`).
- Root on the manager, `python3`, `systemd`.
- Per component: Vaultwarden running in Docker (json-file log driver); Stalwart with file logging; Home Assistant with an admin long-lived access token; PHP-FPM; Nginx Proxy Manager or nginx.

## Layout

```
LICENSE
README.md
vaultwarden-stalwart-homeassistant/
  rules.xml                          rules 100150-100155, 100170-100174, 100180-100184, 100190-100194
  decoders.xml                       decoders: vaultwarden-login, stalwart*, ha-security*
  agent.conf-vaultwarden             group "vaultwarden": Docker log + FIM
  agent.conf-stalwart                group "stalwart": Stalwart log + FIM of web directories
  agent.conf-ha-security             group "ha-security": /var/log/ha-security.log
  agent.conf-fim-default             FIM block for the "default" group (optional)
  ha-security-log                    Home Assistant log collector (Python)
  install-ha-security-collector.sh   installs the collector, systemd timer, logrotate
  deploy.sh                          manager-side deployment
  test.sh                            wazuh-logtest cases
php2shell/
  rules.xml                          rules 100120-100127, 100130-100132
  decoders.xml                       decoders: npm-accesslog*, php-fpm*
  agent.conf-npm                     group "npm": NPM access and error logs
  agent.conf-php-fpm                 group "php-fpm": php-fpm log + FIM of /usr/share/zabbix
  deploy.sh                          manager-side deployment
  test.sh                            wazuh-logtest cases
```

## What is detected

### Vaultwarden / Stalwart / Home Assistant / FIM

| Rule | Level | Triggers on |
|---|---|---|
| 100150 | 0 | Any Vaultwarden log line (`[vaultwarden::` in the Docker json-file log); parent of the rules below |
| 100151 | 5 | Failed login ("Username or password is incorrect"); account and source IP in the description |
| 100152 | 10 | 5 x rule 100151 from the same IP within 600 s |
| 100153 | 10 | "Invalid admin token" (wrong `/admin` panel token) |
| 100154 | 8 | `vaultwarden::ratelimit` (login rate limit exceeded) |
| 100155 | 8 | Failed second factor (TOTP, two-factor, recovery code, 2FA in the line) |
| 100190 | 0 | Any Stalwart log line; parent of the rules below |
| 100192 | 3 | `security.ip-blocked` (connection from an already banned address) |
| 100191 | 5 | `security.scan-ban` or `security.loiter-ban` (scanner banned by Stalwart) |
| 100193 | 10 | `security.authentication-ban`, `security.brute-force-ban` or `security.abuse-ban` |
| 100194 | 10 | 20 x rule 100191 within 3600 s |
| 100170 | 0 | Any line of `/var/log/ha-security.log`; parent of the rules below |
| 100171 | 5 | Home Assistant "invalid authentication" warning (failed login or wrong token) |
| 100172 | 10 | 5 x rule 100171 from the same IP within 600 s |
| 100173 | 8 | Home Assistant IP ban message ("Banned IP") |
| 100174 | 5 | "untrusted proxy" (X-Forwarded-For from a proxy not in `trusted_proxies`) |
| 100180 | 12 | FIM change (rules 550, 553, 554) of `/root/.ssh/authorized_keys` or `/root/.ssh/id_*` |
| 100181 | 10 | FIM change of files under `/var/spool/cron/` |
| 100182 | 12 | FIM change (rules 550, 554) of a `*php`, `*php<digit>`, `*phtml` or `*phar` file under `/srv` or `/var/www` (intended for servers that have no PHP at all) |
| 100183 | 10 | FIM new file (rule 554) with a PHP extension under `/usr/share/zabbix/` |
| 100184 | 10 | FIM change of `/opt/vaultwarden/data/config.json`, `rsa_key*` or `/opt/vaultwarden/docker-compose.yml` |

Levels 10 are deliberate for the "series" rules: bots guess passwords constantly and an e-mail per series would flood the mailbox. In my setup level >= 12 sends e-mail (limited to 12 per hour) and level 10 stays on the dashboard only (Discover query `rule.id:1001*`); adjust to your own alerting thresholds.

### PHP2Shell and PHP logs

| Rule | Level | Triggers on |
|---|---|---|
| 100130 | 0 | Any php-fpm master log line; parent of 100126, 100131, 100132 |
| 100131 | 3 | PHP Warning / Fatal error / Parse error message in the php-fpm log |
| 100132 | 5 | `server reached pm.max_children` or `seems busy` |
| 100120 | 10 | `php2shell` or `PHP_SESSION_UPLOAD_PROGRESS` (case-insensitive) in an access log request (URL or User-Agent); child of 31100 and 31108 |
| 100121 | 6 | POST to a `.php` URL answered with 5xx (child of built-in 31120-31123) |
| 100122 | 10 | 5 x rule 100121 from the same IP within 600 s |
| 100123 | 12 | "Allowed memory size ... exhausted ... in Unknown on line 0" in the nginx error log (child of 31420) or php-fpm log (100131): memory exhausted before any script ran |
| 100125 | 13 | 3 x rule 100123 within 600 s |
| 100124 | 7 | "Input variables exceeded" (max_input_vars) in the nginx error log or php-fpm log; informational |
| 100126 | 12 | php-fpm worker exited on signal 11, 7, 6 or 4 (SIGSEGV, SIGBUS, SIGABRT, SIGILL) |
| 100127 | 12 | Kernel log (built-in rule 1010) `php`/`php-fpm` process "segfault at" |

The rules detect attempts, not a confirmed compromise. After an alert, check the host: new `.php` files, php-fpm child processes, outgoing connections, cron, `authorized_keys`.

PHP2Shell is the name used for CVE-2026-109618 and CVE-2026-109619, patched by PHP in October 2026. Public write-ups disagree on the exact mechanism behind each identifier, so the rule descriptions name the symptom they match (out-of-memory before a script starts, worker crash) and the CVE it most likely belongs to. Check the PHP security advisories for the authoritative description and the fixed versions for your branch. The rules match symptoms of the upload-progress path in general, so they are not tied to one specific patch level.

## Deploy

All scripts run on the Wazuh manager as root. Agent IDs are passed in environment variables as space-separated lists; an empty list creates the group without assigning agents. Both `deploy.sh` scripts back up `local_rules.xml` and `local_decoder.xml` to `/root/pre-wazuh-rules-<date>/`, append the XML between marker comments (re-running replaces the block), run `wazuh-analysisd -t` (on failure the backups are restored), create the agent groups, restart the manager only if rules or decoders changed, and finish by running `test.sh`.

```
# PHP2Shell + web logs
cd php2shell
NPM_AGENT_IDS="001 002" PHPFPM_AGENT_IDS="003" ./deploy.sh

# Vaultwarden / Stalwart / Home Assistant / FIM
cd vaultwarden-stalwart-homeassistant
VAULTWARDEN_AGENT_IDS="001" STALWART_AGENT_IDS="002" HA_SECURITY_AGENT_IDS="003 004" PHPFPM_AGENT_IDS="005" ./deploy.sh
./deploy.sh --fim-default     # optional: FIM for /root/.ssh and /var/spool/cron on all agents (group "default")
```

`vaultwarden-stalwart-homeassistant/deploy.sh` also installs `../php2shell/agent.conf-php-fpm` into the `php-fpm` group, so keep both directories side by side.

`php2shell/deploy.sh` also excludes the built-in Zeus Web Server decoder and rules in the manager's `ossec.conf` (`decoder_exclude` and `rule_exclude`). That decoder matches any line starting with `[dd/Mon/yyyy:...]`, which includes NPM access logs. Skip this if you actually use Zeus; the exclusion must cover both the decoder and its rules file, otherwise the manager does not start.

nginx hosts that are not NPM: add a `<localfile>` for their access and error logs to the agent's local `ossec.conf`.

### Home Assistant collector

Home Assistant does not write the needed warnings by default. In my instances the `homeassistant` logger was at CRITICAL, so the "Login attempt or request with invalid authentication" warning (component `http.ban`) was never produced. Set the logger level for `homeassistant.components.http.ban` and `homeassistant.components.http.forwarded` to WARNING.

On a host that can reach Home Assistant (as root, with the config on stdin so the token is not in the process list):

```
printf 'URL=http://ha.example.lan:8123\nTOKEN=<long-lived access token>\n' | ./install-ha-security-collector.sh ha-main
```

The argument is a label for the instance; it appears in alerts as `$(label)`. The token must belong to an admin user. The collector reads `GET /api/hassio/core/logs` every 60 s, keeps hashes of lines already seen in `/var/lib/ha-security/<label>.seen`, and appends matching lines to `/var/log/ha-security.log` (rotated weekly, 8 copies). The first run only records existing lines. One host can serve several instances: put one `<label>.env` file per instance in `/etc/ha-security/`. A wrong Bearer token on `/api/states` is not logged by Home Assistant (only login_flow and websocket failures are).

## Test

On the manager:

```
./php2shell/test.sh                              # 22 cases
./vaultwarden-stalwart-homeassistant/test.sh     # 17 cases
```

Each case feeds one log line (or a series) through `wazuh-logtest -l <location>` and compares the last matched rule ID. Output is PASS/FAIL per case and the exit code is 1 on any failure. Run `wazuh-logtest` manually with `-l <location>` to try your own lines. FIM rules cannot be tested this way (the `syscheck` location is treated like JSON); 100180 and 100182 were verified only for syntax by the author, 100181, 100183 and 100184 on a live agent.

## Adapting

- Agent groups: group names (`vaultwarden`, `stalwart`, `ha-security`, `npm`, `php-fpm`) are only labels; the rules do not depend on them. Change the `agent.conf-*` files and the group names in `deploy.sh` together.
- Log paths: Vaultwarden `/var/lib/docker/containers/*/*-json.log` (all containers on that agent are read; the rules only match `[vaultwarden::`), Stalwart `/var/log/stalwart/stalwart.%Y-%m-%d`, NPM `/data/logs/*_access.log` and `*_error.log`, php-fpm `/var/log/php*-fpm.log`. Edit `agent.conf-*` for other locations.
- FIM paths in the rules (`/opt/vaultwarden/...`, `/usr/share/zabbix/`, `/srv`, `/var/www`) are hard-coded in both `rules.xml` and the matching `agent.conf-*` / `agent.conf-fim-default`; change them in both places.
- Rule 100182 assumes the server has no PHP at all. Remove it or narrow the paths if it does.
- Levels are set for my alerting; change `level=` as needed.

## Known limitations

- Stalwart at INFO level does not log failed authentications (`auth.failed` is a debug-level event; raising the level produced a flood of logs on a 1 vCPU server), so Stalwart detection relies on ban events from Stalwart's own mechanisms.
- Vaultwarden: the source IP in the log is the real client IP only if the proxy in front passes it on (mine passes the Cloudflare client IP header).
- Rule 100121/100122 only see requests whose status is 5xx and whose method is POST to a URL containing `.php`.
- The Home Assistant collector depends on the `/api/hassio/core/logs` endpoint; instances where that endpoint is not available are not covered.
- A Python default User-Agent can be blocked by Cloudflare in front of Home Assistant (I got 403 from a Cloudflare-fronted instance); the collector does not set a custom one.
- The php2shell rules detect attempts and indicators; they do not prove a compromise or its absence.

## Lessons from writing these rules

- `wazuh-logtest -q` prints nothing. `wazuh-analysisd -t` writes errors only to `ossec.log`; the exit code is what counts.
- `wazuh-logtest` reloads rules and decoders without a manager restart; the restart is needed only for the running analysisd.
- `offset="after_prematch"` in a decoder was rejected. `type="pcre2"` works in `<match>` and `<regex>`, not in `<url>`.
- A parent rule must be defined before the rule that references it with `if_sid`.
- Among sibling rules Wazuh checks level-0 rules first (for example 31108), then the rest from the highest level down, and uses the first match. A custom rule that should win over built-in rules must also be a child of the rules that silence it (hence 100120 under 31108 and 100121 under 31120-31123).
- Lines starting with `{"` are taken by the built-in `json` decoder, so a custom parent decoder with a prematch never runs; use a child of `json`. Of several `json` children only the first matching one is applied, so combine alternatives into one decoder with a branch-reset group `(?|...|...)`.
- `agent_groups -s -i ID` prints the agent name as well, so `grep -w <group>` matches falsely when an agent is named like the group; use `grep "groups:.*\b<group>\b"`.
- The built-in Zeus decoder captures NPM access log lines (see Deploy).
- NPM access logs use the "proxy" and "standard" formats, not Apache combined; the `npm-accesslog` decoder sets type `web-log` so the built-in web rules (31100+) apply.

## License

MIT, see `LICENSE`.
