# wazuh-rules-selfhosted

Custom Wazuh rules, decoders and agent group configuration for a small self-hosted setup. Three rulesets:

- `vaultwarden-stalwart-homeassistant/` - failed logins and bans for Vaultwarden, the Stalwart mail server and Home Assistant, plus FIM (file integrity monitoring) rules for SSH keys, cron, PHP files in web directories and Vaultwarden configuration.
- `php2shell/` - detections for PHP2Shell exploitation attempts (nginx and Nginx Proxy Manager access logs, nginx error log, php-fpm log, kernel segfaults) and decoders for the NPM access log and the php-fpm master log.
- `general/` - quieter built-in rule 31151, 401 series, SSH logins from outside trusted networks (with a home address list that maintains itself), changes of listening ports on agents, night OOM noise and Zabbix dashboard noise.

Rule IDs are in the 100120-100230 range of `local_rules.xml` (plus an `overwrite` of the built-in 31151). Check for collisions with your own local rules before deploying.

## Requirements

- Wazuh manager and agents. Written and tested on Wazuh 4.14.8 (all-in-one install). Other versions are untested.
- `wazuh-logtest`, `wazuh-analysisd`, `verify-agent-conf` and `agent_groups` available on the manager (standard in `/var/ossec/bin`).
- Root on the manager, `python3`, `systemd`.
- `general/`: `curl` on the manager (used once to seed the home list), SSH access with a key to the hosts that get the ports command; optionally Tailscale on the manager. Rule 100230 is a child of built-in 31533, so Zabbix web access logs must be read by Wazuh.
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
general/
  rules.xml                          rules 100200-100201, 100210-100212, 100220-100221, 100225, 100230; overwrite of 31151
  decoders.xml                       decoder: ssh-home
  trusted-ssh                        CDB list of fixed trusted networks (documentation ranges as examples)
  custom-ssh-home, custom-ssh-home.py  integration that maintains the home address list
  ssh-home-list.path, .service       systemd units: restart the manager when the home list changes
  ports-agents.sh, ports-insert.sh   listening-ports command for the agents' local ossec.conf (run from a workstation)
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

### General rules (`general/`)

| Rule | Level | Triggers on |
|---|---|---|
| 31151 | 6 | Built-in "Multiple web server 400 error codes from same source ip" with `overwrite="yes"`: level lowered from 10 to 6, rest of the definition unchanged |
| 100200 | 5 | Web access log line with status 401 (child of 31101) |
| 100201 | 10 | 8 x rule 100200 from the same IP within 300 s (password guessing against a page with HTTP authentication) |
| 100210 | 5 | Successful SSH login (built-in 5715) from an address that is in neither `etc/lists/trusted-ssh` nor `etc/lists/trusted-ssh-home`; runs the integration `custom-ssh-home` |
| 100211 | 12 | Integration result "foreign": login address is not a public IPv4, the home address could not be determined, or the address is outside the /24 of the current home address |
| 100212 | 3 | Integration result "home": the login address is in the /24 of the current home address, the prefix was added to `trusted-ssh-home` |
| 100220 | 10 | Change of the set of listening TCP ports on an agent (alias `listening-ports`, `check_diff` on rule 530) |
| 100221 | 12 | Same for hosts with the alias `public-ports` (internet-facing hosts) |
| 100225 | 8 | Built-in 5108 (system out of memory, level 12) between 22:55 and 05:40 manager time (UTC): lowered because night maintenance triggers it |
| 100230 | 0 | Zabbix web interface POSTs (31533) from one fixed address, matching dashboard refresh URLs; silenced |

I lowered 31151 because 714 level 10 alerts in 5 days came almost entirely from scanners on my public server, which CrowdSec bans and Cloudflare blocks anyway, and they hid real level 10 alerts. 401 series have their own rule (100201).

Rule 100225 and 100230 are tuned to my setup: the time window is in the manager's time zone (UTC in my case) and the source address of 100230 is a documentation address (`192.0.2.11`) that you replace with the host your Zabbix dashboard is viewed from.

#### How the self-maintaining home address list works

The public address of a residential line changes every few days, and a level 12 e-mail for every change was noise. Instead, the home list updates itself:

1. A successful SSH login from an address outside both lists matches rule 100210 (level 5, no e-mail). `integratord` runs `custom-ssh-home` (a shell wrapper that starts `custom-ssh-home.py` with the manager's own Python) with the alert as a JSON file.
2. The script collects the current public addresses of home: the endpoints reported by `tailscale status --json` on the manager (if Tailscale is installed there) and the `ip=` value from `https://1.1.1.1/cdn-cgi/trace`. Only global IPv4 addresses outside 100.64.0.0/10 are kept.
3. It decides: login address not a public IPv4, or no home address found, or login /24 not among the /24s of the home addresses -> result "foreign". Otherwise the /24 prefix (for example `198.51.100.`) is appended to `etc/lists/trusted-ssh-home` (key `prefix:description`, at most 8 entries, the oldest drop out) and the result is "home". If the prefix was already in the list the result is "home-known" and nothing is logged. Any exception is also "foreign", with the error in the reason.
4. The result is one text line in `/var/ossec/logs/ssh-home.log` (`ssh-home: <result> srcip=... user=... target=... prefix=... home=... reason=... entry=...`). It is plain text because JSON is taken by other `json` child decoders and the fields get lost. The decoder `ssh-home` reads it: "foreign" gives rule 100211 (level 12), "home" gives rule 100212 (level 3).
5. Wazuh loads CDB lists only when `analysisd` starts. `ssh-home-list.path` watches the list file; on change `ssh-home-list.service` runs `wazuh-analysisd -t` and restarts the manager. The service has a start limit of 6 per hour.

`trusted-ssh` holds fixed networks and is written by `deploy.sh`; `trusted-ssh-home` is written only by the integration (`deploy.sh` creates it once with the current home /24 and never overwrites it). A dry run without writing: `SSH_HOME_DRY_RUN=1 /var/ossec/integrations/custom-ssh-home <alert.json> x x` (as user `wazuh`) prints the log line.

#### Listening ports

`ports-agents.sh` runs on a workstation and adds a `<localfile>` with `log_format` `full_command` to the local `ossec.conf` of each listed host (and of each running Proxmox container that has an agent), then restarts the agent. The command is `ss -Htln` without loopback addresses and without the `%tailscale` interface, sorted and de-duplicated, every 300 s. `check_diff` makes rule 530 produce an alert on every change of the output, and 100220/100221 match it by alias. The first output is only remembered, so a fresh install is silent (logtest therefore shows 530). I put the command in the local `ossec.conf` instead of `agent.conf` because commands from centralised configuration require `logcollector.remote_commands=1` on the agents, which would let the manager run any command on every host.

## Deploy

All `deploy.sh` scripts run on the Wazuh manager as root. Agent IDs are passed in environment variables as space-separated lists; an empty list creates the group without assigning agents. The `deploy.sh` scripts back up `local_rules.xml` and `local_decoder.xml` to `/root/pre-wazuh-rules-<date>/`, append the XML between marker comments (re-running replaces the block), run `wazuh-analysisd -t` (on failure the backups are restored), create the agent groups, restart the manager only if rules or decoders changed, and finish by running `test.sh`.

```
# PHP2Shell + web logs
cd php2shell
NPM_AGENT_IDS="001 002" PHPFPM_AGENT_IDS="003" ./deploy.sh

# Vaultwarden / Stalwart / Home Assistant / FIM
cd vaultwarden-stalwart-homeassistant
VAULTWARDEN_AGENT_IDS="001" STALWART_AGENT_IDS="002" HA_SECURITY_AGENT_IDS="003 004" PHPFPM_AGENT_IDS="005" ./deploy.sh
./deploy.sh --fim-default     # optional: FIM for /root/.ssh and /var/spool/cron on all agents (group "default")

# General rules (on the manager; no agent IDs, the rules apply to all agents)
cd general
./deploy.sh [--restart]

# Listening ports (from a workstation with SSH keys to the targets, not on the manager)
cd general
PUBLIC_HOSTS="root@203.0.113.10" HOSTS="root@192.0.2.80" PROXMOX_HOSTS="root@192.0.2.11" ./ports-agents.sh
```

`general/deploy.sh` has no agent groups. Its steps: write the `general-rules` and `general-decoders` blocks, write the CDB list `etc/lists/trusted-ssh` and register it in the manager's `ossec.conf`, install the integration into `/var/ossec/integrations/`, create `trusted-ssh-home` (seeded with the current home /24 from the Cloudflare trace; it aborts if the address cannot be determined, because an empty CDB list is an `analysisd` error), register the second list, the `<integration>` for rule 100210 and the `<localfile>` for `ssh-home.log`, install the two systemd units, run `wazuh-analysisd -t` (error = restore backups), restart the manager if anything changed, enable `ssh-home-list.path`, run `test.sh`. Backup file names there start with `general-`.

`ports-agents.sh` takes its targets from environment variables: `PUBLIC_HOSTS` (alias `public-ports`, level 12), `HOSTS` (alias `listening-ports`, level 10), `PROXMOX_HOSTS` (the host and every running container with an agent, found with `pct list`), and `EXCLUDES` (one line per container: `<ssh destination>:<CTID> <grep -E pattern>`, listening addresses matching the pattern are dropped; in my setup a container where Xvfb opens and closes a TCP port by itself, and a container whose port on a VPN interface changes with the server). It is idempotent and keeps a copy `ossec.conf.pre-ports` on each target; if the agent does not start after the change, the copy is restored.

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
./general/test.sh                                # 18 cases (17 if the home address cannot be determined)
```

Each case feeds one log line (or a series) through `wazuh-logtest -l <location>` and compares the last matched rule ID. Output is PASS/FAIL per case and the exit code is 1 on any failure. `general/test.sh` also runs a dry run of the integration three times (foreign address, non-public address, and a neighbour of the current home address); the last one is skipped when the home address cannot be determined. It needs `curl` and `su` to user `wazuh`. The night OOM case (100225) expects 5108 outside the 22:55-05:40 UTC window and 100225 inside it, so the expected ID depends on the time of day. Run `wazuh-logtest` manually with `-l <location>` to try your own lines. FIM rules cannot be tested this way (the `syscheck` location is treated like JSON); 100180 and 100182 were verified only for syntax by the author, 100181, 100183 and 100184 on a live agent. The ports rules are covered only up to rule 530 in logtest (the first output is remembered, the alert comes with the second, different output); The 100220/100221 alert itself is not covered by `test.sh`.

## Adapting

- Agent groups: group names (`vaultwarden`, `stalwart`, `ha-security`, `npm`, `php-fpm`) are only labels; the rules do not depend on them. Change the `agent.conf-*` files and the group names in `deploy.sh` together.
- Log paths: Vaultwarden `/var/lib/docker/containers/*/*-json.log` (all containers on that agent are read; the rules only match `[vaultwarden::`), Stalwart `/var/log/stalwart/stalwart.%Y-%m-%d`, NPM `/data/logs/*_access.log` and `*_error.log`, php-fpm `/var/log/php*-fpm.log`. Edit `agent.conf-*` for other locations.
- FIM paths in the rules (`/opt/vaultwarden/...`, `/usr/share/zabbix/`, `/srv`, `/var/www`) are hard-coded in both `rules.xml` and the matching `agent.conf-*` / `agent.conf-fim-default`; change them in both places.
- Rule 100182 assumes the server has no PHP at all. Remove it or narrow the paths if it does.
- Levels are set for my alerting; change `level=` as needed.
- General rules: replace the example networks in `general/trusted-ssh` (LAN, home ISP range, VPN ranges) with yours; keep one `key:value` per line and no empty file. If you change them, change the addresses in `general/test.sh` as well (192.0.2.x = trusted LAN, 198.51.100.x = trusted home, 203.0.113.x = foreign).
- 100230: set `<srcip>` in `general/rules.xml` to the host your Zabbix dashboard is viewed from, or remove the rule.
- Night window of 100225: edit `<time>` (manager time).
- Home address source: `TRACE_URL` in `custom-ssh-home.py` and the URL in `deploy.sh`/`test.sh`; `MAX_ENTRIES` is the number of home prefixes kept.
- Rule IDs and the list/decoder names (`trusted-ssh`, `trusted-ssh-home`, `ssh-home`) are referenced in several files; rename them in all of `rules.xml`, `decoders.xml`, `deploy.sh`, `test.sh`, the integration and the unit files together.

## Known limitations

- General rules: the trusted list entries in `trusted-ssh` are examples (documentation ranges). With the shipped list every address outside them triggers the integration on a successful SSH login, so edit the list before deploying.
- The home address check trusts a whole /24. Anyone logging in from the same /24 as the current home address (for example another customer of the same mobile operator pool) is treated as home.
- The home address logic is IPv4 only. A login from an IPv6 address is not a public IPv4 for the script and ends as "foreign" (level 12).
- Every new home prefix restarts the manager, because Wazuh reads CDB lists only at `analysisd` start. Until the restart, further logins from the same prefix repeat rule 100210 (level 5) without a log line.
- If the home address cannot be determined (no internet from the manager, Cloudflare trace unreachable, no Tailscale), logins from new addresses give level 12.
- 100210 reacts only to built-in rule 5715 (sshd successful authentication).
- Ports: TCP only; loopback and the Tailscale interface are not listed; containers without an agent and the manager itself are not covered by `ports-agents.sh`.
- 100225 uses the manager's clock; if your manager is not in UTC, change `<time>`.

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
