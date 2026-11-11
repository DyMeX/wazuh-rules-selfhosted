#!/bin/bash
# Tests of the PHP2Shell rules and the NPM/php-fpm decoders through wazuh-logtest (run on the manager). Result: PASS/FAIL per case.
# Test lines follow the real formats of NPM, nginx, php-fpm and journald; addresses and names are placeholders.
# Returns 1 if anything failed.
set -u
LT=/var/ossec/bin/wazuh-logtest; failures=0
test_line() {   # <expected rule id> <location> <log line>
  local expected="$1" loc="$2" line="$3" result id
  result=$(printf '%s\n' "$line" | $LT -l "$loc" 2>&1)
  id=$(printf '%s\n' "$result" | sed -n "s/.*id: '\([0-9]*\)'.*/\1/p" | tail -1)
  if [ "$id" = "$expected" ]; then echo "PASS $expected  ${line:0:90}"; else echo "FAIL expected $expected, got '${id:-none}'  ${line:0:90}"; printf '%s\n' "$result" | grep -E "decoder|id:|level|Rule|Phase" | head -8; failures=1; fi
}
# NPM proxy / standard -> decoder npm-accesslog -> built-in web rules (31100+)
test_line 31101 /data/logs/proxy-host-1_access.log '[23/Oct/2026:07:43:40 +0200] - - 403 - GET https app.example.com "/%2F.github%2Fissue_template" [Client 203.0.113.38] [Length 111] [Gzip 1.35] [Sent-to 192.0.2.70] "curl/8.7.1" "-"'
test_line 31108 /data/logs/proxy-host-9_access.log '[23/Oct/2026:18:13:17 +0200] - 200 200 - POST http ha.example.com "/api/webhook/0123456789abcdef" [Client 203.0.113.57] [Length 2] [Gzip -] [Sent-to 192.0.2.90] "Home Assistant/2026.6.5-22884 (Android 16; SM-S906B)" "-"'
test_line 31100 /data/logs/default-host_access.log '[23/Oct/2026:07:43:40 +0200] 404 - GET http 192.0.2.88 "/" [Client 192.0.2.5] [Length 0] [Gzip -] "curl/8.7.1" "-"'
test_line 31104 /data/logs/proxy-host-1_access.log '[23/Oct/2026:07:43:40 +0200] - - 404 - GET https app.example.com "/../../etc/passwd" [Client 203.0.113.38] [Length 111] [Gzip 1.35] [Sent-to 192.0.2.70] "curl/8.7.1" "-"'
# PHP2Shell - access log: indicator in UA / URL (NPM and classic nginx)
test_line 100120 /data/logs/proxy-host-1_access.log '[23/Oct/2026:07:43:40 +0200] - - 404 - POST https app.example.com "/index.php" [Client 203.0.113.38] [Length 111] [Gzip 1.35] [Sent-to 192.0.2.70] "php2shell/1.0" "-"'
test_line 100120 /var/log/nginx/access.log '203.0.113.9 - - [23/Oct/2026:18:16:14 +0200] "POST /index.php?PHP_SESSION_UPLOAD_PROGRESS=x HTTP/1.1" 200 3994 "-" "Mozilla/5.0"'
test_line 100120 /var/log/nginx/access.log '127.0.0.1 - - [23/Oct/2026:18:33:41 +0200] "GET / HTTP/1.1" 200 3994 "-" "php2shell-e2e2-test"'
test_line 100120 /data/logs/proxy-host-9_access.log '[23/Oct/2026:18:24:53 +0200] - 302 302 - GET https app.example.com "/" [Client 198.51.100.23] [Length 0] [Gzip -] [Sent-to 192.0.2.70] "php2shell-test" "-"'
test_line 100121 /var/log/nginx/access.log '203.0.113.9 - - [23/Oct/2026:18:16:14 +0200] "POST /index.php HTTP/1.1" 500 0 "-" "Mozilla/5.0"'
test_line 31122 /var/log/nginx/access.log '203.0.113.9 - - [23/Oct/2026:18:16:14 +0200] "GET /index.php HTTP/1.1" 500 0 "-" "Mozilla/5.0"'
# series: 5 x POST .php -> 5xx from one IP in one logtest session -> the last line must give 100122
series=$(for i in 1 2 3 4 5; do printf '%s\n' "203.0.113.9 - - [23/Oct/2026:18:16:1$i +0200] \"POST /index.php HTTP/1.1\" 502 0 \"-\" \"Mozilla/5.0\""; done | $LT -l /var/log/nginx/access.log 2>&1 | sed -n "s/.*id: '\([0-9]*\)'.*/\1/p" | tail -1)
if [ "$series" = 100122 ]; then echo "PASS 100122  series 5 x POST .php -> 502"; else echo "FAIL expected 100122, got '${series:-none}'  series 5 x POST .php -> 502"; failures=1; fi
# PHP2Shell - nginx error log (FastCGI stderr) and php-fpm.log
test_line 100123 /var/log/nginx/error.log '2026/10/23 18:16:14 [error] 211237#211237: *45 FastCGI sent in stderr: "PHP message: PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 12582920 bytes) in Unknown on line 0" while reading response header from upstream, client: 203.0.113.9, server: zabbix.example.com, request: "POST /index.php HTTP/1.1", upstream: "fastcgi://unix:/var/run/php/zabbix.sock:", host: "zabbix.example.com"'
test_line 31420 /var/log/nginx/error.log '2026/10/23 18:16:14 [error] 211237#211237: *45 FastCGI sent in stderr: "PHP message: PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 12582920 bytes) in /usr/share/zabbix/ui/include/db.inc.php on line 206" while reading response header from upstream, client: 203.0.113.9, server: zabbix.example.com, request: "POST /index.php HTTP/1.1", upstream: "fastcgi://unix:/var/run/php/zabbix.sock:", host: "zabbix.example.com"'
test_line 100124 /var/log/nginx/error.log '2026/10/23 18:16:14 [error] 211237#211237: *45 FastCGI sent in stderr: "PHP message: PHP Warning:  Input variables exceeded 1000. To increase the limit change max_input_vars in php.ini. in Unknown on line 0" while reading response header from upstream, client: 203.0.113.9, server: zabbix.example.com, request: "POST /index.php HTTP/1.1", upstream: "fastcgi://unix:/var/run/php/zabbix.sock:", host: "zabbix.example.com"'
test_line 100123 /var/log/php8.2-fpm.log '[23-Oct-2026 18:16:14] NOTICE: PHP message: PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 12582920 bytes) in Unknown on line 0'
test_line 100124 /var/log/php8.2-fpm.log '[23-Oct-2026 18:16:14] WARNING: [pool zabbix] child 1234 said into stderr: "PHP message: PHP Warning:  Input variables exceeded 1000. To increase the limit change max_input_vars in php.ini. in Unknown on line 0"'
test_line 100126 /var/log/php8.2-fpm.log '[23-Oct-2026 18:16:14] WARNING: [pool zabbix] child 1234 exited on signal 11 (SIGSEGV) after 3.214 seconds from start'
test_line 100130 /var/log/php8.2-fpm.log '[23-Oct-2026 15:36:40] NOTICE: [pool zabbix] child 208866 started'
test_line 100131 /var/log/php8.2-fpm.log '[23-Oct-2026 18:16:14] NOTICE: PHP message: PHP Warning:  Undefined variable $x in /usr/share/zabbix/ui/index.php on line 5'
test_line 100132 /var/log/php8.2-fpm.log '[23-Oct-2026 18:16:14] WARNING: [pool zabbix] server reached pm.max_children setting (5), consider raising it'
# kernel (host journald): php-fpm segfault
test_line 100127 journald 'Oct 23 18:16:14 host1 kernel: php-fpm8.2[31337]: segfault at 0 ip 00005600deadbeef sp 00007ffc0badf00d error 4 in php-fpm8.2[5600de000000+400000]'
test_line 1010 journald 'Oct 23 18:16:14 host1 kernel: python3[31337]: segfault at 0 ip 00005600deadbeef sp 00007ffc0badf00d error 4 in python3.13[5600de000000+400000]'
exit $failures
