#!/usr/bin/env python3
"""Wazuh integration for rule 100210 (successful SSH login from an address outside the trusted lists). Runs on the manager as user wazuh.
The home address (a residential line) changes every few days, so instead of a level 12 alert on every change:
  - the login address is in the same /24 as the current public address of home (endpoints of the manager's Tailscale + 1.1.1.1/cdn-cgi/trace)
    -> the prefix is added to etc/lists/trusted-ssh-home (ssh-home-list.path restarts the manager), a "home" line is logged -> rule 100212 (level 3);
  - any other address, or a failed check -> a "foreign" line is logged -> rule 100211 (level 12: e-mail, escalation).
Arguments from integratord: alert file (JSON), api_key, hook_url. Dry run without writing: SSH_HOME_DRY_RUN=1 (result on stdout).
Installed by deploy.sh."""
import ipaddress, json, os, subprocess, sys, time, urllib.request

LIST_FILE = "/var/ossec/etc/lists/trusted-ssh-home"
LOG = "/var/ossec/logs/ssh-home.log"
TRACE_URL = "https://1.1.1.1/cdn-cgi/trace"
MAX_ENTRIES = 8          # older home prefixes drop out of the list
DRY_RUN = os.environ.get("SSH_HOME_DRY_RUN") == "1"


def is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and a.is_global and a not in ipaddress.ip_network("100.64.0.0/10")


def home_addresses():
    """Current public addresses of home; empty = could not be determined."""
    result = set()
    try:  # Tailscale endpoints of this host (STUN) - without asking the internet
        st = json.loads(subprocess.run(["tailscale", "status", "--json"], capture_output=True, text=True, timeout=10).stdout)
        result |= {a.rsplit(":", 1)[0] for a in st["Self"].get("Addrs") or []}
    except Exception:
        pass
    try:
        with urllib.request.urlopen(TRACE_URL, timeout=8) as r:
            result |= {l[3:].strip() for l in r.read().decode().splitlines() if l.startswith("ip=")}
    except Exception:
        pass
    return {a for a in result if is_public(a)}


def prefix_of(ip):
    return ip.rsplit(".", 1)[0] + "."


def append_prefix(pref, description):
    """Appends a prefix to the CDB list (key:value); False if it was already there."""
    try:
        rows = [w for w in open(LIST_FILE).read().splitlines() if w.strip()]
    except FileNotFoundError:
        rows = []
    if any(w.split(":", 1)[0] == pref for w in rows):
        return False
    rows = (rows + [f"{pref}:{description}"])[-MAX_ENTRIES:]
    if DRY_RUN:
        return True
    tmp = LIST_FILE + ".new"
    with open(tmp, "w") as f:
        f.write("\n".join(rows) + "\n")
    os.chmod(tmp, 0o660)
    os.replace(tmp, LIST_FILE)   # ssh-home-list.path sees the change and restarts the manager
    return True


def write_entry(entry):
    """One line of text for the ssh-home decoder (JSON is taken by other json child decoders and the fields are lost)."""
    clean = lambda v: str(v).replace(" ", "_") or "-"
    line = ("ssh-home: {ssh_home} srcip={srcip} user={dstuser} target={target} prefix={prefix} home={home} reason={reason} entry={entry}"
            .format(**{**{k: clean(v) for k, v in entry.items()}, "reason": entry["reason"].replace(" entry=", " "), "entry": entry["entry"]}))
    if DRY_RUN:
        print(line)
        return
    with open(LOG, "a") as f:
        f.write(line + "\n")


def main():
    entry = {"ssh_home": "foreign", "srcip": "", "dstuser": "", "target": "", "entry": "", "home": "", "prefix": "", "reason": ""}
    try:
        alert = json.load(open(sys.argv[1]))
        data = alert.get("data", {})
        entry.update(srcip=data.get("srcip", ""), dstuser=data.get("dstuser", ""),
                     target=alert.get("agent", {}).get("name", ""), entry=alert.get("full_log", "")[:400])
        ip = entry["srcip"]
        home = home_addresses()
        entry["home"] = ",".join(sorted(home))
        if not is_public(ip):
            entry["reason"] = "login address is not a public IPv4"
        elif not home:
            entry["reason"] = "current home address could not be determined"
        elif prefix_of(ip) not in {prefix_of(d) for d in home}:
            entry["reason"] = "address outside the /24 of the current home address"
        else:
            new = append_prefix(prefix_of(ip), f"home - added automatically {time.strftime('%Y-%m-%d %H:%M')} (custom-ssh-home, login from {ip})")
            entry.update(ssh_home="home" if new else "home-known", prefix=prefix_of(ip), reason="address in the /24 of the current home address")
    except Exception as e:   # an error is an alarm, not silence
        entry["reason"] = f"check error: {e!r}"[:300]
    if DRY_RUN or entry["ssh_home"] != "home-known":   # prefix already added, manager not yet reloaded - no repeats in the log
        write_entry(entry)


if __name__ == "__main__":
    main()
