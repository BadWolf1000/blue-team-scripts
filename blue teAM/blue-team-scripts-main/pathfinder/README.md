# Pathfinder — Artemis Blue Team Scripts

**Host:** Pathfinder — Ubuntu 22.04 — `10.x.2.12`
**Scored services:** SSH (22), FTP (21), HTTP (80), MySQL (3306)

## Quick start

```bash
# On the box, as root:
git clone https://github.com/BadWolf1000/blue-team-scripts.git /opt/bt
cd /opt/bt/pathfinder
chmod +x *.sh

# Full hardening (prompts for a new master password):
sudo bash harden_pathfinder.sh

# Optional: also open an admin SSH port on 2222 (22 stays open for scoring):
sudo bash harden_pathfinder.sh --alt-ssh 2222

# Verify scored services after hardening:
systemctl status ssh vsftpd mysql
systemctl status apache2 2>/dev/null || systemctl status nginx
```

## What `harden_pathfinder.sh` does

1. **Baseline accounts** to `/root/pathfinder_baseline/` (passwd, shadow, sudoers, groups, authorized_keys).
2. **Rotate passwords** for every Artemis account (20 users from the RvB cred sheet) + root using one prompted value.
3. **Lock unknown accounts** (any non-system login shell not on the allow-list) and force-lock known red-team users (BarnacleBart98 etc.).
4. **Harden SSH** (no root login, MaxAuthTries 3, no forwarding); leave 22 open for scoring; optionally add an admin port.
5. **Firewall** with UFW — allow only the scored ports, explicitly deny known red-team ports (23, 1337, 4444, 8888, 9990, VNC).
6. **Clean Linux run keys** — `/etc/rc.local`, `/etc/profile.d`, every user's `.bashrc/.profile`, all crontabs, `/etc/cron.*`.
7. **Stop / disable / mask** Sliver beacon systemd unit names, wall, sptty, gumper, self-healing watcher, telnetd, xinetd, VNC servers. Kill any process still listening on the known red-team ports. Quarantine the standard red-team drop paths.
8. **SUID audit** — remove SUID from busybox; inventory everything else.
9. **Restore `passwd`/`chpasswd`** if the skimmer wrapper is present (reinstall the `passwd` package). Preserve `/tmp/.creds.log` as evidence.
10. **Fix PAM bypass** — remove `pam_permit.so` line from `common-auth`, reinstall `libpam-modules`.
11. **Kernel sysctl hardening** (rp_filter, syncookies, ptrace_scope, kptr_restrict, protected_symlinks, etc.).
12. **Account watch report** at `~/blueteam_logs/accounts_monitor_<ts>.txt` and a **systemd timer** that re-checks every 5 minutes for new users, sudo-group changes, new authorized_keys, and extra UID=0 accounts. Log at `/var/log/pathfinder_acct_monitor.log`.

## Do NOT touch (per RvB rules)

- `wazuh-agent` — the SIEM node depends on it.
- Wiretap, Scoring Engine, OpenStack — competition infrastructure.
- Scored ports 22 / 21 / 80 / 3306 — moving these breaks the scoring engine.

## Related scripts (from sibling folders)

Run these next from `ballast/` or `silkroad/` (same repo):

- `find_backdoors.sh` — dedicated persistence/backdoor scanner.
- `ir_monitor.sh` — background evidence collector (auth events, new listeners, sessions).
- `service_watchdog.sh` — keeps scored services alive if red team kills them.
- `block_ip.sh` — block a specific attacker IP (never subnets — competition rule).
