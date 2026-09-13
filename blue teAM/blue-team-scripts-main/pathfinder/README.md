# Pathfinder — Artemis Blue Team Scripts

**Host:** Pathfinder — Ubuntu 22.04 — `10.x.2.12`
**Scored services:** SSH (22), FTP (21), HTTP (80), MySQL (3306)

## Quick start

```bash
# On the box, as root:
git clone https://github.com/BadWolf1000/blue-team-scripts.git /opt/bt
cd /opt/bt/pathfinder
chmod +x *.sh

# Full hardening (prompts for a new master password, then lists any
# login-capable account NOT on the RvB packet's 20-user list and asks
# which are legitimate — the RvB 2026 environment ships ~3 accounts
# that aren't published in the packet, so answer with those names):
sudo bash harden_pathfinder.sh

# Non-interactive: pass the extras up front (comma-separated or repeated):
sudo bash harden_pathfinder.sh --keep alice,bob,carol

# Optional: also open an admin SSH port on 2222 (22 stays open for scoring):
sudo bash harden_pathfinder.sh --alt-ssh 2222

# Verify scored services after hardening:
systemctl status ssh vsftpd mysql
systemctl status apache2 2>/dev/null || systemctl status nginx
```

## What `harden_pathfinder.sh` does

1. **Baseline accounts** to `/root/pathfinder_baseline/` (passwd, shadow, sudoers, groups, authorized_keys).
2. **Discover extra Artemis accounts** — enumerates every login-capable UID>=1000 that isn't on the packet's 20-user list and prompts the operator to say which are legitimate (the RvB 2026 environment ships ~3 accounts that aren't in the packet). Kept accounts get password-rotated; the rest get locked. `--keep alice,bob,carol` skips the prompt.
3. **Rotate passwords** for every packet account, every operator-kept extra, and root — one prompted value.
4. **Lock unknown accounts** (any remaining non-system login shell not on the allow-list) and force-lock known red-team users (BarnacleBart98 etc.).
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
