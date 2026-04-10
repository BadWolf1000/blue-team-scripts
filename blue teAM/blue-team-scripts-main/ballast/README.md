# Ballast — Ubuntu 20 | 10.x.2.12
**Scored:** FTP, SSH, VNC

---

## Setup (run once at start)
```bash
cd /opt/bt/ballast && chmod +x *.sh

# 1. Harden the OS
sudo bash harden_linux.sh

# 2. Scan for pre-planted backdoors
sudo bash find_backdoors.sh

# 3. Start evidence monitor (keep running all match)
sudo bash ir_monitor.sh &

# 4. Start service watchdog (keeps FTP/SSH/VNC alive)
sudo bash service_watchdog.sh &

# 5. Verify scored services are UP
systemctl status vsftpd ssh
# VNC: check with: ss -tlnp | grep 590
```

---

## During the match
```bash
# Block an attacker IP
sudo bash block_ip.sh 10.x.x.x
sudo bash block_ip.sh list
sudo bash block_ip.sh unblock 10.x.x.x

# Service went down? Restart it
sudo bash recover_service.sh all
sudo bash recover_service.sh ssh
sudo bash recover_service.sh ftp

# Passwords compromised?
sudo bash change_passwords.sh
```

---

## Incident Response
```bash
# Take a snapshot of current evidence
sudo bash ir_collector.sh
# Output: /tmp/IR_EVIDENCE_<timestamp>/

# Generate IR report for submission
sudo bash generate_ir_report.sh "Description of attack"
# Output: ~/Desktop/blueteam_logs/IR_REPORT_<timestamp>.txt
# Convert to PDF then upload to Discord
```
