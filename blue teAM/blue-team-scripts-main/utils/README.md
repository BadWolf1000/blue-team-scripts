# Utils — Run from any Linux box

These scripts check the whole network, not a single host.
Run them from whichever Linux box you're on.

---

## network_audit.sh — verify all 6 hosts are reachable and services are UP
```bash
# Replace 3 with your team number
bash /opt/bt/utils/network_audit.sh 3
```
Checks that the scoring engine will see your services as UP across all hosts.
Run this after hardening to confirm nothing broke.

---

## status_dashboard.sh — live view of all 6 hosts
```bash
bash /opt/bt/utils/status_dashboard.sh --loop
# Refreshes every 15 seconds
# Ctrl+C to stop
```
Shows service status across Ballast, SilkRoad, PoopDeck, Courier, BlackPearl, JollyRoger at a glance.
