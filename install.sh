#!/bin/sh
# Installs Home Command on Debian or Ubuntu as a system service. Run as root from the folder that holds portal.py.
set -e
[ "$(id -u)" = 0 ] || { echo "Run this as root."; exit 1; }
SRC=$(cd "$(dirname "$0")" && pwd); PORT="${HC_PORT:-3000}"
command -v apt-get >/dev/null || { echo "This installer is for Debian or Ubuntu. On other systems use Docker (see README.md)."; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get update -q >/dev/null; apt-get install -y -q python3 python3-maxminddb curl ca-certificates >/dev/null
id homecommand >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -d /var/lib/homecommand homecommand
install -d -o root -g root /opt/homecommand /opt/homecommand/static
install -d -o homecommand -g homecommand -m 700 /var/lib/homecommand
install -m 644 "$SRC/portal.py" "$SRC/portal-shipper.py" /opt/homecommand/
install -m 644 "$SRC"/static/* /opt/homecommand/static/
cat > /etc/systemd/system/homecommand.service <<UNIT
[Unit]
Description=Home Command portal
After=network-online.target
Wants=network-online.target
[Service]
User=homecommand
Group=homecommand
Environment=HC_DATA=/var/lib/homecommand HC_PORT=$PORT PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 /opt/homecommand/portal.py
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/homecommand
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload; systemctl enable -q homecommand; systemctl restart homecommand
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo "Home Command is running. Open http://${IP:-THIS-MACHINE}:$PORT in a browser to choose a password and start the walkthrough."
echo "To update later: replace the files in this folder and run this script again. Your data in /var/lib/homecommand is kept."
