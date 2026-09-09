#!/bin/bash
# install_service_linux.sh
# Installs ARGUS Linux collectors as systemd services.
# Run with: sudo ./install_service_linux.sh

set -e

INSTALL_DIR="/opt/soc-testing/collectors"
LOG_DIR="/opt/soc-testing/logs"
SERVICE_USER="root"

echo "[ARGUS] Installing Linux collectors..."

# 1. Create directories
mkdir -p "$INSTALL_DIR"
mkdir -p "$LOG_DIR"

# 2. Copy collector files (assumes they're in current directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$SCRIPT_DIR/collector.py" ]; then
    cp "$SCRIPT_DIR/collector.py" "$INSTALL_DIR/"
    echo "[ARGUS] Copied collector.py"
else
    echo "[ARGUS] ERROR: collector.py not found in $SCRIPT_DIR"
    exit 1
fi

if [ -f "$SCRIPT_DIR/firewall_collector.py" ]; then
    cp "$SCRIPT_DIR/firewall_collector.py" "$INSTALL_DIR/"
    echo "[ARGUS] Copied firewall_collector.py"
else
    echo "[ARGUS] WARNING: firewall_collector.py not found, skipping"
fi

if [ -f "$SCRIPT_DIR/risk_scoring.py" ]; then
    cp "$SCRIPT_DIR/risk_scoring.py" "$INSTALL_DIR/"
    echo "[ARGUS] Copied risk_scoring.py"
fi

# 3. Install dependencies (assumes python3 already installed)
pip3 install --quiet --break-system-packages watchdog || \
pip3 install --quiet watchdog || \
echo "[ARGUS] WARNING: pip install failed, you may need to install dependencies manually"

# 4. Create auth collector service
cat > /etc/systemd/system/argus-auth.service << 'EOF'
[Unit]
Description=ARGUS Linux Auth Log Collector
After=network.target
Documentation=https://github.com/your-org/argus

[Service]
Type=simple
User=root
WorkingDirectory=/opt/soc-testing/collectors
ExecStart=/usr/bin/python3 /opt/soc-testing/collectors/auth_collector.py
Restart=always
RestartSec=5
StartLimitInterval=60
StartLimitBurst=3

# Logging
StandardOutput=append:/opt/soc-testing/logs/auth.out.log
StandardError=append:/opt/soc-testing/logs/auth.err.log

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/soc-testing/logs /var/log
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

echo "[ARGUS] Created /etc/systemd/system/argus-auth.service"

# 5. Create system/firewall collector service
cat > /etc/systemd/system/argus-system.service << 'EOF'
[Unit]
Description=ARGUS Linux System & Firewall Collector
After=network.target
Documentation=https://github.com/your-org/argus

[Service]
Type=simple
User=root
WorkingDirectory=/opt/soc-testing/collectors
ExecStart=/usr/bin/python3 /opt/soc-testing/collectors/system_firewall_collector.py
Restart=always
RestartSec=5
StartLimitInterval=60
StartLimitBurst=3

# Logging
StandardOutput=append:/opt/soc-testing/logs/system.out.log
StandardError=append:/opt/soc-testing/logs/system.err.log

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/soc-testing/logs /var/log
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

echo "[ARGUS] Created /etc/systemd/system/argus-system.service"

# 6. Create logrotate config (prevent disk fill)
cat > /etc/logrotate.d/argus << 'EOF'
/opt/soc-testing/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        # Reload doesn't apply to plain files; no action needed
    endscript
}

/opt/soc-testing/logs/*.jsonl {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF

echo "[ARGUS] Created /etc/logrotate.d/argus"

# 7. Reload systemd, enable, and start
systemctl daemon-reload
systemctl enable argus-auth.service
systemctl enable argus-system.service
systemctl start argus-auth.service
systemctl start argus-system.service

sleep 2

echo ""
echo "[ARGUS] ========================================"
echo "[ARGUS] Installation complete!"
echo "[ARGUS] ========================================"
echo ""
echo "Service status:"
systemctl --no-pager status argus-auth.service | head -5
echo "---"
systemctl --no-pager status argus-system.service | head -5
echo ""
echo "Useful commands:"
echo "  sudo systemctl status argus-auth"
echo "  sudo systemctl status argus-system"
echo "  sudo journalctl -u argus-auth -f"
echo "  sudo tail -f /opt/soc-testing/logs/auth.out.log"
echo "  sudo tail -f /opt/soc-testing/logs/system.out.log"
echo ""
echo "To uninstall: sudo /opt/soc-testing/collectors/uninstall_service_linux.sh"
