#!/bin/bash
# install_service_linux.sh
# Installs VALENS.AI Linux collectors as systemd services.
# Run with: sudo ./install_service_linux.sh

set -e

INSTALL_DIR="/opt/soc-testing/collectors"
LOG_DIR="/opt/soc-testing/logs"
SERVICE_USER="root"

echo "[VALENS.AI] Installing Linux collectors..."

# 1. Create directories
mkdir -p "$INSTALL_DIR"
mkdir -p "$LOG_DIR"

# 2. Copy collector files (assumes they're in current directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$SCRIPT_DIR/collector.py" ]; then
    cp "$SCRIPT_DIR/collector.py" "$INSTALL_DIR/"
    echo "[VALENS.AI] Copied collector.py"
else
    echo "[VALENS.AI] ERROR: collector.py not found in $SCRIPT_DIR"
    exit 1
fi

if [ -f "$SCRIPT_DIR/firewall_collector.py" ]; then
    cp "$SCRIPT_DIR/firewall_collector.py" "$INSTALL_DIR/"
    echo "[VALENS.AI] Copied firewall_collector.py"
else
    echo "[VALENS.AI] WARNING: firewall_collector.py not found, skipping"
fi

if [ -f "$SCRIPT_DIR/risk_scoring.py" ]; then
    cp "$SCRIPT_DIR/risk_scoring.py" "$INSTALL_DIR/"
    echo "[VALENS.AI] Copied risk_scoring.py"
fi

# 3. Install dependencies (assumes python3 already installed)
pip3 install --quiet --break-system-packages watchdog || \
pip3 install --quiet watchdog || \
echo "[VALENS.AI] WARNING: pip install failed, you may need to install dependencies manually"

# 4. Create auth collector service
cat > /etc/systemd/system/valens-auth.service << 'EOF'
[Unit]
Description=VALENS.AI Linux Auth Log Collector
After=network.target
Documentation=https://github.com/your-org/valens-ai

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

echo "[VALENS.AI] Created /etc/systemd/system/valens-auth.service"

# 5. Create system/firewall collector service
cat > /etc/systemd/system/valens-system.service << 'EOF'
[Unit]
Description=VALENS.AI Linux System & Firewall Collector
After=network.target
Documentation=https://github.com/your-org/valens-ai

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

echo "[VALENS.AI] Created /etc/systemd/system/valens-system.service"

# 6. Create logrotate config (prevent disk fill)
cat > /etc/logrotate.d/valens << 'EOF'
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

echo "[VALENS.AI] Created /etc/logrotate.d/valens"

# 7. Reload systemd, enable, and start
systemctl daemon-reload
systemctl enable valens-auth.service
systemctl enable valens-system.service
systemctl start valens-auth.service
systemctl start valens-system.service

sleep 2

echo ""
echo "[VALENS.AI] ========================================"
echo "[VALENS.AI] Installation complete!"
echo "[VALENS.AI] ========================================"
echo ""
echo "Service status:"
systemctl --no-pager status valens-auth.service | head -5
echo "---"
systemctl --no-pager status valens-system.service | head -5
echo ""
echo "Useful commands:"
echo "  sudo systemctl status valens-auth"
echo "  sudo systemctl status valens-system"
echo "  sudo journalctl -u valens-auth -f"
echo "  sudo tail -f /opt/soc-testing/logs/auth.out.log"
echo "  sudo tail -f /opt/soc-testing/logs/system.out.log"
echo ""
echo "To uninstall: sudo /opt/soc-testing/collectors/uninstall_service_linux.sh"
