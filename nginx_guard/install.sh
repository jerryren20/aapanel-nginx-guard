#!/bin/bash
set -euo pipefail

PLUGIN_DIR="/www/server/panel/plugin/nginx_guard"
DATA_DIR="/www/server/nginx_guard"

mkdir -p "$DATA_DIR"/{config/sites,rules,sites,cache,logs,backup,runtime,generated,engine,bin}
cp -f "$PLUGIN_DIR"/engine/*.lua "$DATA_DIR/engine/"
cp -f "$PLUGIN_DIR"/rules/*.json "$DATA_DIR/rules/"
cp -f "$PLUGIN_DIR"/bin/disable.py "$DATA_DIR/bin/"
cp -f "$PLUGIN_DIR"/bin/disable.sh "$DATA_DIR/bin/"
chmod 0750 "$DATA_DIR/bin/disable.sh"
chmod 0640 "$DATA_DIR/bin/"*.py
chmod 0644 "$DATA_DIR/engine/"*.lua

if [ ! -f "$DATA_DIR/config/desired.json" ]; then
    printf '%s\n' '{"schema_version":2,"engine_enabled":false,"preferred_engine":"auto","runtime_failure_policy":"open","sites":{},"custom_rules":[],"rule_overrides":{},"cloudflare":{"enabled":false,"official_networks":["173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20","197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13","104.24.0.0/14","172.64.0.0/13","131.0.72.0/22","2400:cb00::/32","2606:4700::/32","2803:f800::/32","2405:b500::/32","2405:8100::/32","2a06:98c0::/29","2c0f:f248::/32"],"manual_networks":[],"networks":[],"updated_at":0},"log_rotation":{"max_bytes":20971520,"keep_days":7,"max_files":100,"max_total_bytes":104857600}}' > "$DATA_DIR/config/desired.json"
fi
if [ ! -f "$DATA_DIR/runtime/version" ]; then
    printf '0\n' > "$DATA_DIR/runtime/version"
fi

if command -v chown >/dev/null 2>&1 && id root >/dev/null 2>&1; then
    chown -R root:root "$DATA_DIR"
fi
chmod 0755 "$DATA_DIR" "$DATA_DIR/runtime" "$DATA_DIR/generated" "$DATA_DIR/engine"
chmod 0750 "$DATA_DIR/config" "$DATA_DIR/backup"
chmod 0770 "$DATA_DIR/logs"
chmod 0640 "$DATA_DIR/config/desired.json"
chmod 0644 "$DATA_DIR/runtime/version"
if [ -f "$DATA_DIR/runtime/snapshot.lua" ]; then
    chmod 0644 "$DATA_DIR/runtime/snapshot.lua"
fi
if id www >/dev/null 2>&1; then
    chown www:www "$DATA_DIR/logs"
    find "$DATA_DIR/logs" -maxdepth 1 -type f -name 'events-site-*.jsonl*' -exec chown www:www {} \;
    find "$DATA_DIR/logs" -maxdepth 1 -type f -name 'events-site-*.jsonl*' -exec chmod 0640 {} \;
fi

# Use the host's existing logrotate scheduler when available; this only
# rotates Nginx Guard's own JSONL files and never creates a daemon/service.
if [ -d /etc/logrotate.d ] && [ -w /etc/logrotate.d ]; then
    cat > /etc/logrotate.d/nginx_guard <<'EOF'
/www/server/nginx_guard/logs/events-site-*.jsonl {
    size 20M
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
EOF
    chmod 0644 /etc/logrotate.d/nginx_guard
fi

# Installation is intentionally inert: no Nginx file is touched, no external
# service is registered, and the engine remains disabled until the user presses
# Apply in the aaPanel UI.
echo "Nginx Guard 1.0.13 installed; engine disabled."
