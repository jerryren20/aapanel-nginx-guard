#!/bin/bash
set -euo pipefail

PLUGIN_DIR="/www/server/panel/plugin/nginx_guard"
DATA_DIR="/www/server/nginx_guard"
DISABLE="$DATA_DIR/bin/disable.sh"

if [ -x "$DISABLE" ]; then
    "$DISABLE"
fi

# Keep the transaction backups for recovery/audit. aaPanel removes the
# plugin code directory after this script returns.
if [ -d "$DATA_DIR" ]; then
    rm -rf "$DATA_DIR/config" "$DATA_DIR/rules" "$DATA_DIR/sites" "$DATA_DIR/cache" "$DATA_DIR/logs" "$DATA_DIR/runtime" "$DATA_DIR/generated" "$DATA_DIR/engine" "$DATA_DIR/bin"
fi
# Remove only the logrotate file created by this plugin; no system service is
# registered and no aaPanel or site-owned scheduler/configuration is touched.
rm -f /etc/logrotate.d/nginx_guard
echo "Nginx Guard removed; backups retained at $DATA_DIR/backup when present."
