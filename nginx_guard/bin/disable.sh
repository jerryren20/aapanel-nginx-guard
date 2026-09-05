#!/bin/bash
set -euo pipefail

PLUGIN_DIR="/www/server/panel/plugin/nginx_guard"
PYTHON="/www/server/panel/pyenv/bin/python"
if [ ! -x "$PYTHON" ]; then
    PYTHON="/usr/bin/python3"
fi
exec "$PYTHON" "$PLUGIN_DIR/bin/disable.py"
