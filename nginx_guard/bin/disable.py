#!/usr/bin/env python3
"""Emergency marker removal; safe to run without opening the aaPanel UI."""

from __future__ import print_function

import sys

PLUGIN_DIR = "/www/server/panel/plugin/nginx_guard"
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)

from lib.nginx import LocalNginxRunner, NginxConfigManager  # noqa: E402


def main():
    manager = NginxConfigManager(
        "/www/server/nginx/conf/nginx.conf",
        "/www/server/panel/vhost/nginx",
        "/www/server/nginx_guard",
        runner=LocalNginxRunner(
            "/www/server/nginx/sbin/nginx",
            "/www/server/nginx/conf/nginx.conf",
        ),
    )
    result = manager.remove()
    print("Nginx Guard disabled: %s" % result.get("backup", "backup created"))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("Nginx Guard emergency disable failed: %s" % exc, file=sys.stderr)
        raise
