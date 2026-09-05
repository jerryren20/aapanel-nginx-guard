"""Compatibility entry point retained for aaPanel installations that expect a dash module."""

try:
    from .nginx_guard_main import nginx_guard_main
except ImportError:
    from nginx_guard_main import nginx_guard_main
