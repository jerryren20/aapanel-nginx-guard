import tempfile
import unittest
from pathlib import Path

from nginx_guard.lib.nginx import (
    NginxCommandError,
    NginxConfigManager,
    detect_real_ip_module,
)


class RenderingTests(unittest.TestCase):
    def test_real_ip_module_detection(self):
        self.assertTrue(detect_real_ip_module("configure arguments: --with-http_realip_module"))
        self.assertFalse(detect_real_ip_module("configure arguments: --with-http_ssl_module"))

    def test_structured_log_contains_cfip_and_client_ip_without_unsupported_realip_variable(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = NginxConfigManager(Path(tmp) / "nginx.conf", Path(tmp) / "vhost", Path(tmp))
            fragment = manager._render_global(
                True,
                False,
                [],
                cloudflare={"enabled": True, "networks": ["104.16.0.0/13"]},
                real_ip_available=True,
            )
            self.assertIn('"cfip":"$ng_guard_cfip"', fragment)
            self.assertIn('"client_ip":"$remote_addr"', fragment)
            self.assertIn("geo $realip_remote_addr $ng_guard_cf_trusted", fragment)
            self.assertIn("map $ng_guard_cf_trusted $ng_guard_cfip", fragment)

            native_only = manager._render_global(
                True,
                False,
                [],
                cloudflare={"enabled": True, "networks": ["104.16.0.0/13"]},
                real_ip_available=False,
            )
            self.assertIn("map $remote_addr $ng_guard_cfip", native_only)
            self.assertNotIn("$realip_remote_addr", native_only)

    def test_native_site_fragment_contains_high_confidence_checks_and_streaming_guardrails(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = NginxConfigManager(Path(tmp) / "nginx.conf", Path(tmp) / "vhost", Path(tmp))
            fragment = manager._render_site(
                {
                    "id": "1",
                    "mode": "BLOCK",
                    "engine": "native",
                    "streaming_paths": ["/events", "/socket"],
                },
                lua_available=False,
            )
            self.assertIn("169\\.254\\.169\\.254", fragment)
            self.assertIn("\\.env", fragment)
            self.assertIn("WebSocket/SSE", fragment)
            self.assertIn("/events", fragment)
            self.assertNotIn("proxy_set_header", fragment)
            self.assertNotIn("proxy_pass", fragment)

    def test_native_site_fragment_emits_medium_rule_blocks_and_explicit_cc_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = NginxConfigManager(Path(tmp) / "nginx.conf", Path(tmp) / "vhost", Path(tmp))
            fragment = manager._render_site(
                {"id": "1", "mode": "BLOCK", "engine": "native"},
                lua_available=False,
            )
            self.assertIn("limit_req_status 429;", fragment)
            self.assertIn("NG2001", fragment)
            self.assertIn("NG2002", fragment)
            self.assertIn("NG2003", fragment)

    def test_lua_site_delegates_native_rule_decisions_to_access_phase(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = NginxConfigManager(Path(tmp) / "nginx.conf", Path(tmp) / "vhost", Path(tmp))
            fragment = manager._render_site(
                {"id": "1", "mode": "BLOCK", "engine": "auto"},
                lua_available=True,
            )
            self.assertIn("access_by_lua_file", fragment)
            self.assertNotIn("if ($ng_guard_site_request_rule_1", fragment)
            self.assertNotIn("if ($ng_guard_site_ua_rule_1", fragment)

    def test_interface_whitelist_uses_full_url_without_protocol_and_keeps_high_risk_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = NginxConfigManager(Path(tmp) / "nginx.conf", Path(tmp) / "vhost", Path(tmp))
            site = {
                "id": "1",
                "mode": "BLOCK",
                "engine": "native",
                "interface_whitelist": [
                    {"match": "exact", "url": "https://example.com/api/login"},
                    {"match": "prefix", "url": "http://example.com/api/upload/"},
                ],
            }
            global_fragment = manager._render_global(True, False, [site])
            site_fragment = manager._render_site(site, False)
            self.assertIn("ng_guard_interface_whitelist_1", global_fragment)
            self.assertIn("example\\.com", global_fragment)
            self.assertIn("ng_guard_ordinary_bypass_1", global_fragment)
            self.assertIn("\\.env", site_fragment)

    def test_structured_log_format_contains_attack_fields_and_429_mapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = NginxConfigManager(Path(tmp) / "nginx.conf", Path(tmp) / "vhost", Path(tmp))
            fragment = manager._render_global(True, False, [])
            self.assertIn('"attack_type"', fragment)
            self.assertIn('"rule_name"', fragment)
            self.assertIn('"action"', fragment)
            self.assertIn("ng_guard_safe_query", fragment)
            self.assertIn("[REDACTED]", fragment)
            self.assertIn("REJECTED NG3001", fragment)
            self.assertIn("limit_req_status", fragment)

    def test_lua_event_variable_is_declared_before_event_maps(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = NginxConfigManager(Path(tmp) / "nginx.conf", Path(tmp) / "vhost", Path(tmp))
            fragment = manager._render_global(True, True, [])
            self.assertLess(
                fragment.index("map $host $ng_guard_lua_rule_id"),
                fragment.index("map \"$ng_guard_rate_rule_id:$ng_guard_lua_rule_id:$ng_guard_native_rule_id\""),
            )

    def test_disabled_engine_does_not_emit_lua_directives(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = NginxConfigManager(Path(tmp) / "nginx.conf", Path(tmp) / "vhost", Path(tmp))
            fragment = manager._render_site({"id": "1", "mode": "MONITOR", "engine": "lua"}, lua_available=False)
            self.assertNotIn("access_by_lua", fragment)

    def test_cloudflare_wiring_is_explicit_and_uses_configured_networks(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = NginxConfigManager(Path(tmp) / "nginx.conf", Path(tmp) / "vhost", Path(tmp))
            fragment = manager._render_global(
                global_enabled=True,
                lua_available=False,
                sites=[],
                cloudflare={"enabled": True, "networks": ["104.16.0.0/13"]},
            )
            self.assertIn("set_real_ip_from 104.16.0.0/13;", fragment)
            self.assertIn("real_ip_header CF-Connecting-IP;", fragment)

    def test_native_map_regex_prefix_is_attached_to_the_pattern(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = NginxConfigManager(Path(tmp) / "nginx.conf", Path(tmp) / "vhost", Path(tmp))
            fragment = manager._render_global(global_enabled=True, lua_available=False, sites=[])

            self.assertIn('    "~*(?:^|/)', fragment)
            self.assertNotIn('    ~* "', fragment)

    def test_site_map_regex_entries_are_single_quoted_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = NginxConfigManager(Path(tmp) / "nginx.conf", Path(tmp) / "vhost", Path(tmp))
            fragment = manager._render_global(
                global_enabled=True,
                lua_available=False,
                sites=[
                    {
                        "id": "1",
                        "mode": "BLOCK",
                        "rate_paths": [{"path": "/wp-login.php", "rate": 2, "burst": 5}],
                        "custom_rules": [
                            {"id": "C1", "match": "uri_contains", "pattern": "/admin", "action": "block"},
                        ],
                    },
                ],
            )

            self.assertIn('    "~*\\.(?:css|js|mjs|png|jpg|jpeg|webp|svg|ico|woff|woff2|ttf|map)$" 0;', fragment)
            self.assertIn('    "~*^/wp\\-login\\.php(?:/|$)" $ng_guard_rate_key_1;', fragment)
            self.assertIn('    "~*/admin" 1;', fragment)
            self.assertFalse(
                any(line.strip().startswith("~*") for line in fragment.splitlines())
            )

    def test_safe_custom_uri_and_method_rules_are_compiled_without_raw_directive_injection(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = NginxConfigManager(Path(tmp) / "nginx.conf", Path(tmp) / "vhost", Path(tmp))
            fragment = manager._render_site(
                {
                    "id": "1",
                    "mode": "BLOCK",
                    "engine": "native",
                    "custom_rules": [
                        {"id": "C1", "match": "uri_contains", "pattern": "/admin", "action": "block"},
                        {"id": "C2", "match": "method", "pattern": "TRACE", "action": "429"},
                    ],
                },
                lua_available=False,
            )
            self.assertNotIn("proxy_pass", fragment)
            global_fragment = manager._render_global(
                True,
                False,
                [{
                    "id": "1",
                    "mode": "BLOCK",
                    "custom_rules": [
                        {"id": "C1", "match": "uri_contains", "pattern": "/admin", "action": "block"},
                        {"id": "C2", "match": "method", "pattern": "TRACE", "action": "429"},
                    ],
                }],
            )
            self.assertIn("/admin", global_fragment)
            self.assertIn("$request_method", global_fragment)

    def test_lua_snapshot_uses_safe_table_serializer_for_site_runtime_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = NginxConfigManager(Path(tmp) / "nginx.conf", Path(tmp) / "vhost", Path(tmp))
            snapshot = manager._render_snapshot(
                [
                    {
                        "id": "1",
                        "mode": "BLOCK",
                        "rate_limit": 10,
                        "auto_ban": {"enabled": True, "threshold": 20, "window": 10, "duration": 600},
                        "custom_rules": [{"id": "C1", "match": "uri_contains", "pattern": "/admin", "action": "block"}],
                    }
                ],
                version=42,
            )
            self.assertIn("version=42", snapshot)
            self.assertIn("custom_rules", snapshot)
            self.assertNotIn("dofile", snapshot)
            self.assertIn("interface_whitelist", snapshot)
            self.assertIn("body_inspection", snapshot)

    def test_builtin_rule_overrides_change_native_block_directives(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = NginxConfigManager(Path(tmp) / "nginx.conf", Path(tmp) / "vhost", Path(tmp))
            fragment = manager._render_site(
                {
                    "id": "1",
                    "mode": "BLOCK",
                    "engine": "native",
                    "rule_overrides": {"NG1001": {"enabled": False}},
                },
                lua_available=False,
            )
            self.assertNotIn("Sensitive file", fragment)
            self.assertNotIn("docker-compose", fragment)

    def test_url_rate_path_gets_its_own_limit_zone(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = NginxConfigManager(Path(tmp) / "nginx.conf", Path(tmp) / "vhost", Path(tmp))
            site = {
                "id": "1",
                "mode": "BLOCK",
                "engine": "native",
                "rate_paths": [{"path": "/wp-login.php", "rate": 2, "burst": 5}],
            }
            global_fragment = manager._render_global(True, False, [site])
            site_fragment = manager._render_site(site, False)
            self.assertIn("ng_guard_url_key_1_0", global_fragment)
            self.assertIn("rate=2r/s", global_fragment)
            self.assertIn("limit_req zone=ng_guard_url_1_0", site_fragment)

    def test_whitelisted_ip_has_no_native_rate_key_for_that_site(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = NginxConfigManager(Path(tmp) / "nginx.conf", Path(tmp) / "vhost", Path(tmp))
            site = {"id": "1", "mode": "BLOCK", "engine": "native", "whitelist": ["10.0.0.8"]}
            global_fragment = manager._render_global(True, False, [site])
            site_fragment = manager._render_site(site, False)
            self.assertIn("map \"$ng_guard_ordinary_bypass_1:$ng_guard_dynamic\"", global_fragment)
            self.assertIn('"0:1" $binary_remote_addr;', global_fragment)
            self.assertIn("limit_req zone=ng_guard_rate_site_1", site_fragment)

    def test_streaming_path_rejects_config_control_characters(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = NginxConfigManager(Path(tmp) / "nginx.conf", Path(tmp) / "vhost", Path(tmp))
            with self.assertRaises(NginxCommandError):
                manager._render_site(
                    {"id": "1", "mode": "BLOCK", "streaming_paths": ["/events\n# injected"]},
                    lua_available=False,
                )

    def test_monitor_can_omit_dry_run_on_old_nginx_without_becoming_a_limiter(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = NginxConfigManager(Path(tmp) / "nginx.conf", Path(tmp) / "vhost", Path(tmp))
            fragment = manager._render_site(
                {"id": "1", "mode": "MONITOR", "engine": "native"},
                lua_available=False,
                limit_req_dry_run=False,
            )
            self.assertNotIn("limit_req zone=ng_guard_rate_site_1", fragment)
            self.assertNotIn("limit_req_dry_run on;", fragment)


if __name__ == "__main__":
    unittest.main()
