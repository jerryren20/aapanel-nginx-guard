import json
import gzip
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import nginx_guard.nginx_guard_main as controller


class ControllerTests(unittest.TestCase):
    def test_get_logs_filters_before_limit_and_normalizes_legacy_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = root / "logs"
            logs.mkdir()
            rows = [
                {"time": "2026-09-03T10:00:00+08:00", "remote_addr": "198.51.100.1", "rule_id": "NG2001", "action": "MONITOR", "status": 403},
                {"time": "2026-09-03T10:00:01+08:00", "remote_addr": "198.51.100.2", "rule_id": "NG1001", "status": 403},
                {"time": "2026-09-03T10:00:02+08:00", "remote_addr": "198.51.100.3", "action": "BLOCK", "status": 403},
            ]
            (logs / "events-site-1.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
            )
            with patch.object(controller, "DATA_ROOT", root):
                result = controller.nginx_guard_main().get_logs(
                    {"site_id": "1", "blocked_only": "true", "limit": "1"}
                )

            self.assertTrue(result["status"])
            self.assertEqual(len(result["data"]), 1)
            self.assertEqual(result["data"][0]["remote_addr"], "198.51.100.3")
            self.assertEqual(result["data"][0]["client_ip"], "198.51.100.3")
            self.assertEqual(result["data"][0]["cfip"], "")
            self.assertTrue(result["data"][0]["blocked"])

    def test_get_logs_reads_gzip_rotation_and_keeps_latest_blocked_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = root / "logs"
            logs.mkdir()
            rotated = logs / "events-site-1.jsonl.20260904120000.gz"
            with gzip.open(rotated, "wt", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        {
                            "time": "2026-09-05T11:30:00+00:00",
                            "remote_addr": "198.51.100.1",
                            "uri": "/rotated-new",
                            "action": "BLOCK",
                            "status": 403,
                        }
                    )
                    + "\n"
                )
            (logs / "events-site-1.jsonl").write_text(
                "".join(
                    json.dumps(row) + "\n"
                    for row in (
                        {
                            "time": "2026-09-05T11:00:00+00:00",
                            "remote_addr": "198.51.100.2",
                            "uri": "/new",
                            "action": "BLOCK",
                            "status": 403,
                        },
                        {
                            "time": "2026-09-05T11:01:00+00:00",
                            "remote_addr": "198.51.100.3",
                            "uri": "/monitor",
                            "action": "MONITOR",
                            "status": 403,
                        },
                    )
                ),
                encoding="utf-8",
            )
            with patch.object(controller, "DATA_ROOT", root):
                result = controller.nginx_guard_main().get_logs(
                    {"site_id": "1", "blocked_only": "true", "limit": "2"}
                )

            self.assertTrue(result["status"])
            self.assertEqual([row["uri"] for row in result["data"]], ["/rotated-new", "/new"])

    def test_metrics_include_compressed_rotated_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = root / "logs"
            logs.mkdir()
            row = {
                "time": datetime.now(timezone.utc).isoformat(),
                "site_id": "1",
                "rule_id": "NG1001",
                "status": 403,
                "action": "BLOCK",
            }
            with gzip.open(logs / "events-site-1.jsonl.20260904120000.gz", "wt", encoding="utf-8") as handle:
                handle.write(json.dumps(row) + "\n")
            with patch.object(controller, "DATA_ROOT", root):
                result = controller.nginx_guard_main().get_metrics({})

            self.assertTrue(result["status"])
            self.assertEqual(result["data"]["total"], 1)
            self.assertEqual(result["data"]["blocked"], 1)

    def test_log_analysis_and_csv_export_are_read_only_and_include_rotated_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = root / "logs"
            logs.mkdir()
            now = datetime.now(timezone.utc)
            rows = [
                {
                    "time": (now - timedelta(minutes=2)).isoformat(),
                    "remote_addr": "198.51.100.7",
                    "uri": "/login",
                    "method": "POST",
                    "action": "BLOCK",
                    "status": 403,
                    "rule_id": "NG2001",
                },
                {
                    "time": (now - timedelta(minutes=1)).isoformat(),
                    "remote_addr": "198.51.100.8",
                    "uri": "/login",
                    "method": "POST",
                    "action": "MONITOR",
                    "status": 200,
                },
            ]
            content = "".join(json.dumps(row) + "\n" for row in rows)
            (logs / "events-site-1.jsonl").write_text(content, encoding="utf-8")
            (logs / "events-site-1.jsonl.20260904").write_text(
                json.dumps(
                    {
                        "time": (now - timedelta(hours=1)).isoformat(),
                        "remote_addr": "198.51.100.9",
                        "uri": "/login",
                        "method": "POST",
                        "action": "BLOCK",
                        "status": 403,
                        "rule_id": "NG2001",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            with patch.object(controller, "DATA_ROOT", root):
                instance = controller.nginx_guard_main()
                result = instance.get_log_analysis({"site_id": "1", "window": "24h"})
                exported = instance.export_log_analysis(
                    {"site_id": "1", "window": "24h", "blocked_only": "true"}
                )

            self.assertTrue(result["status"])
            self.assertEqual(result["data"]["total"], 3)
            self.assertEqual(result["data"]["blocked"], 2)
            self.assertTrue(exported["status"])
            self.assertTrue(exported["data"]["content"].startswith("\ufeff"))
            self.assertEqual(exported["data"]["filename"], "nginx_guard_analysis_site-1_24h.csv")

    def test_save_site_policy_accepts_per_path_rate_units_and_old_shape_defaults_to_seconds(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(controller, "DATA_ROOT", Path(tmp)):
                instance = controller.nginx_guard_main()
                result = instance.save_site_policy(
                    {
                        "site_id": "1",
                        "policy": {
                            "mode": "BLOCK",
                            "rate_paths": [
                                {"path": "/login", "rate": 10, "unit": "m", "burst": 3},
                                {"path": "/legacy", "rate": 2, "burst": 5},
                            ],
                        },
                    }
                )
                saved = instance.store.load_site_policy("1")

            self.assertTrue(result["status"])
            self.assertEqual(saved["rate_paths"][0]["unit"], "m")
            self.assertEqual(saved["rate_paths"][1]["unit"], "s")

    def test_save_site_policy_deduplicates_rate_paths_using_last_definition(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(controller, "DATA_ROOT", Path(tmp)):
                instance = controller.nginx_guard_main()
                result = instance.save_site_policy(
                    {
                        "site_id": "1",
                        "policy": {
                            "mode": "BLOCK",
                            "rate_paths": [
                                {"path": "/Login/", "rate": 10, "unit": "m", "burst": 3},
                                {"path": "/login", "rate": 20, "unit": "s", "burst": 5},
                            ],
                        },
                    }
                )

            self.assertTrue(result["status"])
            self.assertEqual(result["data"]["rate_paths"], [{"path": "/login", "rate": 20, "unit": "s", "burst": 5}])

    def test_ip_list_remove_is_an_exact_persistent_operation(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(controller, "DATA_ROOT", Path(tmp)):
                instance = controller.nginx_guard_main()
                instance.store.save_site_policy(
                    "1",
                    {
                        "mode": "BLOCK",
                        "blacklist": ["192.0.2.1", "192.0.2.10", "198.51.100.0/24"],
                        "whitelist": ["203.0.113.8"],
                    },
                )
                result = instance.mutate_ip_list(
                    {"site_id": "1", "list_name": "blacklist", "operation": "remove", "address": "192.0.2.1"}
                )
                saved = instance.store.load_site_policy("1")

            self.assertTrue(result["status"])
            self.assertEqual(saved["blacklist"], ["192.0.2.10", "198.51.100.0/24"])

    def test_lookup_cloudflare_ip_uses_effective_config_without_reload(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(controller, "DATA_ROOT", Path(tmp)):
                instance = controller.nginx_guard_main()
                saved = instance.save_cloudflare(
                    {"enabled": "true", "manual_networks": json.dumps(["192.0.2.0/24"])}
                )
                self.assertTrue(saved["status"])
                result = instance.lookup_cloudflare_ip({"address": "192.0.2.8"})

            self.assertTrue(result["status"])
            self.assertEqual(result["data"]["matches"][0]["network"], "192.0.2.0/24")
            self.assertEqual(result["data"]["matches"][0]["sources"], ["manual"])

    def test_lookup_cloudflare_ip_returns_chinese_error_for_invalid_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(controller, "DATA_ROOT", Path(tmp)):
                result = controller.nginx_guard_main().lookup_cloudflare_ip({"address": "192.0.2.0/24"})
        self.assertFalse(result["status"])
        self.assertIn("请输入有效的 IPv4 或 IPv6 地址", result["msg"])

    def test_save_cloudflare_does_not_reload_nginx(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(controller, "DATA_ROOT", Path(tmp)):
                instance = controller.nginx_guard_main()
                result = instance.save_cloudflare({"enabled": "true"})
                self.assertTrue(result["status"])
                self.assertTrue(instance.store.load_desired()["cloudflare"]["enabled"])

    def test_cloudflare_manual_networks_survive_refresh_and_are_deduplicated(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(controller, "DATA_ROOT", Path(tmp)):
                instance = controller.nginx_guard_main()
                saved = instance.save_cloudflare(
                    {
                        "enabled": "true",
                        "manual_networks": json.dumps(["192.0.2.0/24", "192.0.2.0/24"]),
                    }
                )
                self.assertTrue(saved["status"])
                with patch.object(controller, "fetch_official_networks", return_value=["198.51.100.0/24"]):
                    refreshed = instance.refresh_cloudflare({})
                self.assertTrue(refreshed["status"])
                data = instance.store.load_desired()["cloudflare"]
                self.assertEqual(data["manual_networks"], ["192.0.2.0/24"])
                self.assertIn("198.51.100.0/24", data["official_networks"])
                self.assertIn("192.0.2.0/24", data["networks"])

    def test_invalid_custom_rule_returns_api_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(controller, "DATA_ROOT", Path(tmp)):
                instance = controller.nginx_guard_main()
                result = instance.save_custom_rule({"rule": json.dumps({"match": "uri_regex", "pattern": "["})})
                self.assertFalse(result["status"])

    def test_site_policy_accepts_full_url_interface_whitelist(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(controller, "DATA_ROOT", Path(tmp)):
                instance = controller.nginx_guard_main()
                result = instance.save_site_policy(
                    {
                        "site_id": "1",
                        "policy": {
                            "mode": "BLOCK",
                            "interface_whitelist": [
                                {"match": "exact", "url": "https://example.com/api/login"},
                                {"match": "prefix", "url": "http://example.com/api/upload/"},
                            ],
                        },
                    }
                )
                self.assertTrue(result["status"])
                saved = instance.store.load_site_policy("1")
                self.assertEqual(len(saved["interface_whitelist"]), 2)
                self.assertEqual(saved["interface_whitelist"][0]["host"], "example.com")

    def test_path_like_site_id_is_returned_as_api_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(controller, "DATA_ROOT", Path(tmp)):
                instance = controller.nginx_guard_main()
                result = instance.get_site_policy({"site_id": "../../etc/passwd"})
                self.assertFalse(result["status"])

    def test_lua_preference_degrades_to_native_when_module_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(controller, "DATA_ROOT", Path(tmp)), \
                 patch.object(controller, "NGINX_CONF", Path(tmp) / "nginx.conf"), \
                 patch.object(controller, "VHOST_DIR", Path(tmp) / "vhost"), \
                 patch.object(controller, "NGINX_BIN", Path(tmp) / "nginx"):
                (Path(tmp) / "nginx.conf").write_text("http {\n}\n", encoding="utf-8")
                (Path(tmp) / "vhost").mkdir()
                (Path(tmp) / "vhost" / "1.conf").write_text(
                    "server { server_name 1; }\n", encoding="utf-8"
                )
                instance = controller.nginx_guard_main()
                instance.store.save_desired(
                    {
                        "schema_version": 1,
                        "engine_enabled": True,
                        "preferred_engine": "lua",
                        "sites": {"1": {"mode": "MONITOR", "engine": "lua"}},
                    }
                )
                class FakeManager:
                    def apply(self, **kwargs):
                        self.kwargs = kwargs
                        return {"ok": True}

                fake_manager = FakeManager()
                with patch.object(instance, "_nginx_v_output", return_value="nginx without lua"):
                    with patch.object(instance, "_manager", return_value=fake_manager):
                        result = instance.apply_config({})
                self.assertTrue(result["status"])
                self.assertIn("Native", result["msg"])

    def test_rule_override_is_validated_and_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(controller, "DATA_ROOT", Path(tmp)):
                instance = controller.nginx_guard_main()
                result = instance.save_rule({"rule_id": "NG1001", "enabled": "false", "action": "monitor"})
                self.assertTrue(result["status"])
                rules = instance.get_rules({})["data"]["builtin"]
                rule = next(item for item in rules if item["id"] == "NG1001")
                self.assertFalse(rule["enabled"])

    def test_apply_passes_global_rule_overrides_to_each_site(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(controller, "DATA_ROOT", Path(tmp)):
                instance = controller.nginx_guard_main()
                instance.store.save_desired(
                    {
                        "schema_version": 1,
                        "engine_enabled": True,
                        "preferred_engine": "native",
                        "rule_overrides": {"NG2001": {"enabled": True, "action": "monitor"}},
                        "sites": {"1": {"mode": "BLOCK", "engine": "native"}},
                    }
                )

                class FakeManager:
                    def apply(self, **kwargs):
                        self.kwargs = kwargs
                        return {"ok": True}

                manager = FakeManager()
                with patch.object(instance, "_manager", return_value=manager), \
                     patch.object(instance, "_nginx_v_output", return_value="nginx/1.0"):
                    result = instance._apply_config_unchecked()

                self.assertTrue(result["status"])
                self.assertEqual(
                    manager.kwargs["sites"][0]["rule_overrides"]["NG2001"]["action"],
                    "monitor",
                )

    def test_get_metrics_exposes_real_hourly_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = root / "logs"
            logs.mkdir()
            (logs / "events-site-1.jsonl").write_text(
                json.dumps(
                    {
                        "time": datetime.now(timezone.utc).isoformat(),
                        "rule_id": "NG1001",
                        "status": 403,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            with patch.object(controller, "DATA_ROOT", root):
                result = controller.nginx_guard_main().get_metrics({})

            self.assertTrue(result["status"])
            self.assertEqual(len(result["data"]["hourly"]), 24)
            self.assertEqual(sum(item["requests"] for item in result["data"]["hourly"]), 1)
            self.assertEqual(sum(item["attacks"] for item in result["data"]["hourly"]), 1)

    def test_get_backups_lists_only_three_most_recent_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            backup_root = Path(tmp) / "backup"
            for name in (
                "20260902050000-a",
                "20260902040000-b",
                "20260902030000-c",
                "20260902020000-d",
                "20260902010000-e",
            ):
                (backup_root / name).mkdir(parents=True)
            with patch.object(controller, "DATA_ROOT", Path(tmp)):
                result = controller.nginx_guard_main().get_backups({})

            self.assertTrue(result["status"])
            self.assertEqual([item["name"] for item in result["data"]], [
                "20260902050000-a",
                "20260902040000-b",
                "20260902030000-c",
            ])


if __name__ == "__main__":
    unittest.main()
