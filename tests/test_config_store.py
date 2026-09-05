import json
import tempfile
import unittest
from pathlib import Path

from nginx_guard.lib.config_store import ConfigStore


class ConfigStoreTests(unittest.TestCase):
    def test_save_and_load_desired_configuration_atomically(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ConfigStore(Path(tmp))
            desired = {
                "schema_version": 1,
                "engine_enabled": True,
                "sites": {"123": {"mode": "MONITOR", "engine": "auto"}},
            }

            store.save_desired(desired)

            loaded = store.load_desired()
            self.assertEqual(loaded["schema_version"], 2)
            self.assertTrue(loaded["engine_enabled"])
            self.assertEqual(loaded["sites"], desired["sites"])
            self.assertIn("cloudflare", loaded)
            self.assertIn("log_rotation", loaded)
            self.assertFalse((Path(tmp) / "config" / "desired.json.tmp").exists())
            self.assertTrue((Path(tmp) / "config" / "desired.json").exists())

    def test_corrupt_json_returns_safe_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = ConfigStore(root)
            (root / "config").mkdir(parents=True, exist_ok=True)
            (root / "config" / "desired.json").write_text("{broken", encoding="utf-8")

            data = store.load_desired()

            self.assertEqual(data["schema_version"], 2)
            self.assertFalse(data["engine_enabled"])
            self.assertEqual(data["sites"], {})

    def test_legacy_cloudflare_and_log_settings_are_migrated_without_loss(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = ConfigStore(root)
            (root / "config").mkdir(parents=True, exist_ok=True)
            (root / "config" / "desired.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "cloudflare": {"enabled": True, "networks": ["192.0.2.0/24"]},
                        "log_rotation": {"max_bytes": 99},
                    }
                ),
                encoding="utf-8",
            )
            data = store.load_desired()
            self.assertEqual(data["schema_version"], 2)
            self.assertIn("192.0.2.0/24", data["cloudflare"]["networks"])
            self.assertIn("192.0.2.0/24", data["cloudflare"]["manual_networks"])
            self.assertEqual(data["log_rotation"]["max_bytes"], 1024)

    def test_malformed_log_settings_fall_back_to_safe_bounds(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = ConfigStore(root)
            (root / "config" / "desired.json").write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "log_rotation": {
                            "max_bytes": 99 * 1024 * 1024,
                            "keep_days": None,
                            "max_files": object(),
                            "max_total_bytes": 999 * 1024 * 1024,
                        },
                    },
                    default=str,
                ),
                encoding="utf-8",
            )

            data = store.load_desired()

            self.assertEqual(data["log_rotation"]["max_bytes"], 20 * 1024 * 1024)
            self.assertEqual(data["log_rotation"]["keep_days"], 7)
            self.assertEqual(data["log_rotation"]["max_files"], 100)
            self.assertEqual(data["log_rotation"]["max_total_bytes"], 100 * 1024 * 1024)

    def test_site_policy_is_not_written_outside_data_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ConfigStore(Path(tmp))
            with self.assertRaises(ValueError):
                store.save_site_policy("../../etc/passwd", {"mode": "BLOCK"})


if __name__ == "__main__":
    unittest.main()
