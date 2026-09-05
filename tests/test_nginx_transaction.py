import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nginx_guard.lib import nginx as nginx_module
from nginx_guard.lib.nginx import (
    NginxConfigManager,
    NginxCommandError,
    detect_limit_req_dry_run,
    detect_lua_module,
)


class FakeRunner:
    def __init__(self, test_ok=True, reload_ok=True):
        self.test_ok = test_ok
        self.reload_ok = reload_ok
        self.calls = []

    def test_config(self):
        self.calls.append("test")
        if not self.test_ok:
            raise NginxCommandError("synthetic nginx -t failure")
        return "syntax is ok"

    def reload(self):
        self.calls.append("reload")
        if not self.reload_ok:
            raise NginxCommandError("synthetic reload failure")
        return "signal process started"


class SequencedRunner:
    def __init__(self, tests, reloads):
        self.tests = list(tests)
        self.reloads = list(reloads)
        self.calls = []

    def test_config(self):
        self.calls.append("test")
        ok = self.tests.pop(0) if self.tests else True
        if not ok:
            raise NginxCommandError("synthetic nginx -t failure")
        return "syntax is ok"

    def reload(self):
        self.calls.append("reload")
        ok = self.reloads.pop(0) if self.reloads else True
        if not ok:
            raise NginxCommandError("synthetic reload failure")
        return "signal process started"


class NginxTransactionTests(unittest.TestCase):
    def _manager(self, root, runner):
        nginx_conf = Path(root) / "nginx.conf"
        vhost_dir = Path(root) / "vhost"
        vhost_dir.mkdir()
        nginx_conf.write_text(
            "http {\n    include /etc/nginx/mime.types;\n}\n",
            encoding="utf-8",
        )
        (vhost_dir / "example.com.conf").write_text(
            "server {\n    listen 80;\n    server_name example.com;\n    location / { proxy_pass http://127.0.0.1:3000; }\n}\n",
            encoding="utf-8",
        )
        return NginxConfigManager(
            nginx_conf=nginx_conf,
            vhost_dir=vhost_dir,
            data_root=Path(root) / "guard",
            runner=runner,
        )

    def test_apply_inserts_owned_markers_and_reloads_only_after_test(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = FakeRunner()
            manager = self._manager(tmp, runner)

            result = manager.apply(
                global_enabled=True,
                sites=[{"id": "123", "name": "example.com", "mode": "MONITOR", "engine": "native"}],
            )

            self.assertTrue(result["ok"])
            self.assertEqual(runner.calls, ["test", "reload"])
            self.assertIn("NGINX_GUARD_GLOBAL", Path(tmp, "nginx.conf").read_text())
            self.assertIn("NGINX_GUARD_SITE:123", Path(tmp, "vhost", "example.com.conf").read_text())
            self.assertTrue((Path(tmp) / "guard" / "backup").exists())

    def test_apply_accepts_aapanel_split_line_block_syntax(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            conf = root / "nginx.conf"
            vhosts = root / "vhost"
            vhosts.mkdir()
            conf.write_text(
                "events\n{\n}\nhttp\n{\n}\n",
                encoding="utf-8",
            )
            vhost = vhosts / "example.com.conf"
            vhost.write_text(
                "server\n{\n    server_name example.com;\n}\n",
                encoding="utf-8",
            )
            manager = NginxConfigManager(conf, vhosts, root / "guard", runner=FakeRunner())

            result = manager.apply(
                global_enabled=True,
                sites=[{"id": "123", "name": "example.com", "mode": "MONITOR", "engine": "native"}],
            )

            self.assertTrue(result["ok"])
            self.assertIn("NGINX_GUARD_GLOBAL", conf.read_text(encoding="utf-8"))
            self.assertIn("NGINX_GUARD_SITE:123", vhost.read_text(encoding="utf-8"))

    def test_find_vhost_accepts_aapanel_node_prefixed_filename(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vhosts = root / "vhost"
            vhosts.mkdir()
            node_vhost = vhosts / "node_chat2response.conf"
            node_vhost.write_text(
                "server {\n    server_name chat2response;\n}\n",
                encoding="utf-8",
            )
            manager = NginxConfigManager(
                root / "nginx.conf",
                vhosts,
                root / "guard",
                runner=FakeRunner(),
            )

            site_id, resolved = manager._find_vhost(
                {"id": "7", "name": "chat2response"}
            )

            self.assertEqual(site_id, "7")
            self.assertEqual(resolved, node_vhost)

    def test_global_marker_is_inserted_before_existing_vhost_includes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            conf = root / "nginx.conf"
            vhosts = root / "vhost"
            vhosts.mkdir()
            conf.write_text(
                "http {\n"
                "    include /www/server/panel/vhost/nginx/*.conf;\n"
                "}\n",
                encoding="utf-8",
            )
            manager = NginxConfigManager(conf, vhosts, root / "guard", runner=FakeRunner())

            manager.apply(global_enabled=True, sites=[])

            rendered = conf.read_text(encoding="utf-8")
            self.assertLess(
                rendered.index("BEGIN NGINX_GUARD_GLOBAL"),
                rendered.index("include /www/server/panel/vhost/nginx/*.conf;"),
            )

    def test_apply_finds_http_block_in_an_included_config_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            conf = root / "nginx.conf"
            vhosts = root / "vhost"
            include_dir = root / "conf.d"
            vhosts.mkdir()
            include_dir.mkdir()
            conf.write_text("include conf.d/http.conf;\n", encoding="utf-8")
            http_conf = include_dir / "http.conf"
            http_conf.write_text("http\n{\n}\n", encoding="utf-8")
            vhost = vhosts / "example.com.conf"
            vhost.write_text(
                "server\n{\n    server_name example.com;\n}\n",
                encoding="utf-8",
            )
            manager = NginxConfigManager(conf, vhosts, root / "guard", runner=FakeRunner())

            result = manager.apply(
                global_enabled=True,
                sites=[{"id": "123", "name": "example.com", "mode": "MONITOR", "engine": "native"}],
            )

            self.assertTrue(result["ok"])
            self.assertIn("NGINX_GUARD_GLOBAL", http_conf.read_text(encoding="utf-8"))
            self.assertNotIn("NGINX_GUARD_GLOBAL", conf.read_text(encoding="utf-8"))
            self.assertIn("NGINX_GUARD_SITE:123", vhost.read_text(encoding="utf-8"))

    def test_apply_resolves_relative_includes_from_aapanel_openresty_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            conf_dir = root / "conf"
            compiled_prefix = root / "nginx"
            vhosts = root / "vhost"
            conf_dir.mkdir()
            (compiled_prefix / "conf.d").mkdir(parents=True)
            vhosts.mkdir()
            conf = conf_dir / "nginx.conf"
            conf.write_text("include conf.d/http.conf;\n", encoding="utf-8")
            http_conf = compiled_prefix / "conf.d" / "http.conf"
            http_conf.write_text("http\n{\n}\n", encoding="utf-8")
            vhost = vhosts / "example.com.conf"
            vhost.write_text(
                "server\n{\n    server_name example.com;\n}\n",
                encoding="utf-8",
            )
            manager = NginxConfigManager(conf, vhosts, root / "guard", runner=FakeRunner())

            result = manager.apply(
                global_enabled=True,
                sites=[{"id": "123", "name": "example.com", "mode": "MONITOR", "engine": "native"}],
            )

            self.assertTrue(result["ok"])
            self.assertIn("NGINX_GUARD_GLOBAL", http_conf.read_text(encoding="utf-8"))

    def test_failed_apply_restores_an_included_http_config_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            conf = root / "nginx.conf"
            vhosts = root / "vhost"
            include_dir = root / "conf.d"
            vhosts.mkdir()
            include_dir.mkdir()
            conf.write_text("include conf.d/http.conf;\n", encoding="utf-8")
            http_conf = include_dir / "http.conf"
            original_http = "http\n{\n}\n"
            http_conf.write_text(original_http, encoding="utf-8")
            vhost = vhosts / "example.com.conf"
            original_vhost = "server\n{\n    server_name example.com;\n}\n"
            vhost.write_text(original_vhost, encoding="utf-8")
            manager = NginxConfigManager(
                conf,
                vhosts,
                root / "guard",
                runner=FakeRunner(test_ok=False),
            )

            with self.assertRaises(NginxCommandError):
                manager.apply(
                    global_enabled=True,
                    sites=[{"id": "123", "name": "example.com", "mode": "BLOCK", "engine": "native"}],
                )

            self.assertEqual(http_conf.read_text(encoding="utf-8"), original_http)
            self.assertEqual(vhost.read_text(encoding="utf-8"), original_vhost)

    def test_failed_nginx_test_restores_original_files_and_does_not_reload(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = FakeRunner(test_ok=False)
            manager = self._manager(tmp, runner)
            original_main = Path(tmp, "nginx.conf").read_text()
            original_site = Path(tmp, "vhost", "example.com.conf").read_text()

            with self.assertRaises(NginxCommandError):
                manager.apply(
                    global_enabled=True,
                    sites=[{"id": "123", "name": "example.com", "mode": "BLOCK", "engine": "native"}],
                )

            self.assertEqual(runner.calls, ["test", "test"])
            self.assertEqual(Path(tmp, "nginx.conf").read_text(), original_main)
            self.assertEqual(
                Path(tmp, "vhost", "example.com.conf").read_text(),
                original_site,
            )

    def test_reload_failure_restores_and_reloads_the_previous_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = SequencedRunner(tests=[True, True], reloads=[False, True])
            manager = self._manager(tmp, runner)
            original_main = Path(tmp, "nginx.conf").read_text()
            original_site = Path(tmp, "vhost", "example.com.conf").read_text()

            with self.assertRaises(NginxCommandError):
                manager.apply(
                    global_enabled=True,
                    sites=[{"id": "123", "name": "example.com", "mode": "BLOCK", "engine": "native"}],
                )

            self.assertEqual(runner.calls, ["test", "reload", "test", "reload"])
            self.assertEqual(Path(tmp, "nginx.conf").read_text(), original_main)
            self.assertEqual(Path(tmp, "vhost", "example.com.conf").read_text(), original_site)

    def test_lua_capability_detection_is_conservative(self):
        self.assertTrue(detect_lua_module("--with-http_lua_module --with-cc"))
        self.assertTrue(detect_lua_module("ngx_http_lua_module"))
        self.assertTrue(detect_lua_module("nginx version: openresty/1.29.2.5"))
        self.assertTrue(detect_lua_module("--add-module=/opt/lua-nginx-module"))
        self.assertTrue(detect_lua_module("--add-module=../ngx_lua-0.10.31rc5"))
        self.assertFalse(detect_lua_module("nginx version: nginx/1.24.0"))

    def test_limit_req_dry_run_capability_detection_handles_old_and_current_builds(self):
        self.assertFalse(detect_limit_req_dry_run("nginx version: nginx/1.16.1"))
        self.assertTrue(detect_limit_req_dry_run("nginx version: openresty/1.31.1.1"))

    def test_site_marker_is_added_to_all_server_blocks_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            conf = root / "nginx.conf"
            vhosts = root / "vhost"
            vhosts.mkdir()
            conf.write_text("http {\n}\n", encoding="utf-8")
            (vhosts / "multi.example.conf").write_text(
                "server {\n listen 80;\n server_name multi.example;\n}\n"
                "server {\n listen 443 ssl;\n server_name multi.example;\n}\n",
                encoding="utf-8",
            )
            runner = FakeRunner()
            manager = NginxConfigManager(conf, vhosts, root / "guard", runner=runner)
            site = {"id": "9", "name": "multi.example", "mode": "BLOCK", "engine": "native"}
            manager.apply(global_enabled=True, sites=[site])
            manager.apply(global_enabled=True, sites=[site])
            text = (vhosts / "multi.example.conf").read_text(encoding="utf-8")
            self.assertEqual(text.count("BEGIN NGINX_GUARD_SITE:9"), 2)
            self.assertEqual(text.count("END NGINX_GUARD_SITE:9"), 2)

    def test_successful_apply_writes_lua_loadable_version_and_manual_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = FakeRunner()
            manager = self._manager(tmp, runner)
            original_main = Path(tmp, "nginx.conf").read_text()
            result = manager.apply(
                global_enabled=True,
                sites=[{"id": "123", "name": "example.com", "mode": "MONITOR", "engine": "native"}],
            )
            version = Path(result["backup"]).parent.parent / "runtime" / "version"
            self.assertTrue(version.is_file())
            self.assertIn("return ", version.read_text())
            Path(tmp, "nginx.conf").write_text("broken\n", encoding="utf-8")
            manager.restore_backup(Path(result["backup"]).name)
            self.assertEqual(Path(tmp, "nginx.conf").read_text(), original_main)

    def test_apply_makes_lua_runtime_files_readable_by_nginx_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = FakeRunner()
            manager = self._manager(tmp, runner)
            runtime_modes = {}
            original_write = nginx_module._atomic_write

            def record_write(path, content, mode=0o640):
                path = Path(path)
                if path.name in {"snapshot.lua", "version"}:
                    runtime_modes[path.name] = mode
                return original_write(path, content, mode)

            with patch.object(nginx_module, "_atomic_write", side_effect=record_write):
                manager.apply(
                    global_enabled=True,
                    sites=[{"id": "123", "name": "example.com", "mode": "MONITOR", "engine": "lua"}],
                    lua_available=True,
                )

            self.assertEqual(runtime_modes["snapshot.lua"], 0o644)
            self.assertEqual(runtime_modes["version"], 0o644)

    def test_restore_backup_revalidates_and_recovers_if_selected_backup_is_bad(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._manager(tmp, FakeRunner())
            result = manager.apply(
                global_enabled=True,
                sites=[{"id": "123", "name": "example.com", "mode": "MONITOR", "engine": "native"}],
            )
            backup_dir = Path(result["backup"])
            manifest = json.loads((backup_dir / "manifest.json").read_text())
            main_record = next(item for item in manifest if item["path"] == str(root / "nginx.conf"))
            (backup_dir / main_record["backup"]).write_text("broken\n", encoding="utf-8")

            runner = SequencedRunner(tests=[False, True], reloads=[True])
            manager.runner = runner
            original_main = (root / "nginx.conf").read_text()
            with self.assertRaises(NginxCommandError):
                manager.restore_backup(backup_dir.name)

            self.assertEqual(runner.calls, ["test", "test", "reload"])
            self.assertEqual((root / "nginx.conf").read_text(), original_main)

    def test_apply_removes_stale_site_marker_when_site_is_no_longer_enabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = FakeRunner()
            manager = self._manager(tmp, runner)
            site = {"id": "123", "name": "example.com", "mode": "BLOCK", "engine": "native"}
            manager.apply(global_enabled=True, sites=[site])
            manager.apply(global_enabled=True, sites=[])
            self.assertNotIn(
                "NGINX_GUARD_SITE:123",
                Path(tmp, "vhost", "example.com.conf").read_text(encoding="utf-8"),
            )

    def test_apply_retains_only_three_most_recent_backups(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = FakeRunner()
            manager = self._manager(tmp, runner)
            site = {"id": "123", "name": "example.com", "mode": "MONITOR", "engine": "native"}

            for _ in range(5):
                manager.apply(global_enabled=True, sites=[site])

            backups = sorted((Path(tmp) / "guard" / "backup").iterdir(), reverse=True)
            self.assertEqual(len([path for path in backups if path.is_dir()]), 3)

    def test_apply_removes_stale_owned_generated_site_fragments(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = FakeRunner()
            manager = self._manager(tmp, runner)
            generated = Path(tmp) / "guard" / "generated"
            generated.mkdir(parents=True)
            stale = generated / "site-999.conf"
            stale.write_text("stale\n", encoding="utf-8")

            manager.apply(
                global_enabled=True,
                sites=[{"id": "123", "name": "example.com", "mode": "MONITOR", "engine": "native"}],
            )

            self.assertFalse(stale.exists())


if __name__ == "__main__":
    unittest.main()
