import json
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]


class PackageLayoutTests(unittest.TestCase):
    def test_aapanel_manifest_and_green_production_ui_exist(self):
        manifest_path = ROOT / "nginx_guard" / "info.json"
        ui_path = ROOT / "nginx_guard" / "index.html"
        self.assertTrue(manifest_path.is_file())
        self.assertTrue(ui_path.is_file())
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["name"], "nginx_guard")
        self.assertEqual(manifest["version"], "1.0.14")
        self.assertTrue(manifest["shell"].endswith("install.sh"))
        ui = ui_path.read_text(encoding="utf-8").lower()
        self.assertIn("#20a53a", ui)
        self.assertIn("nginx guard", ui)
        self.assertIn("window.jquery", ui)
        self.assertIn("function fitpanel", ui)
        self.assertIn('classlist.toggle("error"', ui)
        self.assertIn("init_csrf_err", ui)
        self.assertIn("request_token_head", ui)
        self.assertIn("x-http-token", ui)
        self.assertIn("jq.ajax", ui)
        self.assertIn("headers: requestheaders()", ui)
        self.assertIn("apsess_", ui)
        self.assertIn("array.isarray(m.hourly)", ui)
        self.assertIn(".bar.attack { background: var(--danger);", ui)
        self.assertIn("运行时异常策略", ui)
        self.assertIn("已启用，待应用", ui)
        self.assertIn("最近 3 个", ui)
        self.assertIn("自定义规则", ui)
        self.assertIn("未找到 http 配置块", ui)
        self.assertIn("未找到站点配置文件", ui)
        self.assertIn("http_lua_module", ui)
        self.assertIn("native 原生引擎", ui)
        self.assertIn("text.indexof(key)", ui)
        self.assertIn("ng2001", ui)
        self.assertIn("攻击类型", ui)
        self.assertIn("官方网段", ui)
        self.assertIn("20 mb", ui)
        self.assertIn("blocked_only", ui)
        self.assertIn("logsite", ui)
        self.assertIn("logfilter", ui)
        self.assertIn("lookup_cloudflare_ip", ui)
        self.assertIn("cfip", ui)
        self.assertIn("客户端 ip", ui)
        self.assertIn("删除", ui)
        self.assertIn("日志分析", ui)
        self.assertIn("仅显示已拦截", ui)
        self.assertIn("登录接口", ui)
        self.assertIn("验证码接口", ui)
        self.assertIn("上传接口", ui)
        self.assertIn("导出 csv", ui)

    def test_site_editor_is_namespaced_and_mounts_inside_plugin(self):
        ui = (ROOT / "nginx_guard" / "index.html").read_text(encoding="utf-8").lower()
        self.assertIn(".main { min-width: 0; flex: 1; position: relative;", ui)
        self.assertIn(".ng-modal {", ui)
        self.assertIn('document.queryselector(".main") || document.body', ui)
        self.assertIn('class="ng-modal"', ui)

    def test_panel_layout_reacts_to_the_embedded_container_width(self):
        ui = (ROOT / "nginx_guard" / "index.html").read_text(encoding="utf-8").lower()
        self.assertIn(".layout.narrow .sidebar { width: 64px; flex-basis: 64px; }", ui)
        self.assertIn("new resizeobserver", ui)
        self.assertIn("entries[0].contentrect.width", ui)
        self.assertIn('layout.classlist.toggle("narrow", width < 760)', ui)

    def test_install_does_not_register_an_external_service(self):
        install = (ROOT / "nginx_guard" / "install.sh").read_text(encoding="utf-8")
        uninstall = (ROOT / "nginx_guard" / "uninstall.sh").read_text(encoding="utf-8")
        self.assertNotIn("systemctl", install)
        self.assertNotIn("systemd", install.lower())
        self.assertNotIn("systemctl", uninstall)
        self.assertFalse((ROOT / "nginx_guard" / "systemd").exists())

    def test_install_makes_lua_engine_files_readable_by_nginx_worker(self):
        install = (ROOT / "nginx_guard" / "install.sh").read_text(encoding="utf-8")
        self.assertIn('chmod 0644 "$DATA_DIR/engine/"*.lua', install)
        self.assertIn('chmod 0644 "$DATA_DIR/runtime/version"', install)
        self.assertIn('chmod 0644 "$DATA_DIR/runtime/snapshot.lua"', install)


if __name__ == "__main__":
    unittest.main()
