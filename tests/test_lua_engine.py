import unittest
from pathlib import Path


class LuaEngineSafetyTests(unittest.TestCase):
    def test_request_path_lua_reads_only_bounded_text_body(self):
        access = (Path(__file__).parents[1] / "nginx_guard" / "engine" / "access.lua").read_text(
            encoding="utf-8"
        )
        engine = (Path(__file__).parents[1] / "nginx_guard" / "engine" / "ng_guard_engine.lua").read_text(
            encoding="utf-8"
        )
        self.assertIn("ngx.req.read_body", engine)
        self.assertIn("1048576", engine)
        self.assertIn("application/json", engine)
        self.assertIn("text/", engine)
        self.assertIn("get_body_data", engine)
        self.assertIn("if not declared_length", engine)
        self.assertIn("http_content_encoding", engine)
        self.assertNotIn("io.open", access + engine)
        self.assertNotIn("body_filter_by_lua", access + engine)
        self.assertIn("pcall", access)

    def test_lua_engine_has_ttl_ban_path_and_custom_rule_hook(self):
        engine = (Path(__file__).parents[1] / "nginx_guard" / "engine" / "ng_guard_engine.lua").read_text(
            encoding="utf-8"
        )
        self.assertIn("ng_guard_ban", engine)
        self.assertIn("auto_ban", engine)
        self.assertIn("custom_rules", engine)
        self.assertIn("interface_whitelist", engine)
        self.assertIn("NG2001", engine)
        self.assertIn("NG2002", engine)

    def test_lua_engine_consumes_native_rule_map_before_body_inspection(self):
        engine = (Path(__file__).parents[1] / "nginx_guard" / "engine" / "ng_guard_engine.lua").read_text(
            encoding="utf-8"
        )
        self.assertIn("ng_guard_site_log_rule_id_", engine)
        self.assertIn("Native maps perform", engine)


if __name__ == "__main__":
    unittest.main()
