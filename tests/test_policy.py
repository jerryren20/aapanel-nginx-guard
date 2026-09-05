import unittest
import re

from nginx_guard.lib.policy import (
    DEFAULT_RULES,
    PolicyError,
    evaluate_body,
    evaluate_request,
    interface_whitelist_matches,
    normalize_rate_paths,
    validate_custom_rule,
    validate_interface_whitelist,
)
from nginx_guard.lib.security import ValidationError


class PolicyTests(unittest.TestCase):
    def test_rate_paths_are_canonicalized_and_last_duplicate_wins(self):
        result = normalize_rate_paths(
            [
                {"path": "/Login/", "rate": "10", "unit": "r/m", "burst": "3"},
                {"path": "/login", "rate": "20", "unit": "s", "burst": "5"},
            ]
        )

        self.assertEqual(result, [{"path": "/login", "rate": 20, "unit": "s", "burst": 5}])

    def test_rate_path_query_and_fragment_are_rejected_with_line_number(self):
        for value in ("/login?next=/", "/login#fragment"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValidationError, "第 1 行"):
                    normalize_rate_paths([{"path": value, "rate": 10, "burst": 3}])

    def test_high_confidence_rules_block_dangerous_inputs(self):
        self.assertEqual(evaluate_request("/.env", "", {}, DEFAULT_RULES)["rule_id"], "NG1001")
        self.assertEqual(
            evaluate_request("/download", "file=../../etc/passwd", {}, DEFAULT_RULES)["rule_id"],
            "NG1002",
        )
        self.assertEqual(
            evaluate_request("/webhook", "url=http://169.254.169.254/latest/meta-data/", {}, DEFAULT_RULES)[
                "rule_id"
            ],
            "NG1003",
        )

    def test_sql_xss_and_scanner_rules_default_to_block(self):
        actions = {rule["id"]: rule["action"] for rule in DEFAULT_RULES}
        self.assertEqual(actions["NG2001"], "block")
        self.assertEqual(actions["NG2002"], "block")
        self.assertEqual(actions["NG2003"], "block")
        self.assertEqual(
            evaluate_request("/search", "q=union%20select%201", {}, DEFAULT_RULES)["action"],
            "block",
        )
        self.assertEqual(
            evaluate_request("/search", "q=%3Cscript%3E", {}, DEFAULT_RULES)["action"],
            "block",
        )
        self.assertEqual(
            evaluate_request("/", "", {"user_agent": "sqlmap/1.7"}, DEFAULT_RULES)["action"],
            "block",
        )

    def test_whitelist_does_not_bypass_high_risk_rules(self):
        result = evaluate_request(
            "/.git/config",
            "",
            {"ip": "10.0.0.8", "whitelisted": True},
            DEFAULT_RULES,
        )
        self.assertEqual(result["rule_id"], "NG1001")
        self.assertTrue(result["high_risk"])

    def test_custom_regex_is_rejected_when_it_is_obviously_dangerous(self):
        with self.assertRaises(PolicyError):
            validate_custom_rule({"match": "uri_regex", "pattern": "(a+)+$"})

    def test_native_sensitive_pattern_matches_git_and_environment_paths(self):
        from nginx_guard.lib.policy import native_patterns

        pattern = native_patterns()["sensitive"]
        self.assertRegex("/.git/HEAD", re.compile(pattern, re.IGNORECASE))
        self.assertRegex("/.env.production", re.compile(pattern, re.IGNORECASE))

    def test_native_medium_patterns_match_common_percent_encoded_payloads(self):
        from nginx_guard.lib.policy import native_patterns

        patterns = native_patterns()
        self.assertRegex("q=union%20select%201", re.compile(patterns["sqli"], re.IGNORECASE))
        self.assertRegex("q=%3Cscript%3Ealert(1)", re.compile(patterns["xss"], re.IGNORECASE))
        self.assertRegex("q=or%201%3d1", re.compile(patterns["sqli"], re.IGNORECASE))

    def test_interface_whitelist_ignores_scheme_and_respects_path_boundary_and_port(self):
        entries = validate_interface_whitelist(
            [
                {"match": "exact", "url": "https://example.com:8443/api/login"},
                {"match": "prefix", "url": "http://example.com/api/upload/"},
                {"match": "exact", "url": "https://all.example.com/"},
            ]
        )
        self.assertTrue(interface_whitelist_matches(entries, "EXAMPLE.COM", 8443, "/api/login"))
        self.assertFalse(interface_whitelist_matches(entries, "example.com", 443, "/api/login"))
        self.assertTrue(interface_whitelist_matches(entries, "example.com", 443, "/api/upload/file"))
        self.assertFalse(interface_whitelist_matches(entries, "example.com", 443, "/api/uploads/file"))
        self.assertTrue(interface_whitelist_matches(entries, "all.example.com", 443, "/any/path"))

    def test_interface_whitelist_rejects_query_with_a_chinese_line_number(self):
        with self.assertRaisesRegex(ValueError, "第 1 行"):
            validate_interface_whitelist([{"match": "exact", "url": "https://example.com/api?token=x"}])

    def test_body_inspection_is_limited_to_text_and_one_megabyte(self):
        blocked = evaluate_body('{"q":"union select 1"}', "application/json")
        self.assertEqual(blocked["rule_id"], "NG2001")
        self.assertEqual(blocked["action"], "block")
        self.assertEqual(evaluate_body("q=union%20select%201", "application/x-www-form-urlencoded")["rule_id"], "NG2001")
        self.assertEqual(evaluate_body("x" * (1024 * 1024 + 1), "application/json")["skipped"], "over_limit")
        self.assertFalse(evaluate_body("<script>", "application/octet-stream")["matched"])


if __name__ == "__main__":
    unittest.main()
