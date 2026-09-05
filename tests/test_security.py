import unittest

from nginx_guard.lib.security import (
    ValidationError,
    normalize_site_id,
    sanitize_query,
    validate_ip_or_cidr,
)


class SecurityValidationTests(unittest.TestCase):
    def test_normalize_site_id_accepts_numeric_aa_panel_id(self):
        self.assertEqual(normalize_site_id("123"), "123")
        self.assertEqual(normalize_site_id(7), "7")

    def test_normalize_site_id_rejects_path_like_values(self):
        with self.assertRaises(ValidationError):
            normalize_site_id("../etc/passwd")

        with self.assertRaises(ValidationError):
            normalize_site_id("1/../../2")

    def test_validate_ip_or_cidr_accepts_ipv4_ipv6_and_cidr(self):
        self.assertEqual(validate_ip_or_cidr("203.0.113.10"), "203.0.113.10")
        self.assertEqual(validate_ip_or_cidr("2001:db8::1"), "2001:db8::1")
        self.assertEqual(validate_ip_or_cidr("198.51.100.0/24"), "198.51.100.0/24")

    def test_validate_ip_or_cidr_rejects_invalid_values(self):
        with self.assertRaises(ValidationError):
            validate_ip_or_cidr("999.1.1.1")

        with self.assertRaises(ValidationError):
            validate_ip_or_cidr("not-an-ip")

    def test_sanitize_query_redacts_secret_fields_and_caps_length(self):
        query = "name=alice&token=abc123&password=secret&normal=ok"
        sanitized = sanitize_query(query)
        self.assertIn("name=alice", sanitized)
        self.assertIn("normal=ok", sanitized)
        self.assertNotIn("abc123", sanitized)
        self.assertNotIn("secret", sanitized)
        self.assertIn("[REDACTED]", sanitized)
        self.assertLessEqual(len(sanitize_query("x=" + ("a" * 5000))), 2048)


if __name__ == "__main__":
    unittest.main()

