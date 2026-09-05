import unittest

from nginx_guard.lib.cloudflare import (
    DEFAULT_CLOUDFLARE_NETWORKS,
    lookup_network_membership,
    normalize_cloudflare_config,
    resolve_real_ip,
)


class CloudflareTests(unittest.TestCase):
    def test_lookup_reports_official_manual_and_duplicate_sources(self):
        result = lookup_network_membership(
            "104.16.0.1",
            official_networks=["104.16.0.0/13"],
            manual_networks=["104.16.0.0/13", "192.0.2.0/24"],
        )
        self.assertEqual(result["ip"], "104.16.0.1")
        self.assertTrue(result["matched"])
        self.assertEqual(result["matches"], [{"network": "104.16.0.0/13", "sources": ["official", "manual"]}])
        self.assertFalse(lookup_network_membership("203.0.113.8", ["104.16.0.0/13"], ["192.0.2.0/24"])["matched"])

    def test_lookup_rejects_cidr_and_invalid_address_in_chinese(self):
        for address in ("104.16.0.0/13", "not-an-ip"):
            with self.assertRaisesRegex(ValueError, "请输入有效的 IPv4 或 IPv6 地址"):
                lookup_network_membership(address)

    def test_cf_connecting_ip_is_used_only_from_trusted_cloudflare_network(self):
        headers = {"CF-Connecting-IP": "203.0.113.8"}
        self.assertEqual(
            resolve_real_ip("104.16.0.1", headers, DEFAULT_CLOUDFLARE_NETWORKS, enabled=True),
            "203.0.113.8",
        )
        self.assertEqual(
            resolve_real_ip("198.51.100.2", headers, DEFAULT_CLOUDFLARE_NETWORKS, enabled=True),
            "198.51.100.2",
        )

    def test_invalid_forwarded_address_falls_back_to_remote(self):
        self.assertEqual(
            resolve_real_ip(
                "104.16.0.1",
                {"CF-Connecting-IP": "not-an-ip"},
                DEFAULT_CLOUDFLARE_NETWORKS,
                enabled=True,
            ),
            "104.16.0.1",
        )

    def test_legacy_networks_are_migrated_to_manual_and_survive_official_refresh(self):
        migrated = normalize_cloudflare_config(
            {"enabled": True, "networks": ["192.0.2.0/24"]}
        )

        self.assertIn("192.0.2.0/24", migrated["manual_networks"])
        self.assertIn("192.0.2.0/24", migrated["networks"])
        refreshed = normalize_cloudflare_config(
            {
                "enabled": True,
                "official_networks": ["198.51.100.0/24"],
                "manual_networks": migrated["manual_networks"],
            }
        )
        self.assertEqual(refreshed["official_networks"], ["198.51.100.0/24"])
        self.assertIn("192.0.2.0/24", refreshed["manual_networks"])
        self.assertIn("192.0.2.0/24", refreshed["networks"])

    def test_string_false_does_not_enable_cloudflare(self):
        self.assertFalse(normalize_cloudflare_config({"enabled": "false"})["enabled"])


if __name__ == "__main__":
    unittest.main()
