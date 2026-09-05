import json
import unittest
from datetime import datetime, timedelta, timezone

from nginx_guard.lib.analysis import analyze_jsonl, analysis_to_csv


class LogAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)

    def rows(self):
        rows = []
        for index in range(3):
            rows.append(
                {
                    "time": (self.now - timedelta(minutes=10 + index)).isoformat(),
                    "remote_addr": "198.51.100.10",
                    "host": "example.com",
                    "method": "POST",
                    "uri": "/login",
                    "status": 200,
                    "action": "MONITOR",
                    "content_type": "application/json",
                    "content_length": "42",
                }
            )
        rows.extend(
            [
                {
                    "time": (self.now - timedelta(minutes=5)).isoformat(),
                    "remote_addr": "198.51.100.11",
                    "method": "GET",
                    "uri": "/admin",
                    "rule_id": "NG2001",
                    "rule_name": "SQL 注入特征",
                    "status": 403,
                    "action": "BLOCK",
                    "query": "token=secret&x=1",
                    "cookie": "must-not-export",
                },
                {
                    "time": (self.now - timedelta(minutes=4)).isoformat(),
                    "remote_addr": "198.51.100.11",
                    "method": "GET",
                    "uri": "/admin",
                    "rule_id": "NG2001",
                    "rule_name": "SQL 注入特征",
                    "status": 403,
                    "action": "BLOCK",
                },
                {
                    "time": (self.now - timedelta(minutes=3)).isoformat(),
                    "remote_addr": "198.51.100.11",
                    "method": "GET",
                    "uri": "/admin",
                    "rule_id": "NG2001",
                    "rule_name": "SQL 注入特征",
                    "status": 403,
                    "action": "BLOCK",
                },
                {
                    "time": (self.now - timedelta(minutes=2)).isoformat(),
                    "remote_addr": "198.51.100.12",
                    "method": "GET",
                    "uri": "/app.js",
                    "status": 200,
                    "action": "MONITOR",
                },
                {
                    "time": (self.now - timedelta(days=8)).isoformat(),
                    "remote_addr": "198.51.100.99",
                    "uri": "/old",
                    "action": "BLOCK",
                    "status": 403,
                },
            ]
        )
        return rows

    def test_analysis_uses_window_buckets_top_lists_and_endpoint_candidates(self):
        result = analyze_jsonl(
            [json.dumps(row) for row in self.rows()],
            now=self.now,
            window="24h",
            top_n=10,
        )

        self.assertEqual(result["total"], 7)
        self.assertEqual(result["blocked"], 3)
        self.assertEqual(result["monitor"], 4)
        self.assertEqual(result["block_rate"], 42.86)
        self.assertEqual(len(result["trend"]), 24)
        self.assertEqual(result["top_ips"][0]["ip"], "198.51.100.11")
        self.assertEqual(result["top_paths"][0]["path"], "/admin")
        self.assertEqual(result["top_rules"][0]["rule_id"], "NG2001")
        self.assertIn("403", {item["status"] for item in result["status_counts"]})
        candidates = [item for item in result["endpoint_candidates"] if item["path"] == "/login"]
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["category"], "login")
        self.assertEqual(candidates[0]["requests"], 3)
        self.assertEqual(candidates[0]["confidence"], "high")
        self.assertEqual(candidates[0]["template"]["unit"], "m")
        self.assertFalse(any(item["path"] == "/app.js" for item in result["endpoint_candidates"]))

    def test_blocked_only_filters_before_aggregation_and_window_sizes_are_stable(self):
        result = analyze_jsonl(
            [json.dumps(row) for row in self.rows()],
            now=self.now,
            window="3d",
            blocked_only=True,
            top_n=2,
        )
        self.assertEqual(result["total"], 3)
        self.assertEqual(result["blocked"], 3)
        self.assertEqual(result["monitor"], 0)
        self.assertEqual(len(result["trend"]), 12)
        self.assertLessEqual(len(result["top_ips"]), 2)
        self.assertEqual(len(analyze_jsonl([], now=self.now, window="7d")["trend"]), 7)

    def test_csv_is_bom_prefixed_aggregated_and_does_not_export_secrets(self):
        result = analyze_jsonl(
            [json.dumps(row) for row in self.rows()],
            now=self.now,
            window="24h",
        )
        csv_text = analysis_to_csv(result)

        self.assertTrue(csv_text.startswith("\ufeff"))
        self.assertIn("Top 攻击 IP", csv_text)
        self.assertIn("198.51.100.11", csv_text)
        self.assertNotIn("must-not-export", csv_text)
        self.assertNotIn("authorization", csv_text.lower())
        self.assertNotIn("token=", csv_text.lower())


if __name__ == "__main__":
    unittest.main()
