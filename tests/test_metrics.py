import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from nginx_guard.lib.metrics import aggregate_jsonl


class MetricsTests(unittest.TestCase):
    def test_aggregate_jsonl_counts_attacks_by_site_and_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "attack.jsonl"
            rows = [
                {"site": "example.com", "action": "BLOCK", "rule_id": "NG1001"},
                {"site": "example.com", "action": "MONITOR", "rule_id": "NG2001"},
                {"site": "api.demo.cn", "action": "BLOCK", "rule_id": "NG1002"},
                {"site": "example.com", "action": "BLOCK", "rule_id": "NG1001"},
            ]
            path.write_text(
                "\n".join(json.dumps(row) for row in rows) + "\n",
                encoding="utf-8",
            )

            result = aggregate_jsonl(path)

            self.assertEqual(result["total"], 4)
            self.assertEqual(result["blocked"], 3)
            self.assertEqual(result["by_site"]["example.com"], 3)
            self.assertEqual(result["by_rule"]["NG1001"], 2)

    def test_aggregate_jsonl_ignores_malformed_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "attack.jsonl"
            path.write_text('{"site":"example.com"}\nnot-json\n', encoding="utf-8")

            result = aggregate_jsonl(path)

            self.assertEqual(result["total"], 1)
            self.assertEqual(result["malformed"], 1)

    def test_aggregate_jsonl_builds_real_recent_hour_buckets(self):
        now = datetime(2026, 9, 2, 12, 0, tzinfo=timezone.utc)
        rows = [
            {"time": (now - timedelta(hours=2, minutes=5)).isoformat(), "action": "MONITOR"},
            {"time": (now - timedelta(hours=2, minutes=1)).isoformat(), "rule_id": "NG1001", "status": 403},
            {"time": (now - timedelta(hours=25)).isoformat(), "action": "BLOCK"},
        ]

        result = aggregate_jsonl(
            [json.dumps(row) for row in rows],
            now=now,
        )

        self.assertEqual(len(result["hourly"]), 24)
        self.assertEqual(result["hourly"][21]["requests"], 2)
        self.assertEqual(result["hourly"][21]["attacks"], 1)
        self.assertEqual(sum(item["requests"] for item in result["hourly"]), 2)


if __name__ == "__main__":
    unittest.main()
