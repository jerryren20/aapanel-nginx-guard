import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from nginx_guard.lib.logs import (
    cleanup_jsonl_directory,
    iter_log_lines,
    is_blocked_event,
    normalize_event,
    safe_event,
    rotate_jsonl,
)


class LogRotationTests(unittest.TestCase):
    def test_log_reader_skips_corrupt_gzip_rotation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corrupt = root / "events-site-1.jsonl.20260904120000.gz"
            corrupt.write_bytes(b"not-a-gzip-file")
            valid = root / "events-site-1.jsonl"
            valid.write_text('{"status":200}\n', encoding="utf-8")

            self.assertEqual(list(iter_log_lines([corrupt, valid])), ['{"status":200}\n'])

    def test_blocked_event_distinguishes_monitor_from_real_block(self):
        self.assertTrue(is_blocked_event({"action": "BLOCK", "status": 403}))
        self.assertTrue(is_blocked_event({"action": "RATE_LIMIT", "status": 429}))
        self.assertFalse(is_blocked_event({"action": "MONITOR", "status": 403, "rule_id": "NG2001"}))
        self.assertFalse(is_blocked_event({"blocked": False, "rule_id": "NG1001", "status": 403}))
        self.assertTrue(is_blocked_event({"rule_id": "NG1001", "status": 403}))
        self.assertFalse(is_blocked_event({"status": 404}))

    def test_event_normalization_falls_back_to_remote_addr_and_adds_fields(self):
        normalized = normalize_event({"remote_addr": "198.51.100.8", "status": 403, "rule_id": "NG1001"})
        self.assertEqual(normalized["client_ip"], "198.51.100.8")
        self.assertEqual(normalized["cfip"], "")
        self.assertEqual(normalized["content_type"], "")
        self.assertEqual(normalized["content_length"], "")
        self.assertTrue(normalized["blocked"])

    def test_safe_event_removes_legacy_sensitive_fields_and_request_queries(self):
        normalized = safe_event(
            {
                "remote_addr": "198.51.100.8",
                "query": "token=secret&name=alice",
                "http_cookie": "session=secret",
                "access_token": "secret",
                "request": "GET /login?token=secret HTTP/1.1",
                "status": 403,
                "rule_id": "NG1001",
            }
        )

        self.assertEqual(normalized["query"], "token=[REDACTED]&name=alice")
        self.assertEqual(normalized["request"], "GET /login HTTP/1.1")
        self.assertNotIn("http_cookie", normalized)
        self.assertNotIn("access_token", normalized)

    def test_rotation_caps_file_size_and_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current = root / "events-site-1.jsonl"
            current.write_text(json.dumps({"query": "password=x"}) + "\n" * 20, encoding="utf-8")
            old = root / "events-site-1.jsonl.20200101000000"
            old.write_text("old\n", encoding="utf-8")
            result = rotate_jsonl(current, max_bytes=20, keep_days=1, max_files=1, now=time.time())
            self.assertTrue(result["rotated"])
            self.assertLessEqual(len(list(root.glob("events-site-1.jsonl*"))), 2)
            self.assertTrue(current.is_file())

    def test_rotation_enforces_total_directory_size_and_age(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current = root / "events-site-1.jsonl"
            current.write_text("current\n", encoding="utf-8")
            for index in range(4):
                rotated = root / ("events-site-1.jsonl.2026010100000%s" % index)
                rotated.write_text("x" * 20, encoding="utf-8")
                old_time = time.time() - (index + 2) * 86400
                os.utime(rotated, (old_time, old_time))

            rotate_jsonl(
                current,
                max_bytes=1024,
                keep_days=7,
                max_files=20,
                max_total_bytes=45,
                now=time.time(),
            )

            retained = [path for path in root.glob("events-site-1.jsonl*") if path.is_file()]
            self.assertLessEqual(sum(path.stat().st_size for path in retained), 45)

    def test_cleanup_rotates_an_old_active_file_before_applying_age_retention(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current = root / "events-site-1.jsonl"
            current.write_text("old event\n", encoding="utf-8")
            old_time = time.time() - 8 * 86400
            os.utime(current, (old_time, old_time))

            cleanup_jsonl_directory(root, max_bytes=1024, keep_days=7, now=time.time())

            self.assertTrue(current.is_file())
            self.assertEqual(current.read_text(encoding="utf-8"), "")

    def test_rotation_truncates_the_active_inode_for_nginx_open_file_handles(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current = root / "events-site-1.jsonl"
            current.write_text("event\n", encoding="utf-8")

            with current.open("rb") as handle:
                inode = os.fstat(handle.fileno()).st_ino
                result = rotate_jsonl(current, max_bytes=1, now=time.time())
                self.assertTrue(result["rotated"])
                self.assertEqual(os.fstat(handle.fileno()).st_ino, os.stat(current).st_ino)
                self.assertEqual(os.fstat(handle.fileno()).st_ino, inode)

            self.assertEqual(current.read_text(encoding="utf-8"), "")
            self.assertTrue(any(path.name.startswith("events-site-1.jsonl.") for path in root.iterdir()))

    def test_cleanup_enforces_total_size_across_multiple_active_site_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for site_id in range(1, 4):
                current = root / ("events-site-%s.jsonl" % site_id)
                current.write_text("x" * 40, encoding="utf-8")
                os.utime(current, (time.time() - site_id, time.time() - site_id))

            cleanup_jsonl_directory(
                root,
                max_bytes=1024,
                keep_days=7,
                max_files=20,
                max_total_bytes=50,
                now=time.time(),
            )

            retained = [path for path in root.glob("events-site-*.jsonl*") if path.is_file()]
            self.assertLessEqual(sum(path.stat().st_size for path in retained), 50)


if __name__ == "__main__":
    unittest.main()
