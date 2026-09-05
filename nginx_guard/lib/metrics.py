"""Small, dependency-free JSONL metric aggregation helpers."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def aggregate_jsonl(lines, now=None):
    current = _as_utc(now)

    if isinstance(lines, (str, Path)):
        try:
            with Path(lines).open("r", encoding="utf-8", errors="replace") as handle:
                lines = handle
                return _aggregate_lines(lines, current)
        except OSError:
            return _empty_result()
    return _aggregate_lines(lines, current)


def _empty_hourly():
    return [{"requests": 0, "attacks": 0} for _ in range(24)]


def _empty_result():
    return {
        "total": 0,
        "blocked": 0,
        "malformed": 0,
        "by_site": {},
        "by_rule": {},
        "hourly": _empty_hourly(),
    }


def _as_utc(value):
    if value is None:
        return datetime.now(timezone.utc)
    if not isinstance(value, datetime):
        raise TypeError("now must be a datetime")
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _parse_timestamp(row):
    value = row.get("time") or row.get("timestamp")
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, timezone.utc)
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        return _as_utc(parsed)
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _is_attack(row):
    action = str(row.get("action") or "").lower()
    if row.get("blocked") is True or action in {"block", "deny", "rate_limit", "403", "404", "429", "444"}:
        return True
    rule = str(row.get("rule_id") or row.get("rule") or "").strip()
    if rule and rule.lower() != "unknown":
        return True
    try:
        return int(row.get("status")) in {403, 404, 429, 444}
    except (TypeError, ValueError):
        return False


def _aggregate_lines(lines, now):
    total = 0
    blocked = 0
    malformed = 0
    by_site = Counter()
    by_rule = Counter()
    hourly = _empty_hourly()

    for line in lines:
        text = str(line).strip()
        if not text:
            continue
        try:
            row = json.loads(text)
        except (TypeError, ValueError, json.JSONDecodeError):
            malformed += 1
            continue
        if not isinstance(row, dict):
            malformed += 1
            continue
        total += 1
        action = str(row.get("action") or "").lower()
        if row.get("blocked") is True or action in {"block", "deny", "rate_limit"}:
            blocked += 1
        site = str(row.get("site_id") or row.get("site") or "unknown")
        rule = str(row.get("rule_id") or row.get("rule") or "unknown")
        by_site[site] += 1
        by_rule[rule] += 1
        timestamp = _parse_timestamp(row)
        if timestamp is not None:
            age = (now - timestamp).total_seconds()
            if 0 <= age < 24 * 60 * 60:
                index = 23 - int(age // (60 * 60))
                hourly[index]["requests"] += 1
                if _is_attack(row):
                    hourly[index]["attacks"] += 1

    return {
        "total": total,
        "blocked": blocked,
        "malformed": malformed,
        "by_site": dict(by_site),
        "by_rule": dict(by_rule),
        "hourly": hourly,
    }
