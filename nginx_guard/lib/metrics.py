"""Small, dependency-free JSONL metric aggregation helpers."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .logs import is_attack_event, is_blocked_event, iter_log_lines, parse_event_time


def aggregate_jsonl(lines, now=None):
    current = _as_utc(now)

    if isinstance(lines, (str, Path)):
        return _aggregate_lines(iter_log_lines([Path(lines)]), current)
    return _aggregate_lines(lines, current)


def _empty_hourly():
    return [{"requests": 0, "attacks": 0} for _ in range(24)]


def _as_utc(value):
    if value is None:
        return datetime.now(timezone.utc)
    if not isinstance(value, datetime):
        raise TypeError("now must be a datetime")
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


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
        except (TypeError, ValueError):
            malformed += 1
            continue
        if not isinstance(row, dict):
            malformed += 1
            continue
        total += 1
        if is_blocked_event(row):
            blocked += 1
        site = str(row.get("site_id") or row.get("site") or "unknown")
        rule = str(row.get("rule_id") or row.get("rule") or "unknown")
        by_site[site] += 1
        by_rule[rule] += 1
        timestamp = parse_event_time(row)
        if timestamp is not None:
            age = (now - timestamp).total_seconds()
            if 0 <= age < 24 * 60 * 60:
                index = 23 - int(age // (60 * 60))
                hourly[index]["requests"] += 1
                if is_attack_event(row):
                    hourly[index]["attacks"] += 1

    return {
        "total": total,
        "blocked": blocked,
        "malformed": malformed,
        "by_site": dict(by_site),
        "by_rule": dict(by_rule),
        "hourly": hourly,
    }
