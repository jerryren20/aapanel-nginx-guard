"""Streaming attack-log analysis and safe aggregate export helpers."""

from __future__ import annotations

import csv
import io
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .logs import is_attack_event, is_blocked_event, iter_log_lines, parse_event_time, safe_event


WINDOWS = {
    "24h": (timedelta(hours=24), timedelta(hours=1)),
    "3d": (timedelta(days=3), timedelta(hours=6)),
    "7d": (timedelta(days=7), timedelta(days=1)),
}

STATIC_SUFFIXES = (
    ".css",
    ".js",
    ".mjs",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".bmp",
    ".avif",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".pdf",
)

_STATIC_PREFIXES = ("/static/", "/assets/", "/dist/", "/build/")
_WRITE_METHODS = {"POST", "PUT", "PATCH"}
_CATEGORY_MARKERS = {
    "login": ("/login", "/signin", "/sign-in", "/auth/login", "/oauth/token", "/session"),
    "captcha": ("/captcha", "/verify-code", "/verification-code", "/sms", "/otp", "/mfa"),
    "upload": ("/upload", "/uploads", "/file", "/attachment", "/media", "/import", "/avatar"),
}
_TEMPLATES = {
    "login": {"rate": 10, "unit": "m", "burst": 3},
    "captcha": {"rate": 6, "unit": "m", "burst": 2},
    "upload": {"rate": 2, "unit": "s", "burst": 5},
}

RULE_NAMES = {
    "NG1001": "敏感文件暴露",
    "NG1002": "路径穿越",
    "NG1003": "云元数据 SSRF",
    "NG2001": "SQL 注入特征",
    "NG2002": "XSS 特征",
    "NG2003": "扫描器 User-Agent",
    "NG3001": "CC 速率限制",
    "NG3002": "临时 IP 封禁",
}


def _rule_name(rule_id, value=""):
    name = str(value or "").strip()
    if name:
        return name
    normalized_id = str(rule_id or "").strip()
    if not normalized_id or normalized_id in {"—", "-"}:
        return ""
    return RULE_NAMES.get(normalized_id.upper(), "自定义规则")


def _as_utc(value=None):
    if value is None:
        return datetime.now(timezone.utc)
    if not isinstance(value, datetime):
        raise TypeError("now must be a datetime")
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _window_settings(window):
    key = str(window or "24h").strip().lower()
    if key not in WINDOWS:
        raise ValueError("时间范围只能是 24h、3d 或 7d")
    duration, bucket = WINDOWS[key]
    return key, duration, bucket


def _iso(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _event_path(row):
    raw = str(row.get("uri") or row.get("request_uri") or row.get("path") or "").strip()
    if not raw:
        raw = str(row.get("request") or "").strip()
    if " " in raw:
        match = re.search(r"\s(\S*?/[^\s]*)\s+HTTP(?:/|$)", raw, re.I)
        if match:
            raw = match.group(1)
        else:
            pieces = raw.split()
            candidates = [piece for piece in pieces if piece.startswith("/")]
            raw = candidates[0] if candidates else raw
    if not raw.startswith("/"):
        raw = "/" + raw
    try:
        parsed = urlsplit(raw)
        raw = parsed.path or "/"
    except ValueError:
        raw = raw.split("?", 1)[0] or "/"
    return raw.split("?", 1)[0].split("#", 1)[0] or "/"


def _candidate_path(path):
    """Return the effective path key used for endpoint recommendations."""

    value = str(path or "/").strip().lower()
    return value.rstrip("/") or "/"


def _is_static_path(path):
    lowered = str(path or "").lower()
    return lowered.endswith(STATIC_SUFFIXES) or lowered.startswith(_STATIC_PREFIXES)


def _has_marker(path, marker):
    path_parts = [item for item in str(path or "").lower().strip("/").split("/") if item]
    marker_parts = [item for item in str(marker).lower().strip("/").split("/") if item]
    if not path_parts or not marker_parts or len(marker_parts) > len(path_parts):
        return False
    for start in range(len(path_parts) - len(marker_parts) + 1):
        matched = True
        for offset, marker_part in enumerate(marker_parts):
            value = path_parts[start + offset]
            is_last = offset == len(marker_parts) - 1
            if value == marker_part:
                continue
            if is_last and re.fullmatch(
                re.escape(marker_part) + r"\.[a-z0-9][a-z0-9_-]{0,15}", value
            ):
                continue
            matched = False
            break
        if matched:
            return True
    return False


def _categories_for(path):
    return [
        category
        for category, markers in _CATEGORY_MARKERS.items()
        if any(_has_marker(path, marker) for marker in markers)
    ]


def _top(counter, top_n, key_name, blocked_counter=None):
    values = sorted(counter.items(), key=lambda item: (-item[1], str(item[0])))[:top_n]
    return [
        {
            key_name: value,
            "value": value,
            "count": count,
            "requests": count,
            "blocked": (blocked_counter.get(value, 0) if blocked_counter is not None else 0),
        }
        for value, count in values
    ]


def _candidate_reason(category, methods, content_types, multipart):
    labels = {
        "login": "路径包含登录接口关键词",
        "captcha": "路径包含验证码接口关键词",
        "upload": "路径包含上传/文件接口关键词",
    }
    reasons = [labels[category]]
    if methods.intersection(_WRITE_METHODS):
        reasons.append("观察到写入请求方法")
    if multipart:
        reasons.append("请求类型为 multipart/form-data")
    if content_types:
        reasons.append("已记录请求 Content-Type")
    return "；".join(reasons)


def _endpoint_candidates(stats):
    result = []
    for (category, path), item in stats.items():
        if item["requests"] < 3:
            continue
        methods = item["methods"]
        content_types = item["content_types"]
        multipart = item["multipart"]
        write_seen = bool(methods.intersection(_WRITE_METHODS))
        high = write_seen if category != "upload" else (write_seen or multipart)
        template = dict(_TEMPLATES[category])
        result.append(
            {
                "category": category,
                "path": path,
                "confidence": "high" if high else "medium",
                "reason": _candidate_reason(category, methods, content_types, multipart),
                "methods": sorted(methods),
                "requests": item["requests"],
                "peak_rate": max(item["minute_counts"].values() or [0]),
                "content_type": ", ".join(sorted(content_types)),
                "content_types": sorted(content_types),
                "template": template,
            }
        )
    return sorted(result, key=lambda item: (-item["requests"], item["category"], item["path"]))


def analyze_jsonl(lines, now=None, window="24h", blocked_only=False, top_n=10):
    """Analyze JSONL rows without retaining the raw request data."""

    if isinstance(lines, (str, Path)):
        lines = iter_log_lines([Path(lines)])
    window, duration, bucket_size = _window_settings(window)
    try:
        top_n = max(1, min(50, int(top_n)))
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("top_n 必须是 1-50 的整数") from exc
    current = _as_utc(now)
    start = current - duration
    bucket_count = int(duration.total_seconds() // bucket_size.total_seconds())
    trend = []
    for index in range(bucket_count):
        bucket_start = start + index * bucket_size
        trend.append(
            {
                "start": _iso(bucket_start),
                "end": _iso(bucket_start + bucket_size),
                "requests": 0,
                "blocked": 0,
                "monitor": 0,
            }
        )

    total = 0
    blocked = 0
    malformed = 0
    ips = Counter()
    blocked_ips = Counter()
    paths = Counter()
    blocked_paths = Counter()
    rules = Counter()
    blocked_rules = Counter()
    rule_names = {}
    statuses = Counter()
    actions = Counter()
    candidates = defaultdict(
        lambda: {
            "requests": 0,
            "methods": set(),
            "content_types": set(),
            "multipart": False,
            "minute_counts": Counter(),
        }
    )

    for line in lines:
        try:
            raw = line if isinstance(line, dict) else json.loads(str(line))
        except (TypeError, ValueError):
            malformed += 1
            continue
        if not isinstance(raw, dict):
            malformed += 1
            continue
        row = safe_event(raw)
        timestamp = parse_event_time(row)
        if timestamp is None:
            continue
        age = (timestamp - start).total_seconds()
        if age < 0 or age > duration.total_seconds() or timestamp > current:
            continue
        event_blocked = is_blocked_event(row)
        if blocked_only and not event_blocked:
            continue
        total += 1
        if event_blocked:
            blocked += 1
        bucket_index = min(bucket_count - 1, int(age // bucket_size.total_seconds()))
        trend[bucket_index]["requests"] += 1
        trend[bucket_index]["blocked" if event_blocked else "monitor"] += 1

        ip = str(row.get("client_ip") or row.get("remote_addr") or "—")
        path = _event_path(row)
        rule_id = str(row.get("rule_id") or row.get("rule") or "—")
        rule_name = _rule_name(rule_id, row.get("rule_name") or row.get("attack_type"))
        status = str(row.get("status") if row.get("status") is not None else "—")
        action = str(row.get("action") or ("BLOCK" if event_blocked else "MONITOR")).upper()
        if is_attack_event(row, event_blocked):
            ips[ip] += 1
            paths[path] += 1
            if event_blocked:
                blocked_ips[ip] += 1
                blocked_paths[path] += 1
            if rule_id not in {"", "—", "-", "unknown", "UNKNOWN"}:
                rules[rule_id] += 1
                rule_names.setdefault(rule_id, rule_name)
                if event_blocked:
                    blocked_rules[rule_id] += 1
        statuses[status] += 1
        actions[action] += 1

        if not _is_static_path(path):
            method = str(row.get("method") or "GET").upper()
            content_type = str(
                row.get("content_type")
                or row.get("content-type")
                or row.get("http_content_type")
                or ""
            ).strip()[:128]
            multipart = "multipart/form-data" in content_type.lower()
            for category in _categories_for(path):
                candidate = candidates[(category, _candidate_path(path))]
                candidate["requests"] += 1
                candidate["methods"].add(method)
                if content_type:
                    candidate["content_types"].add(content_type)
                candidate["multipart"] = candidate["multipart"] or multipart
                candidate["minute_counts"][timestamp.replace(second=0, microsecond=0)] += 1

    block_rate = round((blocked * 100.0 / total), 2) if total else 0.0
    top_rules = []
    for rule_id, count in sorted(rules.items(), key=lambda item: (-item[1], str(item[0])))[:top_n]:
        top_rules.append(
            {
                "rule_id": rule_id,
                "value": rule_id,
                "rule_name": rule_names.get(rule_id, ""),
                "count": count,
                "requests": count,
                "blocked": blocked_rules.get(rule_id, 0),
            }
        )
    return {
        "window": window,
        "from": _iso(start),
        "to": _iso(current),
        "total": total,
        "blocked": blocked,
        "monitor": total - blocked,
        "block_rate": block_rate,
        "malformed": malformed,
        "trend": trend,
        "top_ips": _top(ips, top_n, "ip", blocked_ips),
        "top_paths": _top(paths, top_n, "path", blocked_paths),
        "top_rules": top_rules,
        "status_counts": [
            {"status": value, "value": value, "count": count}
            for value, count in sorted(statuses.items(), key=lambda item: (-item[1], str(item[0])))[:top_n]
        ],
        "action_counts": [
            {"action": value, "value": value, "count": count}
            for value, count in sorted(actions.items(), key=lambda item: (-item[1], str(item[0])))
        ],
        "endpoint_candidates": _endpoint_candidates(candidates),
    }


def analysis_to_csv(result):
    """Serialize aggregate data only; never include raw request/query fields."""

    output = io.StringIO(newline="")
    output.write("\ufeff")
    writer = csv.writer(output)
    writer.writerow(["Nginx Guard 攻击分析"])
    writer.writerow(["时间范围", result.get("window", "24h"), "开始", result.get("from", ""), "结束", result.get("to", "")])
    writer.writerow(["总请求", result.get("total", 0), "已拦截", result.get("blocked", 0), "仅监控", result.get("monitor", 0), "拦截率", result.get("block_rate", 0)])
    writer.writerow([])

    def write_top(title, rows, fields):
        writer.writerow([title, "名称", "请求数", "拦截数"])
        for row in rows:
            name = row.get(fields[0], row.get("value", ""))
            if fields[0] == "rule_id":
                rule_id = str(name or "").strip()
                display_name = _rule_name(rule_id, row.get("rule_name"))
                if display_name and rule_id:
                    name = "%s（%s）" % (display_name, rule_id)
            writer.writerow([title, name, row.get("count", 0), row.get("blocked", "")])
        writer.writerow([])

    write_top("Top 攻击 IP", result.get("top_ips", []), ("ip",))
    write_top("Top 攻击 URL", result.get("top_paths", []), ("path",))
    write_top("Top 命中规则", result.get("top_rules", []), ("rule_id",))
    writer.writerow(["状态码分布", "状态码", "次数"])
    for row in result.get("status_counts", []):
        writer.writerow(["状态码分布", row.get("status", row.get("value", "")), row.get("count", 0)])
    writer.writerow([])
    writer.writerow(["动作分布", "动作", "次数"])
    for row in result.get("action_counts", []):
        writer.writerow(["动作分布", row.get("action", row.get("value", "")), row.get("count", 0)])
    writer.writerow([])
    writer.writerow(["接口候选", "类型", "路径", "置信度", "请求数", "峰值请求/分钟", "请求方法", "Content-Type", "说明"])
    for row in result.get("endpoint_candidates", []):
        writer.writerow(
            [
                "接口候选",
                row.get("category", ""),
                row.get("path", ""),
                row.get("confidence", ""),
                row.get("requests", 0),
                row.get("peak_rate", 0),
                ", ".join(row.get("methods", [])),
                row.get("content_type", ""),
                row.get("reason", ""),
            ]
        )
    return output.getvalue()
