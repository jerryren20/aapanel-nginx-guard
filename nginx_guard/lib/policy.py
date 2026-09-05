"""High-confidence request rules and bounded custom-rule validation."""

from __future__ import annotations

import re
from urllib.parse import unquote, urlsplit

from .security import ValidationError, validate_text


class PolicyError(ValueError):
    """Raised when a rule or policy cannot be safely compiled."""


DEFAULT_RULES = [
    {
        "id": "NG1001",
        "name": "敏感文件暴露",
        "description": "拦截常见环境变量、版本库、云凭据和备份文件。",
        "category": "敏感文件",
        "severity": "high",
        "enabled": True,
        "action": "block",
        "high_risk": True,
    },
    {
        "id": "NG1002",
        "name": "路径穿越",
        "description": "拦截编码或明文的路径穿越，以及本地文件探测。",
        "category": "路径穿越",
        "severity": "high",
        "enabled": True,
        "action": "block",
        "high_risk": True,
    },
    {
        "id": "NG1003",
        "name": "云元数据 SSRF",
        "description": "拦截云平台内网元数据地址和元数据路径探测。",
        "category": "SSRF",
        "severity": "high",
        "enabled": True,
        "action": "block",
        "high_risk": True,
    },
    {
        "id": "NG2001",
        "name": "SQL 注入特征",
        "description": "拦截常见 SQL 注入特征，记录命中规则供进一步分析。",
        "category": "SQL 注入",
        "severity": "medium",
        "enabled": True,
        "action": "block",
        "high_risk": False,
    },
    {
        "id": "NG2002",
        "name": "XSS 特征",
        "description": "拦截常见脚本和事件处理器特征。",
        "category": "XSS",
        "severity": "medium",
        "enabled": True,
        "action": "block",
        "high_risk": False,
    },
    {
        "id": "NG2003",
        "name": "扫描器 User-Agent",
        "description": "拦截常见自动化扫描器的 User-Agent。",
        "category": "扫描器",
        "severity": "low",
        "enabled": True,
        "action": "block",
        "high_risk": False,
    },
]


_SENSITIVE = re.compile(
    r"(?:^|/)(?:\.env(?:\.[A-Za-z0-9_.-]+)?|\.git(?:/.*)?|\.git-credentials|"
    r"\.aws(?:/.*)?|\.azure(?:/.*)?|\.vscode(?:/.*)?|"
    r"wp-config\.php(?:\.(?:bak|old|swp)|~)?|terraform\.tfstate|"
    r"docker-compose\.ya?ml|serverless\.ya?ml|application\.ya?ml|config\.json)(?:[/?]|$)",
    re.IGNORECASE,
)
_TRAVERSAL = re.compile(
    r"(?:\.\./|\\\.\.\\|/etc/(?:passwd|shadow)|/proc/(?:self|1)/(?:environ|cmdline))",
    re.IGNORECASE,
)
_METADATA = re.compile(
    r"(?:169\.254\.169\.254|metadata\.google\.internal|latest/meta-data|latest/user-data)",
    re.IGNORECASE,
)
_SQLI = re.compile(
    r"(?:\bunion\s+select\b|\bor\s+1\s*=\s*1\b|\bsleep\s*\(|information_schema)",
    re.IGNORECASE,
)
_XSS = re.compile(r"(?:<script\b|javascript:|onerror\s*=|onload\s*=)", re.IGNORECASE)
_SCANNER = re.compile(r"(?:sqlmap|nikto|nmap|masscan|zgrab|wpscan)", re.IGNORECASE)
_DANGEROUS_REGEX = re.compile(
    r"(?:\([^)]*[+*][^)]*\)[+*]|\([^)]*[+*][^)]*\)\{|\.\*.*\.\*|"
    r"\(\.\+\)\+|\\[1-9])"
)

BODY_MAX_BYTES = 1024 * 1024


def validate_interface_whitelist(entries):
    """Validate full HTTP(S) URLs used for ordinary-rule bypasses.

    Matching intentionally ignores the URL scheme.  A root URL is stored as
    a host-wide prefix because the aaPanel UI uses it to represent all paths
    on that site.  Query strings and fragments are rejected because the
    runtime matches only the normalized URI path.
    """

    if entries is None:
        return []
    if not isinstance(entries, (list, tuple)):
        raise ValidationError("接口白名单必须是数组")
    result = []
    seen = set()
    for index, item in enumerate(entries, 1):
        prefix = "接口白名单第 %s 行" % index
        if not isinstance(item, dict):
            raise ValidationError("%s 必须是对象" % prefix)
        match = str(item.get("match", "")).strip().lower()
        if match not in {"exact", "prefix"}:
            raise ValidationError("%s 类型必须是 exact 或 prefix" % prefix)
        raw_url = validate_text(item.get("url"), "%s URL" % prefix, 2048)
        if any(character in raw_url for character in "\x00\r\n{};\""):
            raise ValidationError("%s 包含非法字符" % prefix)
        try:
            parsed = urlsplit(raw_url)
            scheme = parsed.scheme.lower()
            host = parsed.hostname
            port = parsed.port
        except ValueError as exc:
            raise ValidationError("%s 格式无效" % prefix) from exc
        if scheme not in {"http", "https"} or not host:
            raise ValidationError("%s 必须是 http:// 或 https:// 完整 URL" % prefix)
        if parsed.username is not None or parsed.password is not None:
            raise ValidationError("%s 不允许包含用户名或密码" % prefix)
        if parsed.query or parsed.fragment:
            raise ValidationError("%s 不允许包含查询参数或片段" % prefix)
        path = parsed.path or "/"
        if not path.startswith("/") or len(path) > 1024:
            raise ValidationError("%s 路径无效" % prefix)
        if any(character in path for character in "\x00\r\n{};\""):
            raise ValidationError("%s 路径包含非法字符" % prefix)
        host = host.rstrip(".").lower()
        if not host or any(character.isspace() for character in host):
            raise ValidationError("%s 域名无效" % prefix)
        try:
            host_key = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValidationError("%s 域名无效" % prefix) from exc
        # A host-wide root URL is deliberately a prefix entry.  This keeps
        # the UI's https://example.com form useful without making a root
        # exact entry accidentally mean only the homepage.
        whole_host = path == "/"
        if whole_host:
            match = "prefix"
        if port is not None and not 1 <= int(port) <= 65535:
            raise ValidationError("%s 端口无效" % prefix)
        key = (match, host_key, port, path, whole_host)
        if key in seen:
            continue
        seen.add(key)
        result.append(
            {
                "match": match,
                "url": raw_url,
                "host": host_key,
                "port": int(port) if port is not None else None,
                "path": path,
                "whole_host": whole_host,
            }
        )
    return result


def interface_whitelist_matches(entries, host, port, uri):
    """Return whether a request host/port/path matches a validated entry."""

    request_host = str(host or "").rstrip(".").lower()
    request_path = str(uri or "/").split("?", 1)[0] or "/"
    try:
        request_port = int(port)
    except (TypeError, ValueError):
        request_port = None
    for entry in entries or ():
        if not isinstance(entry, dict) or str(entry.get("host", "")).lower() != request_host:
            continue
        expected_port = entry.get("port")
        if expected_port is not None and request_port != int(expected_port):
            continue
        path = str(entry.get("path") or "/")
        if entry.get("whole_host") or (str(entry.get("match")) == "prefix" and path == "/"):
            return True
        if str(entry.get("match")) == "exact" and request_path == path:
            return True
        if str(entry.get("match")) == "prefix":
            boundary = path if path.endswith("/") else path + "/"
            if request_path == path or request_path.startswith(boundary):
                return True
    return False


def _decode(value):
    text = str(value or "")
    for _ in range(2):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded
    return text.replace("\\", "/")


def is_text_content_type(content_type):
    """Return whether a request body is safe for bounded text inspection."""

    value = str(content_type or "").split(";", 1)[0].strip().lower()
    return bool(
        value.startswith("text/")
        or value in {"application/json", "application/x-www-form-urlencoded", "application/xml"}
        or value.endswith("+json")
        or value.endswith("+xml")
    )


def evaluate_body(body, content_type, rules=None):
    """Evaluate a bounded text body using the same ordinary rule patterns."""

    if not is_text_content_type(content_type):
        return {"matched": False, "action": "allow", "status": 200}
    text = str(body or "")
    if len(text.encode("utf-8", errors="ignore")) > BODY_MAX_BYTES:
        return {"matched": False, "action": "allow", "status": 200, "skipped": "over_limit"}
    decoded = _decode(text)
    configured = _rule_map(rules or DEFAULT_RULES)
    checks = [
        ("NG2001", any(_SQLI.search(candidate) for candidate in (text, decoded))),
        ("NG2002", any(_XSS.search(candidate) for candidate in (text, decoded))),
    ]
    for rule_id, matched in checks:
        rule = configured.get(rule_id)
        if not matched or not rule or not rule.get("enabled", True):
            continue
        action = str(rule.get("action") or "monitor").lower()
        blocking = action in {"deny", "403", "block"}
        return {
            "matched": True,
            "rule_id": rule_id,
            "rule_name": rule.get("name", rule_id),
            "action": "block" if blocking else "monitor",
            "status": 403 if blocking else 200,
            "high_risk": False,
        }
    return {"matched": False, "action": "allow", "status": 200}


def _rule_map(rules):
    return {str(rule.get("id")): rule for rule in rules if isinstance(rule, dict)}


def evaluate_request(path, query, context=None, rules=None):
    """Evaluate bounded request metadata; never reads body or response data."""

    context = context if isinstance(context, dict) else {}
    rules = rules or DEFAULT_RULES
    configured = _rule_map(rules)
    decoded_path = _decode(path)
    decoded_query = _decode(query)
    combined = decoded_path + "?" + decoded_query

    checks = [
        ("NG1001", _SENSITIVE.search(decoded_path) or _SENSITIVE.search(combined)),
        ("NG1002", _TRAVERSAL.search(combined)),
        ("NG1003", _METADATA.search(combined)),
        ("NG2001", _SQLI.search(combined)),
        ("NG2002", _XSS.search(combined)),
        ("NG2003", _SCANNER.search(str(context.get("user_agent") or ""))),
    ]
    for rule_id, matched in checks:
        rule = configured.get(rule_id)
        if not matched or not rule or not rule.get("enabled", True):
            continue
        high_risk = bool(rule.get("high_risk"))
        if context.get("whitelisted") and not high_risk:
            continue
        action = str(rule.get("action") or "monitor").lower()
        return {
            "matched": True,
            "rule_id": rule_id,
            "rule_name": rule.get("name", rule_id),
            "action": "block" if action in {"deny", "403", "block"} else "monitor",
            "status": 403 if action in {"deny", "403", "block"} else 200,
            "high_risk": high_risk,
        }
    return {"matched": False, "action": "allow", "status": 200, "high_risk": False}


def validate_custom_rule(rule):
    if not isinstance(rule, dict):
        raise PolicyError("custom rule must be an object")
    match = validate_text(rule.get("match"), "match", 32).lower()
    allowed = {"uri_contains", "uri_regex", "query_contains", "method", "ip", "user_agent", "header", "host"}
    if match not in allowed:
        raise PolicyError("unsupported custom match")
    pattern = validate_text(rule.get("pattern"), "pattern", 512)
    if any(character in pattern for character in "\r\n;{}"):
        raise PolicyError("pattern contains forbidden directive characters")
    if match == "uri_regex":
        if _DANGEROUS_REGEX.search(pattern):
            raise PolicyError("regex has a potentially catastrophic shape")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise PolicyError("invalid regex") from exc
    header_name = ""
    if match == "header":
        header_name = validate_text(rule.get("header") or "x-requested-with", "header", 64).lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", header_name):
            raise PolicyError("invalid header name")
    action = str(rule.get("action") or "monitor").lower()
    if action not in {"allow", "monitor", "block", "403", "404", "444", "429"}:
        raise PolicyError("unsupported custom action")
    return {
        "id": validate_text(rule.get("id") or "custom", "id", 64),
        "match": match,
        "pattern": pattern,
        "action": action,
        "enabled": bool(rule.get("enabled", True)),
        "severity": str(rule.get("severity") or "medium").lower(),
        "header": header_name,
    }


def native_patterns():
    """Return conservative PCRE snippets for generated server-level checks."""

    return {
        "sensitive": r"(?:^|/)(?:\.env(?:[./?]|$)|\.git(?:/|$)|\.git-credentials(?:[/?]|$)|\.aws(?:/|$)|\.azure(?:/|$)|\.vscode(?:/|$)|wp-config\.php(?:\.(?:bak|old|swp)|~)?(?:[/?]|$)|terraform\.tfstate(?:[/?]|$)|docker-compose\.ya?ml(?:[/?]|$)|serverless\.ya?ml(?:[/?]|$)|application\.ya?ml(?:[/?]|$)|config\.json(?:[/?]|$))",
        "traversal": r"(?:\.\./|%2e%2e|%2fetc%2f(?:passwd|shadow)|/etc/(?:passwd|shadow)|/proc/(?:self|1)/(?:environ|cmdline))",
        "metadata": r"(?:169\.254\.169\.254|metadata\.google\.internal|latest/meta-data|latest/user-data)",
        "sqli": r"(?:\bunion(?:\s|%20|\+)+select\b|\bor(?:\s|%20|\+)+1(?:\s|%20|\+)*(?:=|%3d)(?:\s|%20|\+)*1\b|\bsleep(?:\s|%20|\+)*\(|\bsleep(?:\s|%20|\+)*%28|information(?:_|%5f)schema)",
        "xss": r"(?:<script\b|%3cscript\b|javascript(?::|%3a)|on(?:error|load)(?:\s|%20|\+)*(?:=|%3d))",
        "scanner": r"(?:sqlmap|nikto|nmap|masscan|zgrab|wpscan)",
    }
