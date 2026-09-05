"""Security-sensitive input helpers for the Nginx Guard aaPanel plugin."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qsl, urlencode


class ValidationError(ValueError):
    """Raised when user-controlled plugin input is invalid."""


_SITE_ID_RE = re.compile(r"^[1-9][0-9]{0,18}$")
_SECRET_KEY_RE = re.compile(
    r"(?:token|password|passwd|secret|authorization|auth|signature|sign|"
    r"api[_-]?key|access[_-]?key|private[_-]?key|cookie|session|credential|"
    r"captcha|code)",
    re.IGNORECASE,
)


def normalize_site_id(value) -> str:
    """Return a safe aaPanel numeric site id."""

    text = str(value).strip()
    if not _SITE_ID_RE.fullmatch(text):
        raise ValidationError("site id must be a positive numeric id")
    return text


def validate_ip_or_cidr(value) -> str:
    """Validate and canonicalize one IP address or network."""

    text = str(value).strip()
    if not text or len(text) >  CIDR_MAX_LENGTH:
        raise ValidationError("invalid IP address or CIDR")
    try:
        if "/" in text:
            return str(ipaddress.ip_network(text, strict=False))
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise ValidationError("invalid IP address or CIDR") from exc


CIDR_MAX_LENGTH = 79


def sanitize_query(query, max_length: int = 2048) -> str:
    """Redact secrets and cap a query string before it reaches a log."""

    raw = str(query or "")
    if max_length < 64:
        max_length = 64
    try:
        pairs = parse_qsl(raw[: max_length * 2], keep_blank_values=True, strict_parsing=False)
        safe_pairs = []
        for key, value in pairs:
            safe_value = "[REDACTED]" if _SECRET_KEY_RE.search(key) else value
            safe_pairs.append((key[:128], safe_value[:512]))
        result = urlencode(safe_pairs, doseq=True).replace("%5BREDACTED%5D", "[REDACTED]")
    except (UnicodeError, ValueError):
        result = raw
    if len(result) > max_length:
        return result[: max_length - 3] + "..."
    return result


def validate_text(value, field: str, max_length: int, allow_empty: bool = False) -> str:
    """Normalize bounded text fields used by the plugin API."""

    text = str(value or "").strip()
    if not text and not allow_empty:
        raise ValidationError("%s is required" % field)
    if len(text) > max_length:
        raise ValidationError("%s is too long" % field)
    if "\x00" in text:
        raise ValidationError("%s contains a NUL byte" % field)
    return text


def validate_streaming_path(value) -> str:
    """Validate a path that may be copied into generated Nginx comments."""

    text = validate_text(value, "流式路径", 256)
    if not text.startswith("/"):
        raise ValidationError("流式路径必须以 / 开头")
    if any(
        ord(character) < 32
        or ord(character) == 127
        or character in "#;{}\"'\\"
        for character in text
    ):
        raise ValidationError("流式路径包含非法字符")
    return text


def safe_filename(value: str) -> str:
    """Allow a conservative filename component for generated fragments."""

    text = validate_text(value, "filename", 128)
    if text in {".", ".."} or not re.fullmatch(r"[\w.-]+", text, re.UNICODE):
        raise ValidationError("unsafe filename")
    return text
