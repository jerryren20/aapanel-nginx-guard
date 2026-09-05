"""Bounded log retention helpers."""

from __future__ import annotations

import datetime
import os
import shutil
import time
from pathlib import Path


DEFAULT_LOG_MAX_BYTES = 20 * 1024 * 1024
DEFAULT_LOG_KEEP_DAYS = 7
DEFAULT_LOG_MAX_FILES = 100
DEFAULT_LOG_MAX_TOTAL_BYTES = 100 * 1024 * 1024

BLOCK_ACTIONS = {"block", "deny", "rate_limit", "403", "404", "429", "444"}
BLOCK_STATUS_CODES = {403, 429, 444}


def is_blocked_event(row) -> bool:
    """Return whether a log row represents an actual WAF block.

    Nginx Guard has emitted a few log shapes over its lifetime.  Prefer the
    explicit action/blocked fields, keep MONITOR rows out of the blocked view,
    and only use the rule-plus-status combination as a legacy fallback.
    """

    if not isinstance(row, dict):
        return False
    if row.get("blocked") is True:
        return True
    if row.get("blocked") is False:
        return False
    action = str(row.get("action") or "").strip().lower()
    if action in BLOCK_ACTIONS:
        return True
    if action in {"monitor", "allow", "pass", "open"}:
        return False
    rule_id = str(row.get("rule_id") or row.get("rule") or "").strip()
    try:
        status = int(row.get("status"))
    except (TypeError, ValueError, OverflowError):
        status = None
    return bool(rule_id and status in BLOCK_STATUS_CODES)


def normalize_event(row):
    """Return a compatibility-shaped event row for the panel log view."""

    if not isinstance(row, dict):
        return {}
    normalized = dict(row)
    normalized["cfip"] = str(normalized.get("cfip") or "")
    normalized["client_ip"] = str(
        normalized.get("client_ip") or normalized.get("remote_addr") or ""
    )
    normalized["content_type"] = str(
        normalized.get("content_type") or normalized.get("content-type") or ""
    )
    normalized["content_length"] = str(
        normalized.get("content_length") or normalized.get("content-length") or ""
    )
    normalized["blocked"] = is_blocked_event(normalized)
    return normalized


def _copytruncate(path, rotated):
    """Copy a log and truncate the active inode in place.

    Nginx keeps the active access-log file descriptor open.  Renaming the
    active file would leave Nginx writing an untracked inode, so rotation uses
    the same copy-then-truncate semantics as logrotate's copytruncate mode.
    """

    if rotated.exists() or rotated.is_symlink():
        raise FileExistsError(str(rotated))
    try:
        with path.open("rb") as source, rotated.open("xb") as destination:
            shutil.copyfileobj(source, destination, length=1024 * 1024)
            destination.flush()
            os.fsync(destination.fileno())
        try:
            os.chmod(str(rotated), path.stat().st_mode & 0o777)
        except OSError:
            pass
        with path.open("r+b") as active:
            active.truncate(0)
            active.flush()
            os.fsync(active.fileno())
    except Exception:
        try:
            rotated.unlink()
        except OSError:
            pass
        raise


def rotate_jsonl(
    path,
    max_bytes=DEFAULT_LOG_MAX_BYTES,
    keep_days=DEFAULT_LOG_KEEP_DAYS,
    max_files=DEFAULT_LOG_MAX_FILES,
    max_total_bytes=DEFAULT_LOG_MAX_TOTAL_BYTES,
    now=None,
):
    path = Path(path)
    now = time.time() if now is None else float(now)
    result = {"rotated": False, "removed": 0, "path": str(path)}
    if path.is_symlink() or not path.is_file():
        return result
    try:
        size_limit = int(max_bytes)
    except (TypeError, ValueError, OverflowError):
        size_limit = DEFAULT_LOG_MAX_BYTES
    # A non-positive limit is used internally to rotate an aged active file
    # even when it is smaller than the normal size threshold.
    if size_limit > 0 and path.stat().st_size <= max(1, size_limit):
        _prune(path, keep_days, max_files, max_total_bytes, now, result)
        return result
    stamp = datetime.datetime.utcfromtimestamp(now).strftime("%Y%m%d%H%M%S")
    rotated = path.with_name(path.name + "." + stamp)
    suffix = 1
    while rotated.exists():
        rotated = path.with_name(path.name + ".%s-%s" % (stamp, suffix))
        suffix += 1
    _copytruncate(path, rotated)
    result["rotated"] = True
    result["rotated_path"] = str(rotated)
    _prune(path, keep_days, max_files, max_total_bytes, now, result)
    return result


def _prune(path, keep_days, max_files, max_total_bytes, now, result):
    try:
        keep_days = max(1, int(keep_days))
        max_files = max(0, int(max_files))
    except (TypeError, ValueError):
        keep_days, max_files = DEFAULT_LOG_KEEP_DAYS, DEFAULT_LOG_MAX_FILES
    try:
        max_total_bytes = max(1, int(max_total_bytes))
    except (TypeError, ValueError):
        max_total_bytes = DEFAULT_LOG_MAX_TOTAL_BYTES
    candidates = sorted(
        (item for item in path.parent.glob(path.name + ".*") if item.is_file() and not item.is_symlink()),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    cutoff = now - keep_days * 86400
    kept = []
    for item in candidates:
        remove = item.stat().st_mtime < cutoff or len(kept) >= max_files
        if remove:
            try:
                item.unlink()
                result["removed"] += 1
            except OSError:
                pass
        else:
            kept.append(item)

    try:
        total = path.stat().st_size + sum(item.stat().st_size for item in kept)
    except OSError:
        total = sum(item.stat().st_size for item in kept if item.is_file())
    for item in reversed(kept):
        if total <= max_total_bytes:
            break
        try:
            size = item.stat().st_size
            item.unlink()
            total -= size
            result["removed"] += 1
        except OSError:
            continue


def cleanup_jsonl_directory(
    directory,
    max_bytes=DEFAULT_LOG_MAX_BYTES,
    keep_days=DEFAULT_LOG_KEEP_DAYS,
    max_files=DEFAULT_LOG_MAX_FILES,
    max_total_bytes=DEFAULT_LOG_MAX_TOTAL_BYTES,
    now=None,
):
    """Rotate owned event logs and enforce one total directory budget."""

    directory = Path(directory)
    now = time.time() if now is None else float(now)
    results = []
    if not directory.is_dir():
        return results
    try:
        normalized_keep_days = max(1, int(keep_days))
    except (TypeError, ValueError, OverflowError):
        normalized_keep_days = DEFAULT_LOG_KEEP_DAYS
    try:
        normalized_total_bytes = max(1, int(max_total_bytes))
    except (TypeError, ValueError, OverflowError):
        normalized_total_bytes = DEFAULT_LOG_MAX_TOTAL_BYTES
    cutoff = now - normalized_keep_days * 86400

    # Keep the active filename for Nginx, but do not let a completely idle
    # file survive the age budget forever.  Rotation is still plugin-owned.
    for path in sorted(directory.glob("events-site-*.jsonl")):
        if path.is_file() and not path.is_symlink():
            try:
                if path.stat().st_size and path.stat().st_mtime < cutoff:
                    results.append(
                        rotate_jsonl(
                            path,
                            max_bytes=0,
                            keep_days=normalized_keep_days,
                            max_files=max_files,
                            max_total_bytes=normalized_total_bytes,
                            now=now,
                        )
                    )
            except OSError:
                pass
    for path in sorted(directory.glob("events-site-*.jsonl")):
        if path.is_file() and not path.is_symlink():
            results.append(
                rotate_jsonl(
                    path,
                    max_bytes=max_bytes,
                    keep_days=keep_days,
                    max_files=max_files,
                    max_total_bytes=normalized_total_bytes,
                    now=now,
                )
            )

    def owned_candidates():
        return [
            path
            for path in directory.glob("events-site-*.jsonl*")
            if path.is_file() and not path.is_symlink()
        ]

    def remove_oldest_rotated(total, rotated_paths):
        removed_count = 0
        for rotated_path in rotated_paths:
            if total <= normalized_total_bytes:
                break
            try:
                size = rotated_path.stat().st_size
                rotated_path.unlink()
                total -= size
                removed_count += 1
            except OSError:
                pass
        return total, removed_count

    candidates = owned_candidates()
    current = [path for path in candidates if path.name.endswith(".jsonl")]
    rotated = sorted(
        [path for path in candidates if path not in current],
        key=lambda path: path.stat().st_mtime,
    )
    removed = 0
    for path in rotated:
        if path.stat().st_mtime < cutoff:
            try:
                path.unlink()
                removed += 1
            except OSError:
                pass
    # Enforce the directory budget across both active and rotated files.  If
    # rotated files are not enough, copytruncate the oldest active files and
    # then remove their rotated copies; this preserves each active pathname
    # while still making the hard total bound effective.
    while True:
        candidates = owned_candidates()
        current = [path for path in candidates if path.name.endswith(".jsonl")]
        rotated = sorted(
            [path for path in candidates if path not in current],
            key=lambda path: path.stat().st_mtime,
        )
        total = sum(path.stat().st_size for path in candidates)
        total, count = remove_oldest_rotated(total, rotated)
        removed += count
        if total <= normalized_total_bytes:
            break
        active = []
        for path in current:
            try:
                if path.stat().st_size > 0:
                    active.append(path)
            except OSError:
                pass
        if not active:
            break
        active.sort(key=lambda path: path.stat().st_mtime)
        try:
            results.append(
                rotate_jsonl(
                    active[0],
                    max_bytes=0,
                    keep_days=normalized_keep_days,
                    max_files=max_files,
                    max_total_bytes=normalized_total_bytes,
                    now=now,
                )
            )
        except OSError:
            break
    if removed:
        results.append({"rotated": False, "removed": removed, "path": str(directory)})
    return results
