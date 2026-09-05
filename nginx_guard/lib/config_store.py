"""Atomic desired-state storage for Nginx Guard."""

from __future__ import annotations

import copy
import json
import os
import tempfile
from pathlib import Path

from .cloudflare import DEFAULT_CLOUDFLARE_NETWORKS, normalize_cloudflare_config
from .security import ValidationError, normalize_site_id


DEFAULT_CONFIG = {
    "schema_version": 2,
    "engine_enabled": False,
    "preferred_engine": "auto",
    "runtime_failure_policy": "open",
    "sites": {},
    "custom_rules": [],
    "rule_overrides": {},
    "cloudflare": {
        "enabled": False,
        "official_networks": list(DEFAULT_CLOUDFLARE_NETWORKS),
        "manual_networks": [],
        "networks": list(DEFAULT_CLOUDFLARE_NETWORKS),
        "updated_at": 0,
    },
    "log_rotation": {
        "max_bytes": 20 * 1024 * 1024,
        "keep_days": 7,
        "max_files": 100,
        "max_total_bytes": 100 * 1024 * 1024,
    },
}


class ConfigStore:
    """Persist desired state without exposing partially-written JSON."""

    def __init__(self, root):
        self.root = Path(root)
        self.config_root = self.root / "config"
        self.sites_root = self.config_root / "sites"
        self.config_root.mkdir(parents=True, exist_ok=True)
        self.sites_root.mkdir(parents=True, exist_ok=True)
        self.desired_path = self.config_root / "desired.json"

    def _atomic_write_json(self, path: Path, value) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(
            prefix=".%s." % path.name,
            suffix=".tmp",
            dir=str(path.parent),
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, str(path))
        finally:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass

    def _defaults(self):
        return copy.deepcopy(DEFAULT_CONFIG)

    def _migrate(self, value):
        defaults = self._defaults()
        result = copy.deepcopy(value) if isinstance(value, dict) else {}
        result.setdefault("engine_enabled", defaults["engine_enabled"])
        result.setdefault("preferred_engine", defaults["preferred_engine"])
        result.setdefault("runtime_failure_policy", defaults["runtime_failure_policy"])
        result["sites"] = result.get("sites") if isinstance(result.get("sites"), dict) else {}
        result["custom_rules"] = result.get("custom_rules") if isinstance(result.get("custom_rules"), list) else []
        result["rule_overrides"] = result.get("rule_overrides") if isinstance(result.get("rule_overrides"), dict) else {}
        result["cloudflare"] = normalize_cloudflare_config(result.get("cloudflare"))
        rotation = result.get("log_rotation")
        rotation = rotation if isinstance(rotation, dict) else {}

        def bounded_int(key, minimum, maximum=None):
            fallback = defaults["log_rotation"][key]
            try:
                parsed = int(rotation.get(key, fallback))
            except (TypeError, ValueError, OverflowError):
                parsed = fallback
            parsed = max(minimum, parsed)
            if maximum is not None:
                parsed = min(maximum, parsed)
            return parsed

        result["log_rotation"] = {
            "max_bytes": bounded_int("max_bytes", 1024, 20 * 1024 * 1024),
            "keep_days": bounded_int("keep_days", 1, 365),
            "max_files": bounded_int("max_files", 1, 1000),
            "max_total_bytes": bounded_int("max_total_bytes", 1024, 100 * 1024 * 1024),
        }
        result["schema_version"] = 2
        return result

    def load_desired(self):
        if not self.desired_path.is_file():
            return self._defaults()
        try:
            with self.desired_path.open("r", encoding="utf-8") as handle:
                value = json.load(handle)
            if not isinstance(value, dict):
                raise ValueError("desired state must be an object")
            return self._migrate(value)
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return self._defaults()

    def save_desired(self, desired) -> dict:
        if not isinstance(desired, dict):
            raise ValidationError("desired state must be an object")
        value = self._migrate(copy.deepcopy(desired))
        if not isinstance(value.get("sites"), dict):
            raise ValidationError("sites must be an object")
        self._atomic_write_json(self.desired_path, value)
        return value

    def save_site_policy(self, site_id, policy) -> dict:
        normalized_id = normalize_site_id(site_id)
        if not isinstance(policy, dict):
            raise ValidationError("site policy must be an object")
        filename = self.sites_root / ("site-%s.json" % normalized_id)
        self._atomic_write_json(filename, copy.deepcopy(policy))
        desired = self.load_desired()
        desired.setdefault("sites", {})[normalized_id] = copy.deepcopy(policy)
        self.save_desired(desired)
        return policy

    def load_site_policy(self, site_id):
        normalized_id = normalize_site_id(site_id)
        filename = self.sites_root / ("site-%s.json" % normalized_id)
        try:
            with filename.open("r", encoding="utf-8") as handle:
                value = json.load(handle)
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return self.load_desired().get("sites", {}).get(normalized_id, {})

    def list_site_policies(self):
        value = self.load_desired().get("sites", {})
        return value if isinstance(value, dict) else {}
