"""aaPanel controller for Nginx Guard.

The controller stores desired state first. Nginx is only changed by the
explicit apply transaction, which backs up files, runs nginx -t, and reloads
only after validation succeeds.
"""

from __future__ import annotations

import json
import heapq
import os
import subprocess
import time
import copy
from functools import wraps
from pathlib import Path

try:
    import public  # type: ignore
except ImportError:  # local tests and package inspection
    public = None

try:
    from .lib.cloudflare import (
        fetch_official_networks,
        lookup_network_membership,
        normalize_cloudflare_config,
    )
    from .lib.config_store import ConfigStore
    from .lib.analysis import analyze_jsonl, analysis_to_csv
    from .lib.logs import cleanup_jsonl_directory, iter_log_lines, parse_event_time, safe_event
    from .lib.metrics import aggregate_jsonl
    from .lib.nginx import (
        LocalNginxRunner,
        NginxCommandError,
        NginxConfigManager,
        detect_limit_req_dry_run,
        detect_lua_module,
        detect_real_ip_module,
    )
    from .lib.policy import (
        DEFAULT_RULES,
        PolicyError,
        normalize_rate_paths,
        validate_custom_rule,
        validate_interface_whitelist,
    )
    from .lib.security import (
        ValidationError,
        normalize_site_id,
        validate_ip_or_cidr,
        validate_streaming_path,
        validate_text,
    )
except ImportError:
    from lib.cloudflare import (
        fetch_official_networks,
        lookup_network_membership,
        normalize_cloudflare_config,
    )
    from lib.config_store import ConfigStore
    from lib.analysis import analyze_jsonl, analysis_to_csv
    from lib.logs import cleanup_jsonl_directory, iter_log_lines, parse_event_time, safe_event
    from lib.metrics import aggregate_jsonl
    from lib.nginx import (
        LocalNginxRunner,
        NginxCommandError,
        NginxConfigManager,
        detect_limit_req_dry_run,
        detect_lua_module,
        detect_real_ip_module,
    )
    from lib.policy import DEFAULT_RULES, PolicyError, normalize_rate_paths, validate_custom_rule, validate_interface_whitelist
    from lib.security import (
        ValidationError,
        normalize_site_id,
        validate_ip_or_cidr,
        validate_streaming_path,
        validate_text,
    )


PLUGIN_ROOT = Path("/www/server/panel/plugin/nginx_guard")
DATA_ROOT = Path("/www/server/nginx_guard")
NGINX_CONF = Path("/www/server/nginx/conf/nginx.conf")
VHOST_DIR = Path("/www/server/panel/vhost/nginx")
NGINX_BIN = Path("/www/server/nginx/sbin/nginx")


def _value(args, key, default=None):
    if args is None:
        return default
    if isinstance(args, dict):
        return args.get(key, default)
    getter = getattr(args, "get", None)
    if callable(getter):
        try:
            return getter(key, default)
        except TypeError:
            return getter(key)
    return getattr(args, key, default)


def _json_response(status, msg="", data=None):
    return {"status": bool(status), "msg": str(msg), "data": data if data is not None else {}}


def api_errors(function):
    """Turn malformed panel input into a JSON error instead of a traceback."""

    @wraps(function)
    def wrapped(self, get=None, *args, **kwargs):
        try:
            return function(self, get, *args, **kwargs)
        except (ValidationError, NginxCommandError, OSError, TypeError, ValueError) as exc:
            return _json_response(False, str(exc) or "请求参数无效")

    return wrapped


class nginx_guard_main:
    """aaPanel plugin controller; class name follows the required filename."""

    def __init__(self):
        self.store = ConfigStore(DATA_ROOT)

    def _check(self, args=None):
        """Use aaPanel's session checker when present; fail closed in panel."""

        if public is None:
            return True
        checker = getattr(public, "check_session", None)
        if callable(checker):
            try:
                try:
                    result = checker(args)
                except TypeError:
                    result = checker()
                return result is not False
            except Exception:
                return False
        return True

    def _guard(self, args=None):
        if not self._check(args):
            return _json_response(False, "会话已失效，请重新登录")
        return None

    @staticmethod
    def _safe_json(value):
        try:
            return json.loads(value) if isinstance(value, str) else value
        except (TypeError, ValueError) as exc:
            raise ValidationError("JSON 参数无效") from exc

    def _panel_sites(self):
        if public is None:
            return []
        try:
            rows = public.M("sites").field("id,name,path,status,ps").select()
            return [row for row in (rows or []) if isinstance(row, dict)]
        except Exception:
            return None

    def _known_site(self, site_id):
        normalized = normalize_site_id(site_id)
        rows = self._panel_sites()
        if rows is None:
            return None
        for row in rows:
            if str(row.get("id")) == normalized:
                return {
                    "id": normalized,
                    "name": validate_text(row.get("name") or normalized, "domain", 255),
                    "path": str(row.get("path") or ""),
                    "status": row.get("status", 1),
                    "ps": row.get("ps", ""),
                }
        # A panel-less local test is allowed to inspect and configure numeric
        # ids; a real aaPanel instance always supplies the site row above.
        if public is None:
            return {"id": normalized, "name": normalized, "path": "", "status": 1, "ps": ""}
        return None

    def _manager(self):
        runner = LocalNginxRunner(str(NGINX_BIN), str(NGINX_CONF))
        return NginxConfigManager(NGINX_CONF, VHOST_DIR, DATA_ROOT, runner=runner)

    def _nginx_v_output(self):
        try:
            result = subprocess.run(
                [str(NGINX_BIN), "-V"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
            return result.stdout or ""
        except OSError:
            return ""

    def _wiring_status(self):
        files = []
        try:
            files.extend(
                NginxConfigManager(NGINX_CONF, VHOST_DIR, DATA_ROOT).config_graph_paths()
            )
        except NginxCommandError:
            pass
        if NGINX_CONF.is_file():
            files.append(NGINX_CONF)
        if VHOST_DIR.is_dir():
            files.extend(VHOST_DIR.glob("*.conf"))
        seen = set()
        unique_files = []
        for path in files:
            key = str(path.absolute()).casefold()
            if key not in seen:
                seen.add(key)
                unique_files.append(path)
        return any(
            path.is_file()
            and not path.is_symlink()
            and "NGINX_GUARD" in path.read_text(encoding="utf-8", errors="replace")
            for path in unique_files
        )

    def get_status(self, get=None):
        denied = self._guard(get)
        if denied:
            return denied
        desired = self.store.load_desired()
        nginx_v_output = self._nginx_v_output()
        data = {
            "version": "1.0.15",
            "engine_enabled": bool(desired.get("engine_enabled", False)),
            "preferred_engine": desired.get("preferred_engine", "auto"),
            "runtime_failure_policy": desired.get("runtime_failure_policy", "open"),
            "lua_available": detect_lua_module(nginx_v_output),
            "real_ip_available": detect_real_ip_module(nginx_v_output),
            "nginx_config_exists": NGINX_CONF.is_file(),
            "wiring_active": self._wiring_status(),
            "backup_dir": str(DATA_ROOT / "backup"),
        }
        return _json_response(True, "ok", data)

    @api_errors
    def list_sites(self, get=None):
        denied = self._guard(get)
        if denied:
            return denied
        policies = self.store.list_site_policies()
        panel_rows = self._panel_sites()
        if public is not None and panel_rows is None:
            return _json_response(False, "无法读取 aaPanel 网站列表")
        output = []
        for row in panel_rows or []:
            site_id = str(row.get("id", ""))
            if not site_id.isdigit():
                continue
            policy = policies.get(site_id, {})
            output.append(
                {
                    "id": site_id,
                    "name": row.get("name", site_id),
                    "type": "PHP" if str(row.get("project_type", "")).lower() == "php" else "Site",
                    "status": row.get("status", 1),
                    "mode": policy.get("mode", "OFF"),
                    "engine": policy.get("engine", "auto"),
                    "rate": policy.get("rate_limit", 5),
                    "streaming_paths": policy.get("streaming_paths", []),
                }
            )
        return _json_response(True, "ok", output)

    @api_errors
    def get_site_policy(self, get=None):
        denied = self._guard(get)
        if denied:
            return denied
        site_id = normalize_site_id(_value(get, "site_id"))
        if self._known_site(site_id) is None:
            return _json_response(False, "网站不存在或无法由 aaPanel 验证")
        return _json_response(True, "ok", self.store.load_site_policy(site_id))

    @api_errors
    def save_global(self, get=None):
        denied = self._guard(get)
        if denied:
            return denied
        desired = self.store.load_desired()
        enabled = str(_value(get, "engine_enabled", desired.get("engine_enabled", False))).lower()
        engine = str(_value(get, "preferred_engine", desired.get("preferred_engine", "auto"))).lower()
        if engine not in {"auto", "native", "lua"}:
            return _json_response(False, "引擎只能是 auto、native 或 lua")
        desired["engine_enabled"] = enabled in {"1", "true", "on", "yes"}
        desired["preferred_engine"] = engine
        desired["runtime_failure_policy"] = "open"
        self.store.save_desired(desired)
        return _json_response(True, "配置已保存，请点击应用配置")

    @api_errors
    def save_site_policy(self, get=None):
        denied = self._guard(get)
        if denied:
            return denied
        site_id = normalize_site_id(_value(get, "site_id"))
        site = self._known_site(site_id)
        if site is None:
            return _json_response(False, "网站不存在或无法由 aaPanel 验证")
        policy = self._safe_json(_value(get, "policy", "{}"))
        if not isinstance(policy, dict):
            return _json_response(False, "站点配置必须是对象")
        mode = str(policy.get("mode", "MONITOR")).upper()
        engine = str(policy.get("engine", "auto")).lower()
        if mode not in {"OFF", "MONITOR", "BLOCK"} or engine not in {"auto", "native", "lua"}:
            return _json_response(False, "站点模式或引擎无效")
        existing = self.store.load_site_policy(site_id)
        rate = policy.get("rate_limit", policy.get("rate", 5))
        try:
            rate = max(1, min(1000, int(rate)))
        except (TypeError, ValueError):
            return _json_response(False, "速率必须是 1-1000 的整数")
        burst = policy.get("burst", 20)
        try:
            burst = max(1, min(10000, int(burst)))
        except (TypeError, ValueError):
            return _json_response(False, "burst 必须是 1-10000 的整数")
        streaming_paths = []
        for path in policy.get("streaming_paths", []) or []:
            streaming_paths.append(validate_streaming_path(path))
        try:
            rate_paths = normalize_rate_paths(policy.get("rate_paths", []))
        except ValidationError as exc:
            return _json_response(False, str(exc))
        auto_ban = policy.get("auto_ban")
        if not isinstance(auto_ban, dict):
            auto_ban = existing.get("auto_ban", {}) if isinstance(existing.get("auto_ban"), dict) else {}
        try:
            interface_whitelist = validate_interface_whitelist(
                policy.get("interface_whitelist", existing.get("interface_whitelist", []))
            )
        except (ValidationError, ValueError) as exc:
            return _json_response(False, str(exc))
        clean = {
            "mode": mode,
            "engine": engine,
            "rate_limit": rate,
            "burst": burst,
            "blacklist": [
                validate_ip_or_cidr(item)
                for item in policy.get("blacklist", existing.get("blacklist", [])) or []
            ],
            "whitelist": [
                validate_ip_or_cidr(item)
                for item in policy.get("whitelist", existing.get("whitelist", [])) or []
            ],
            "interface_whitelist": interface_whitelist,
            "streaming_paths": streaming_paths,
            "rate_paths": rate_paths,
            "strict_whitelist": bool(policy.get("strict_whitelist", False)),
            "auto_ban": {
                "enabled": bool(auto_ban.get("enabled", True)),
                "threshold": max(5, min(1000, int(auto_ban.get("threshold", 20)))),
                "window": max(1, min(3600, int(auto_ban.get("window", 10)))),
                "duration": max(60, min(86400, int(auto_ban.get("duration", 600)))),
            },
        }
        self.store.save_site_policy(site_id, clean)
        return _json_response(True, "站点配置已保存，请点击应用配置", clean)

    @api_errors
    def apply_config(self, get=None):
        denied = self._guard(get)
        if denied:
            return denied
        return self._apply_config_unchecked()

    def _apply_config_unchecked(self):
        # Apply-time fallback cleanup complements system logrotate and keeps
        # the plugin-owned event directory bounded even on minimal hosts.
        self._rotate_logs_unchecked()
        desired = self.store.load_desired()
        panel_rows = self._panel_sites()
        if public is not None and panel_rows is None:
            return _json_response(False, "无法读取 aaPanel 网站列表，已拒绝修改 Nginx")
        sites = []
        policies = desired.get("sites", {})
        for row in panel_rows:
            site_id = str(row.get("id", ""))
            if not site_id.isdigit():
                continue
            policy = policies.get(site_id)
            if not isinstance(policy, dict) or str(policy.get("mode", "OFF")).upper() == "OFF":
                continue
            site = dict(policy)
            site.update(
                {
                    "id": site_id,
                    "name": row.get("name", site_id),
                    "custom_rules": desired.get("custom_rules", []),
                    "rule_overrides": copy.deepcopy(desired.get("rule_overrides", {})),
                }
            )
            sites.append(site)
        if public is None:
            # Local packaging tests can exercise the transaction without panel
            # globals. Production aaPanel always uses the rows above.
            sites = [
                dict(policy, id=site_id, name=site_id)
                for site_id, policy in policies.items()
                if isinstance(policy, dict) and str(policy.get("mode", "OFF")).upper() != "OFF"
            ]
            for site in sites:
                site["custom_rules"] = desired.get("custom_rules", [])
                site["rule_overrides"] = copy.deepcopy(desired.get("rule_overrides", {}))
        preferred = str(desired.get("preferred_engine", "auto")).lower()
        nginx_v_output = self._nginx_v_output()
        lua_available = detect_lua_module(nginx_v_output)
        limit_req_dry_run = detect_limit_req_dry_run(nginx_v_output)
        real_ip_available = detect_real_ip_module(nginx_v_output)
        degraded = preferred == "lua" and not lua_available
        try:
            result = self._manager().apply(
                global_enabled=bool(desired.get("engine_enabled", False)),
                sites=sites if desired.get("engine_enabled", False) else [],
                lua_available=lua_available and preferred in {"auto", "lua"},
                cloudflare=desired.get("cloudflare", {}),
                limit_req_dry_run=limit_req_dry_run,
                real_ip_available=real_ip_available,
            )
            message = "Nginx Guard 已完成备份、nginx -t 和 reload"
            if degraded:
                message += "；未检测到 Lua，已安全降级为 Native"
            return _json_response(True, message, result)
        except (OSError, NginxCommandError, ValidationError, ValueError) as exc:
            return _json_response(False, "应用失败，已自动回滚：%s" % str(exc))

    @api_errors
    def disable_engine(self, get=None):
        denied = self._guard(get)
        if denied:
            return denied
        try:
            result = self._manager().remove()
            desired = self.store.load_desired()
            desired["engine_enabled"] = False
            self.store.save_desired(desired)
            return _json_response(True, "引擎已停用", result)
        except (OSError, NginxCommandError) as exc:
            return _json_response(False, "停用失败，原配置已恢复：%s" % str(exc))

    @api_errors
    def get_rules(self, get=None):
        denied = self._guard(get)
        if denied:
            return denied
        desired = self.store.load_desired()
        custom = desired.get("custom_rules", [])
        builtin = copy.deepcopy(DEFAULT_RULES)
        overrides = desired.get("rule_overrides", {})
        for rule in builtin:
            override = overrides.get(rule["id"], {}) if isinstance(overrides, dict) else {}
            if isinstance(override, dict):
                if "enabled" in override:
                    rule["enabled"] = bool(override["enabled"])
                if "action" in override:
                    rule["action"] = str(override["action"])
        return _json_response(True, "ok", {"builtin": builtin, "custom": custom})

    @api_errors
    def save_rule(self, get=None):
        denied = self._guard(get)
        if denied:
            return denied
        rule_id = validate_text(_value(get, "rule_id"), "rule id", 64)
        known = {rule["id"] for rule in DEFAULT_RULES}
        if rule_id not in known:
            return _json_response(False, "内置规则不存在")
        action = str(_value(get, "action", "block")).lower()
        if action not in {"block", "monitor", "403", "404", "429", "444"}:
            return _json_response(False, "规则动作无效")
        enabled = str(_value(get, "enabled", "true")).lower() in {"1", "true", "on", "yes"}
        desired = self.store.load_desired()
        overrides = desired.get("rule_overrides", {})
        if not isinstance(overrides, dict):
            overrides = {}
        overrides[rule_id] = {"enabled": enabled, "action": action}
        desired["rule_overrides"] = overrides
        self.store.save_desired(desired)
        return _json_response(True, "规则配置已保存，请点击应用配置", overrides[rule_id])

    @api_errors
    def save_custom_rule(self, get=None):
        denied = self._guard(get)
        if denied:
            return denied
        desired = self.store.load_desired()
        try:
            rule = validate_custom_rule(self._safe_json(_value(get, "rule", "{}")))
        except (PolicyError, ValidationError) as exc:
            return _json_response(False, str(exc))
        custom = [
            item for item in desired.get("custom_rules", [])
            if isinstance(item, dict) and item.get("id") != rule["id"]
        ]
        custom.append(rule)
        desired["custom_rules"] = custom[:200]
        self.store.save_desired(desired)
        return _json_response(True, "自定义规则已保存，请点击应用配置", rule)

    @api_errors
    def get_ip_lists(self, get=None):
        denied = self._guard(get)
        if denied:
            return denied
        site_id = normalize_site_id(_value(get, "site_id"))
        if self._known_site(site_id) is None:
            return _json_response(False, "网站不存在或无法由 aaPanel 验证")
        return _json_response(
            True,
            "ok",
            {
                "blacklist": self.store.load_site_policy(site_id).get("blacklist", []),
                "whitelist": self.store.load_site_policy(site_id).get("whitelist", []),
            },
        )

    @api_errors
    def mutate_ip_list(self, get=None):
        denied = self._guard(get)
        if denied:
            return denied
        site_id = normalize_site_id(_value(get, "site_id"))
        if self._known_site(site_id) is None:
            return _json_response(False, "网站不存在或无法由 aaPanel 验证")
        list_name = str(_value(get, "list_name", "")).lower()
        operation = str(_value(get, "operation", "add")).lower()
        if list_name not in {"blacklist", "whitelist"} or operation not in {"add", "remove"}:
            return _json_response(False, "IP 列表操作无效")
        address = validate_ip_or_cidr(_value(get, "address"))
        policy = self.store.load_site_policy(site_id)
        values = list(policy.get(list_name, []) or [])
        if operation == "add" and address not in values:
            values.append(address)
        if operation == "remove":
            values = [item for item in values if item != address]
        policy[list_name] = values[:5000]
        self.store.save_site_policy(site_id, policy)
        return _json_response(True, "IP 列表已更新，请点击应用配置", {list_name: values})

    @api_errors
    def get_logs(self, get=None):
        denied = self._guard(get)
        if denied:
            return denied
        self._rotate_logs_unchecked()
        site_id = normalize_site_id(_value(get, "site_id"))
        limit = max(1, min(500, int(_value(get, "limit", 100))))
        blocked_only = str(_value(get, "blocked_only", "false")).strip().lower() in {
            "1",
            "true",
            "on",
            "yes",
        }
        rows = []
        sequence = 0
        for line in iter_log_lines(self._site_log_paths(site_id)):
            try:
                row = json.loads(line)
            except (TypeError, ValueError):
                continue
            if not isinstance(row, dict):
                continue
            row = safe_event(row)
            if blocked_only and not row["blocked"]:
                continue
            event_time = parse_event_time(row)
            timestamp = event_time.timestamp() if event_time is not None else float("-inf")
            entry = (timestamp, sequence, row)
            sequence += 1
            if len(rows) < limit:
                heapq.heappush(rows, entry)
            elif entry[:2] > rows[0][:2]:
                heapq.heapreplace(rows, entry)
        rows.sort(key=lambda item: item[:2], reverse=True)
        return _json_response(True, "ok", [item[2] for item in rows])

    @staticmethod
    def _blocked_only_value(value):
        return str(value or "false").strip().lower() in {"1", "true", "on", "yes"}

    def _site_log_paths(self, site_id):
        """Return only this plugin's active and rotated JSONL files."""

        logs_dir = DATA_ROOT / "logs"
        if not logs_dir.is_dir():
            return []
        prefix = "events-site-%s.jsonl" % normalize_site_id(site_id)
        paths = []
        for path in logs_dir.glob(prefix + "*"):
            if path.is_file() and not path.is_symlink() and (path.name == prefix or path.name.startswith(prefix + ".")):
                paths.append(path)
        def sort_key(item):
            if item.name == prefix:
                return (1, 0.0, item.name)
            try:
                mtime = item.stat().st_mtime
            except OSError:
                mtime = 0.0
            return (0, mtime, item.name)

        return sorted(paths, key=sort_key)

    def _all_site_log_paths(self):
        logs_dir = DATA_ROOT / "logs"
        if not logs_dir.is_dir():
            return []
        paths = [
            path
            for path in logs_dir.glob("events-site-*.jsonl*")
            if path.is_file() and not path.is_symlink()
        ]
        def sort_key(item):
            try:
                mtime = item.stat().st_mtime
            except OSError:
                mtime = 0.0
            return (mtime, item.name)

        return sorted(paths, key=sort_key)

    def _iter_site_log_lines(self, site_id):
        yield from iter_log_lines(self._site_log_paths(site_id))

    def _analyze_site_logs(self, site_id, window, blocked_only=False, top_n=10):
        result = analyze_jsonl(
            self._iter_site_log_lines(site_id),
            window=window,
            blocked_only=blocked_only,
            top_n=top_n,
        )
        result["site_id"] = normalize_site_id(site_id)
        return result

    @api_errors
    def get_log_analysis(self, get=None):
        denied = self._guard(get)
        if denied:
            return denied
        site_id = normalize_site_id(_value(get, "site_id"))
        if public is not None and self._known_site(site_id) is None:
            return _json_response(False, "网站不存在或无法由 aaPanel 验证")
        self._rotate_logs_unchecked()
        blocked_only = self._blocked_only_value(_value(get, "blocked_only", "false"))
        top_n = _value(get, "top_n", 10)
        result = self._analyze_site_logs(
            site_id,
            str(_value(get, "window", "24h")),
            blocked_only=blocked_only,
            top_n=top_n,
        )
        result["blocked_only"] = blocked_only
        return _json_response(True, "ok", result)

    @api_errors
    def export_log_analysis(self, get=None):
        denied = self._guard(get)
        if denied:
            return denied
        site_id = normalize_site_id(_value(get, "site_id"))
        if public is not None and self._known_site(site_id) is None:
            return _json_response(False, "网站不存在或无法由 aaPanel 验证")
        self._rotate_logs_unchecked()
        window = str(_value(get, "window", "24h"))
        blocked_only = self._blocked_only_value(_value(get, "blocked_only", "false"))
        result = self._analyze_site_logs(site_id, window, blocked_only=blocked_only, top_n=50)
        return _json_response(
            True,
            "ok",
            {
                "filename": "nginx_guard_analysis_site-%s_%s.csv" % (site_id, result["window"]),
                "content": analysis_to_csv(result),
            },
        )

    @api_errors
    def get_metrics(self, get=None):
        denied = self._guard(get)
        if denied:
            return denied
        self._rotate_logs_unchecked()
        result = aggregate_jsonl(iter_log_lines(self._all_site_log_paths()))
        return _json_response(True, "ok", result)

    @api_errors
    def get_cloudflare(self, get=None):
        denied = self._guard(get)
        if denied:
            return denied
        desired = self.store.load_desired()
        return _json_response(True, "ok", normalize_cloudflare_config(desired.get("cloudflare")))

    @api_errors
    def refresh_cloudflare(self, get=None):
        denied = self._guard(get)
        if denied:
            return denied
        try:
            networks = fetch_official_networks()
        except Exception as exc:
            return _json_response(False, "获取 Cloudflare 官方网段失败：%s" % str(exc))
        desired = self.store.load_desired()
        current = normalize_cloudflare_config(desired.get("cloudflare"))
        desired["cloudflare"] = normalize_cloudflare_config(
            {
                "enabled": current["enabled"],
                "official_networks": networks,
                "manual_networks": current["manual_networks"],
                "updated_at": int(time.time()),
            }
        )
        self.store.save_desired(desired)
        return _json_response(True, "Cloudflare 网段已更新，请点击应用配置", desired["cloudflare"])

    @api_errors
    def save_cloudflare(self, get=None):
        denied = self._guard(get)
        if denied:
            return denied
        desired = self.store.load_desired()
        current = normalize_cloudflare_config(desired.get("cloudflare"))
        enabled = str(_value(get, "enabled", current.get("enabled", False))).lower()
        raw_manual = _value(get, "manual_networks", current["manual_networks"])
        raw_manual = self._safe_json(raw_manual) if isinstance(raw_manual, str) else raw_manual
        if not isinstance(raw_manual, (list, tuple)):
            return _json_response(False, "Cloudflare 手动网段必须是数组")
        try:
            manual = []
            for value in raw_manual:
                address = validate_ip_or_cidr(value)
                if address not in manual:
                    manual.append(address)
            if len(manual) > 500:
                return _json_response(False, "Cloudflare 手动网段最多 500 条")
        except ValidationError as exc:
            return _json_response(False, str(exc))
        desired["cloudflare"] = normalize_cloudflare_config(
            {
                "enabled": enabled in {"1", "true", "on", "yes"},
                "official_networks": current["official_networks"],
                "manual_networks": manual,
                "updated_at": current.get("updated_at", 0),
            }
        )
        self.store.save_desired(desired)
        return _json_response(True, "Cloudflare 配置已保存，请点击应用配置", desired["cloudflare"])

    @api_errors
    def mutate_cloudflare_network(self, get=None):
        denied = self._guard(get)
        if denied:
            return denied
        operation = str(_value(get, "operation", "add")).lower()
        if operation not in {"add", "remove"}:
            return _json_response(False, "Cloudflare 网段操作无效")
        address = validate_ip_or_cidr(_value(get, "address"))
        desired = self.store.load_desired()
        current = normalize_cloudflare_config(desired.get("cloudflare"))
        manual = list(current["manual_networks"])
        if operation == "add" and address not in manual:
            if len(manual) >= 500:
                return _json_response(False, "Cloudflare 手动网段最多 500 条")
            manual.append(address)
        elif operation == "remove":
            manual = [item for item in manual if item != address]
        desired["cloudflare"] = normalize_cloudflare_config(
            {
                "enabled": current["enabled"],
                "official_networks": current["official_networks"],
                "manual_networks": manual,
                "updated_at": current["updated_at"],
            }
        )
        self.store.save_desired(desired)
        return _json_response(True, "Cloudflare 手动网段已更新，请点击应用配置", desired["cloudflare"])

    @api_errors
    def lookup_cloudflare_ip(self, get=None):
        denied = self._guard(get)
        if denied:
            return denied
        desired = self.store.load_desired()
        current = normalize_cloudflare_config(desired.get("cloudflare"))
        result = lookup_network_membership(
            _value(get, "address"),
            official_networks=current["official_networks"],
            manual_networks=current["manual_networks"],
        )
        return _json_response(True, "ok", result)

    @api_errors
    def get_backups(self, get=None):
        denied = self._guard(get)
        if denied:
            return denied
        NginxConfigManager(NGINX_CONF, VHOST_DIR, DATA_ROOT)._prune_backups()
        backups = []
        if (DATA_ROOT / "backup").is_dir():
            for path in sorted(DATA_ROOT.joinpath("backup").iterdir(), reverse=True):
                if path.is_dir() and len(backups) < 3:
                    backups.append({"name": path.name, "path": str(path)})
        return _json_response(True, "ok", backups)

    @api_errors
    def restore_backup(self, get=None):
        denied = self._guard(get)
        if denied:
            return denied
        name = validate_text(_value(get, "backup"), "backup", 128)
        result = self._manager().restore_backup(name)
        return _json_response(True, "备份已恢复并重新加载 Nginx", result)

    @api_errors
    def rotate_logs(self, get=None):
        denied = self._guard(get)
        if denied:
            return denied
        return _json_response(True, "日志轮转完成", self._rotate_logs_unchecked())

    def _rotate_logs_unchecked(self):
        desired = self.store.load_desired()
        settings = desired.get("log_rotation", {})
        logs_dir = DATA_ROOT / "logs"
        return cleanup_jsonl_directory(
            logs_dir,
            max_bytes=settings.get("max_bytes", 20 * 1024 * 1024),
            keep_days=settings.get("keep_days", 7),
            max_files=settings.get("max_files", 100),
            max_total_bytes=settings.get("max_total_bytes", 100 * 1024 * 1024),
        )

    @api_errors
    def diagnostics(self, get=None):
        denied = self._guard(get)
        if denied:
            return denied
        manager = NginxConfigManager(NGINX_CONF, VHOST_DIR, DATA_ROOT)
        nginx_v_output = self._nginx_v_output()
        try:
            http_config = str(manager.http_config_path())
            http_block_found = True
        except NginxCommandError:
            http_config = ""
            http_block_found = False
        return _json_response(
            True,
            "ok",
            {
                "python": os.sys.version.split()[0],
                "nginx_conf": str(NGINX_CONF),
                "http_config": http_config,
                "http_block_found": http_block_found,
                "vhost_dir": str(VHOST_DIR),
                "data_root": str(DATA_ROOT),
                "lua_available": detect_lua_module(nginx_v_output),
                "real_ip_available": detect_real_ip_module(nginx_v_output),
                "config_writable": os.access(str(DATA_ROOT), os.W_OK),
            },
        )
