"""Nginx marker wiring and safe apply/rollback transactions."""

from __future__ import annotations

import datetime
import glob
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from .cloudflare import normalize_cloudflare_config
from .policy import (
    BODY_MAX_BYTES,
    DEFAULT_RULES,
    PolicyError,
    native_patterns,
    validate_custom_rule,
    validate_interface_whitelist,
)
from .security import ValidationError, normalize_site_id, safe_filename, validate_streaming_path


class NginxCommandError(RuntimeError):
    """Raised when nginx -t or reload fails."""


def detect_lua_module(nginx_v_output: str) -> bool:
    text = str(nginx_v_output or "")
    markers = (
        "--with-http_lua_module",
        "ngx_http_lua_module",
        "lua-nginx-module",
        "lua_nginx_module",
        "ngx_lua",
        "openresty/",
    )
    return any(marker in text for marker in markers)


def detect_real_ip_module(nginx_v_output: str) -> bool:
    """Detect the HTTP Real IP module without matching a --without flag."""

    text = str(nginx_v_output or "")
    return bool(
        re.search(r"--with-http_realip_module\b", text)
        or "ngx_http_realip_module" in text
    )


def detect_limit_req_dry_run(nginx_v_output: str) -> bool:
    """Detect support for limit_req_dry_run on older Nginx builds."""

    match = re.search(r"(?:nginx|openresty)/(\d+)\.(\d+)\.(\d+)", str(nginx_v_output or ""))
    if not match:
        # aaPanel's supported Nginx/OpenResty builds are modern; retain the
        # historical default when a test double or wrapper hides the version.
        return True
    version = tuple(int(value) for value in match.groups())
    return version >= (1, 17, 1)


def _atomic_write(path: Path, content: str, mode=0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".%s." % path.name, suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, str(path))
        os.chmod(str(path), mode)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def _block_opening_pattern(block_name: str) -> str:
    """Match an Nginx named block across whitespace and comments."""

    return r"(?m)^[ \t]*%s\b(?:(?:[ \t]*#[^\r\n]*)|[ \t\r\n])*\{" % re.escape(block_name)


def _insert_inside_block(text: str, block_name: str, snippet: str) -> str:
    """Insert a marker snippet inside the first named nginx block."""

    opening = re.search(_block_opening_pattern(block_name), text)
    if not opening:
        raise NginxCommandError("nginx.conf does not contain a %s block" % block_name)
    brace = text.find("{", opening.start(), opening.end())
    depth = 0
    end = None
    for index in range(brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end = index
                break
    if end is None:
        raise NginxCommandError("nginx.conf has an unclosed %s block" % block_name)
    return text[:brace + 1] + "\n" + snippet.rstrip() + "\n" + text[brace + 1:]


def _remove_marker(text: str, begin: str, end: str) -> str:
    pattern = re.compile(
        r"(?ms)^[ \t]*" + re.escape(begin) + r"[ \t]*\r?\n.*?^[ \t]*" + re.escape(end) + r"[ \t]*\r?\n?"
    )
    return pattern.sub("", text)


def _block_end(text: str, brace: int, block_name: str) -> int:
    depth = 0
    for index in range(brace, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    raise NginxCommandError("vhost has an unclosed %s block" % block_name)


def _server_ranges(text: str):
    ranges = []
    for match in re.finditer(_block_opening_pattern("server"), text):
        brace = text.find("{", match.start(), match.end())
        ranges.append((match.start(), brace, _block_end(text, brace, "server")))
    return ranges


class LocalNginxRunner:
    """Run only fixed nginx commands; no shell interpolation is used."""

    def __init__(self, nginx_binary="/www/server/nginx/sbin/nginx", config_path="/www/server/nginx/conf/nginx.conf"):
        self.nginx_binary = str(nginx_binary)
        self.config_path = str(config_path)

    def _run(self, args):
        try:
            completed = subprocess.run(
                [self.nginx_binary] + list(args),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
        except OSError as exc:
            raise NginxCommandError(str(exc)) from exc
        if completed.returncode != 0:
            raise NginxCommandError(completed.stdout[-4096:])
        return completed.stdout

    def test_config(self):
        return self._run(["-t", "-c", self.config_path])

    def reload(self):
        return self._run(["-s", "reload", "-c", self.config_path])


class NginxConfigManager:
    """Apply generated fragments and vhost markers transactionally."""

    global_begin = "# BEGIN NGINX_GUARD_GLOBAL"
    global_end = "# END NGINX_GUARD_GLOBAL"
    backup_retention = 3

    def __init__(self, nginx_conf, vhost_dir, data_root, runner=None):
        self.nginx_conf = Path(nginx_conf)
        self.vhost_dir = Path(vhost_dir)
        self.data_root = Path(data_root)
        self.backup_root = self.data_root / "backup"
        self.generated_root = self.data_root / "generated"
        self.runner = runner or LocalNginxRunner(config_path=str(self.nginx_conf))

    @staticmethod
    def _unique_paths(paths):
        result = []
        seen = set()
        for path in paths:
            path = Path(path)
            key = str(path.absolute()).casefold()
            if key in seen:
                continue
            seen.add(key)
            result.append(path)
        return result

    @staticmethod
    def _include_specs(text):
        """Return simple, line-oriented Nginx include arguments.

        Nginx allows an include argument to be quoted and permits glob
        patterns.  Keeping this parser line-oriented avoids treating text in
        comments or regular expressions as configuration directives.
        """

        for match in re.finditer(r"(?m)^[ \t]*include[ \t]+([^;#\r\n]+);", text):
            value = match.group(1).strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                value = value[1:-1]
            if value:
                yield value

    def _include_paths(self, including, spec):
        """Resolve an include against the common Nginx/aaPanel prefixes."""

        spec = str(spec).strip()
        prefix = self.nginx_conf.parent.parent
        spec = spec.replace("${prefix}", str(prefix)).replace("$prefix", str(prefix))
        if "$" in spec:
            # Variables other than $prefix are runtime-dependent and cannot
            # be safely resolved for a transaction backup.
            return []

        candidate_specs = []
        raw_path = Path(spec)
        if raw_path.is_absolute():
            candidate_specs.append(raw_path)
        else:
            for root in (
                Path(including).parent,
                self.nginx_conf.parent,
                prefix,
                prefix / "nginx",
                prefix / "openresty",
            ):
                candidate_specs.append(root / spec)

        result = []
        seen = set()
        for candidate in candidate_specs:
            matches = glob.glob(str(candidate))
            if not matches and candidate.is_file():
                matches = [str(candidate)]
            for match in matches:
                path = Path(match)
                if not path.is_file() or path.is_symlink():
                    continue
                key = str(path.absolute()).casefold()
                if key in seen:
                    continue
                seen.add(key)
                result.append(path)
        return result

    def _config_graph(self):
        """Read the active config and its reachable include files once."""

        pending = [self.nginx_conf]
        visited = set()
        graph = []
        while pending:
            path = Path(pending.pop(0))
            key = str(path.absolute()).casefold()
            if key in visited:
                continue
            visited.add(key)
            if path.is_symlink() or not path.is_file():
                if path == self.nginx_conf:
                    raise NginxCommandError("无法读取 Nginx 主配置文件：%s" % path)
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except OSError as exc:
                if path == self.nginx_conf:
                    raise NginxCommandError("无法读取 Nginx 主配置文件：%s" % path) from exc
                continue
            graph.append((path, text))
            for spec in self._include_specs(text):
                pending.extend(self._include_paths(path, spec))
        return graph

    def config_graph_paths(self):
        """Return active config files, including files reached by include."""

        return [path for path, _text in self._config_graph()]

    def http_config_path(self):
        """Find the file that owns the active http block."""

        opening = _block_opening_pattern("http")
        for path, text in self._config_graph():
            if re.search(opening, text):
                return path
        raise NginxCommandError(
            "未找到可修改的 http 配置块，请检查 Nginx 主配置及 include 文件"
        )

    def _global_marker_paths(self):
        return [
            path
            for path, text in self._config_graph()
            if self.global_begin in text or self.global_end in text
        ]

    def _restore_path_is_safe(self, path):
        path = Path(path)
        if not path.is_absolute() or path.is_symlink():
            return False
        fixed = {
            self.nginx_conf,
            self.generated_root / "global.conf",
            self.data_root / "runtime" / "snapshot.lua",
            self.data_root / "runtime" / "version",
        }
        if path in fixed:
            return True
        roots = [self.nginx_conf.parent, self.vhost_dir, self.generated_root]
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path.absolute()
        for root in roots:
            try:
                resolved.relative_to(root.resolve())
                return True
            except (ValueError, OSError):
                continue
        return False

    def _backup(self, paths, prune=True):
        stamp = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:8]
        directory = self.backup_root / stamp
        directory.mkdir(parents=True, exist_ok=False)
        records = []
        for path in paths:
            path = Path(path)
            if path.is_symlink():
                raise NginxCommandError("refusing to touch symlink: %s" % path)
            exists = path.exists()
            backup_path = directory / ("%02d-%s" % (len(records), safe_filename(path.name)))
            if exists:
                shutil.copy2(str(path), str(backup_path))
            records.append((path, backup_path, exists))
        _atomic_write(
            directory / "manifest.json",
            json.dumps(
                [
                    {"path": str(path), "backup": backup_path.name, "exists": existed}
                    for path, backup_path, existed in records
                ],
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
        )
        if prune:
            self._prune_backups()
        return directory, records

    def _prune_backups(self):
        if not self.backup_root.is_dir():
            return
        directories = sorted(
            (
                path
                for path in self.backup_root.iterdir()
                if path.is_dir() and not path.is_symlink()
            ),
            key=lambda path: path.name,
            reverse=True,
        )
        for path in directories[self.backup_retention :]:
            try:
                shutil.rmtree(str(path))
            except OSError:
                # A failed cleanup must not prevent the already-created
                # transaction backup from protecting the current apply.
                continue

    @staticmethod
    def _restore(records):
        for path, backup_path, existed in records:
            if existed:
                if path.is_symlink():
                    path.unlink()
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(backup_path), str(path))
            else:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass

    def _transaction_paths(self, extra=None):
        """Return plugin-owned files that can be saved before a recovery."""

        targets = [self.nginx_conf]
        try:
            targets.extend(self.config_graph_paths())
        except NginxCommandError:
            # The main file may be the damaged file being recovered.  The
            # manifest paths supplied by the caller are added below.
            pass
        if self.vhost_dir.is_dir():
            targets.extend(
                path
                for path in self.vhost_dir.glob("*.conf")
                if path.is_file() and not path.is_symlink()
            )
        targets.extend(
            [
                self.generated_root / "global.conf",
                self.data_root / "runtime" / "snapshot.lua",
                self.data_root / "runtime" / "version",
            ]
        )
        if self.generated_root.is_dir():
            targets.extend(
                path
                for path in self.generated_root.glob("site-*.conf")
                if path.is_file() and not path.is_symlink()
            )
        targets.extend(path for path, _backup, _exists in (extra or []))
        return self._unique_paths(targets)

    def _rollback_and_revalidate(self, records, original, operation):
        """Restore a transaction and prove the restored config is runnable."""

        try:
            self._restore(records)
            self.runner.test_config()
            self.runner.reload()
        except Exception as recovery_error:
            raise NginxCommandError(
                "%s失败，且恢复原配置后验证或 reload 也失败：%s；原始错误：%s"
                % (operation, recovery_error, original)
            ) from recovery_error
        raise original

    def _global_snippet(self):
        fragment = self.data_root / "generated" / "global.conf"
        return (
            "%s\n"
            "include %s;\n"
            "%s"
        ) % (self.global_begin, fragment.as_posix(), self.global_end)

    @staticmethod
    def _site_markers(site_id, fragment):
        begin = "# BEGIN NGINX_GUARD_SITE:%s" % site_id
        end = "# END NGINX_GUARD_SITE:%s" % site_id
        return begin, end, "%s\ninclude %s;\n%s" % (begin, fragment.as_posix(), end)

    def _find_vhost(self, site):
        site_id = normalize_site_id(site.get("id"))
        name = safe_filename(site.get("name") or site_id)
        candidates = [
            self.vhost_dir / (name + ".conf"),
            self.vhost_dir / ("site-%s.conf" % site_id),
            # aaPanel stores Node project vhosts with a ``node_`` prefix,
            # while the site API exposes the project name without it.
            self.vhost_dir / ("node_" + name + ".conf"),
        ]
        for candidate in candidates:
            if candidate.is_file():
                return site_id, candidate
        raise NginxCommandError("vhost file not found for site %s" % site_id)

    def _patch_site(self, text, site_id, fragment):
        begin, end, snippet = self._site_markers(site_id, fragment)
        text = _remove_marker(text, begin, end)
        # The fragment include belongs in the server block. For aaPanel vhosts,
        # inserting before the final server brace keeps existing locations intact.
        servers = _server_ranges(text)
        if not servers:
            raise NginxCommandError("vhost does not contain a server block")
        patched = text
        # Insert from the end so offsets for earlier server blocks stay valid.
        for _start, _brace, end_index in reversed(servers):
            patched = patched[:end_index] + "\n" + snippet + "\n" + patched[end_index:]
        return patched

    @staticmethod
    def _remove_all_site_markers(text):
        return re.sub(
            r"(?ms)^[ \t]*# BEGIN NGINX_GUARD_SITE:[^\r\n]+[ \t]*\r?\n.*?^[ \t]*# END NGINX_GUARD_SITE:[^\r\n]+[ \t]*\r?\n?",
            "",
            text,
        )

    @staticmethod
    def _rate_settings(site):
        value = site.get("rate_limit", site.get("rate", 5))
        burst = site.get("burst", 20)
        if isinstance(value, dict):
            burst = value.get("burst", burst)
            value = value.get("rate", 5)
        try:
            rate = max(1, min(1000, int(value)))
        except (TypeError, ValueError):
            rate = 5
        try:
            burst = max(1, min(10000, int(burst)))
        except (TypeError, ValueError):
            burst = 20
        return rate, burst

    @classmethod
    def _rate_path_settings(cls, site):
        result = []
        for item in site.get("rate_paths", []) or []:
            if not isinstance(item, dict):
                raise NginxCommandError("rate path must be an object")
            path = str(item.get("path", "")).strip()
            if not path.startswith("/") or len(path) > 128 or any(
                ord(character) < 32
                or ord(character) == 127
                or character in "#\"'{};\\"
                for character in path
            ):
                raise NginxCommandError("invalid rate path")
            try:
                rate = max(1, min(1000, int(item.get("rate", 2))))
                burst = max(1, min(10000, int(item.get("burst", 20))))
            except (TypeError, ValueError) as exc:
                raise NginxCommandError("invalid rate path limits") from exc
            result.append((path, rate, burst))
        return result

    @staticmethod
    def _builtin_status(site, rule_id, default=403):
        override = (site.get("rule_overrides") or {}).get(rule_id, {})
        if not isinstance(override, dict) or override.get("enabled", True) is False:
            return None
        action = str(override.get("action", "block")).lower()
        if action == "block":
            return default
        try:
            status = int(action)
        except (TypeError, ValueError):
            return None
        return status if status in {403, 404, 429, 444} else None

    @staticmethod
    def _lua_string(value):
        text = str(value or "")
        return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'

    @classmethod
    def _lua_value(cls, value):
        if value is None:
            return "nil"
        if value is True:
            return "true"
        if value is False:
            return "false"
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, dict):
            fields = []
            for key, item in value.items():
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(key)):
                    rendered_key = str(key)
                else:
                    rendered_key = "[" + cls._lua_string(key) + "]"
                fields.append("%s=%s" % (rendered_key, cls._lua_value(item)))
            return "{" + ",".join(fields) + "}"
        if isinstance(value, (list, tuple, set)):
            return "{" + ",".join(cls._lua_value(item) for item in value) + "}"
        return cls._lua_string(value)

    def _render_snapshot(self, sites, version=None):
        snapshot_sites = {}
        pattern_values = native_patterns()
        for site in sites:
            site_id = normalize_site_id(site.get("id"))
            whitelist = {}
            for address in site.get("whitelist", []) or []:
                address = str(address).strip()
                if "/" not in address:
                    whitelist[address] = True
            rate, _burst = self._rate_settings(site)
            auto_ban = site.get("auto_ban", {}) if isinstance(site.get("auto_ban", {}), dict) else {}
            custom_rules = []
            for custom in site.get("custom_rules", []) or []:
                try:
                    custom_rules.append(validate_custom_rule(custom))
                except (PolicyError, ValueError) as exc:
                    raise NginxCommandError("invalid custom rule: %s" % exc)
            rule_ids = {item["id"] for item in DEFAULT_RULES}
            rule_overrides = {}
            builtin_rules = {}
            for rule_id, rule in (site.get("rule_overrides") or {}).items():
                if str(rule_id) in rule_ids and isinstance(rule, dict):
                    rule_overrides[str(rule_id)] = {
                        "enabled": bool(rule.get("enabled", True)),
                        "action": str(rule.get("action", "block")).lower(),
                    }
            for default_rule in DEFAULT_RULES:
                override = rule_overrides.get(default_rule["id"], {})
                builtin_rules[default_rule["id"]] = {
                    "enabled": bool(override.get("enabled", default_rule.get("enabled", True))),
                    "action": str(override.get("action", default_rule.get("action", "monitor"))).lower(),
                    "name": default_rule["name"],
                }
            try:
                interface_whitelist = validate_interface_whitelist(site.get("interface_whitelist", []))
            except (PolicyError, ValueError) as exc:
                raise NginxCommandError("接口白名单无效：%s" % exc)
            snapshot_sites[site_id] = {
                "mode": str(site.get("mode", "MONITOR")).upper(),
                "rate": rate,
                "strict_whitelist": bool(site.get("strict_whitelist", False)),
                "whitelist": whitelist,
                "interface_whitelist": interface_whitelist,
                "body_inspection": {"enabled": True, "max_bytes": BODY_MAX_BYTES, "text_only": True},
                "patterns": {
                    "sqli": pattern_values["sqli"],
                    "xss": pattern_values["xss"],
                    "scanner": pattern_values["scanner"],
                },
                "builtin_rules": builtin_rules,
                "auto_ban": {
                    "enabled": bool(auto_ban.get("enabled", True)),
                    "threshold": max(5, min(1000, int(auto_ban.get("threshold", 20)))),
                    "window": max(1, min(3600, int(auto_ban.get("window", 10)))),
                    "duration": max(60, min(86400, int(auto_ban.get("duration", 600)))),
                },
                "custom_rules": custom_rules,
                "rule_overrides": rule_overrides,
            }
        if version is None:
            version = int(time.time() * 1000)
        return "return %s\n" % self._lua_value({"version": version, "sites": snapshot_sites})

    def _render_global(
        self,
        global_enabled=True,
        lua_available=False,
        sites=None,
        cloudflare=None,
        real_ip_available=True,
    ):
        sites = list(sites or [])
        patterns = native_patterns()
        cloudflare = normalize_cloudflare_config(cloudflare)
        trusted_networks = []
        for value in cloudflare.get("networks", []):
            try:
                network = ipaddress.ip_network(str(value).strip(), strict=False)
            except ValueError:
                continue
            canonical = str(network)
            if canonical not in trusted_networks:
                trusted_networks.append(canonical)
        use_real_ip = bool(cloudflare.get("enabled") and real_ip_available and trusted_networks)
        lines = [
            "# Generated by Nginx Guard. Do not edit manually.",
            'map $request_uri $ng_guard_path_rule {',
            '    default "";',
            '    "~*%s" NG1001;' % patterns["sensitive"],
            '    "~*%s" NG1002;' % patterns["traversal"],
            "}",
            'map $args $ng_guard_args_rule {',
            '    default "";',
            '    "~*%s" NG1003;' % patterns["metadata"],
            "}",
            'map "$request_uri:$args" $ng_guard_request_rule {',
            '    default "";',
            '    "~*%s" NG2001;' % patterns["sqli"],
            '    "~*%s" NG2002;' % patterns["xss"],
            "}",
            'map $http_user_agent $ng_guard_ua_rule {',
            '    default "";',
            '    "~*%s" NG2003;' % patterns["scanner"],
            "}",
            'map $args $ng_guard_safe_query {',
            '    default $args;',
            '    "~*(?:^|&)(?:token|access_token|api[_-]?key|password|passwd|secret|authorization|cookie|session|signature|sign)(?:=|%3d)" "[REDACTED]";',
            "}",
            'map $host $ng_guard_lua_rule_id {',
            '    default "";',
            "}",
            'map "$ng_guard_path_rule:$ng_guard_args_rule:$ng_guard_request_rule:$ng_guard_ua_rule" $ng_guard_native_rule_id {',
            '    default "";',
            '    ~^NG1001: NG1001;',
            '    ~^NG1002: NG1002;',
            '    ~^:NG1003: NG1003;',
            '    ~^::NG2001: NG2001;',
            '    ~^::NG2002: NG2002;',
            '    ~^:::[^:]*NG2003 NG2003;',
            "}",
            'map $limit_req_status $ng_guard_rate_rule_id {',
            '    default "";',
            '    REJECTED NG3001;',
            '    REJECTED_DRY_RUN NG3001;',
            "}",
            'map "$ng_guard_rate_rule_id:$ng_guard_lua_rule_id:$ng_guard_native_rule_id" $ng_guard_event_rule_id {',
            '    default $ng_guard_native_rule_id;',
            '    ~^NG3001: NG3001;',
            '    ~^:[^:]+: $ng_guard_lua_rule_id;',
            "}",
            'map $ng_guard_event_rule_id $ng_guard_attack_type {',
            '    default "自定义规则";',
            '    "" "";',
            '    NG1001 "敏感文件";',
            '    NG1002 "路径穿越";',
            '    NG1003 "云元数据 SSRF";',
            '    NG2001 "SQL 注入";',
            '    NG2002 "XSS";',
            '    NG2003 "扫描器";',
            '    NG3001 "CC 限速";',
            '    NG3002 "临时封禁";',
            "}",
            'map $ng_guard_event_rule_id $ng_guard_rule_name {',
            '    default "自定义规则";',
            '    "" "";',
            '    NG1001 "敏感文件暴露";',
            '    NG1002 "路径穿越";',
            '    NG1003 "云元数据 SSRF";',
            '    NG2001 "SQL 注入特征";',
            '    NG2002 "XSS 特征";',
            '    NG2003 "扫描器 User-Agent";',
            '    NG3001 "CC 速率限制";',
            '    NG3002 "临时 IP 封禁";',
            "}",
            'map "$ng_guard_event_rule_id:$status" $ng_guard_rule_action {',
            '    default "";',
            '    ~^.+:2[0-9][0-9]$ MONITOR;',
            '    ~^.+:(?:403|404|429|444)$ BLOCK;',
            "}",
            'map $limit_req_status $ng_guard_rate_action {',
            '    default "";',
            '    REJECTED BLOCK;',
            '    REJECTED_DRY_RUN MONITOR;',
            "}",
            'map "$ng_guard_rate_action:$ng_guard_rule_action" $ng_guard_event_action {',
            '    default $ng_guard_rule_action;',
            '    ~^BLOCK: BLOCK;',
            '    ~^MONITOR: MONITOR;',
            "}",
        ]
        if use_real_ip:
            lines.extend([
                "# Cloudflare Real IP: trust only the configured official and manual ranges.",
                "geo $realip_remote_addr $ng_guard_cf_trusted {",
                "    default 0;",
            ])
            lines.extend("    %s 1;" % network for network in trusted_networks)
            lines.extend([
                "}",
                "map $ng_guard_cf_trusted $ng_guard_cfip {",
                '    default "";',
                "    1 $realip_remote_addr;",
                "}",
            ])
            lines.extend("set_real_ip_from %s;" % network for network in trusted_networks)
            lines.extend(["real_ip_header CF-Connecting-IP;", "real_ip_recursive on;"])
        else:
            lines.extend([
                "map $remote_addr $ng_guard_cfip {",
                '    default "";',
                "}",
            ])
        lines.extend([
            'log_format ng_guard_json escape=json \'{"time":"$time_iso8601","remote_addr":"$remote_addr","cfip":"$ng_guard_cfip","client_ip":"$remote_addr","host":"$host","method":"$request_method","uri":"$uri","query":"$ng_guard_safe_query","status":$status,"request_time":$request_time,"rule_id":"$ng_guard_event_rule_id","rule_name":"$ng_guard_rule_name","attack_type":"$ng_guard_attack_type","action":"$ng_guard_event_action","user_agent":"$http_user_agent"}\';',
            "map $uri $ng_guard_dynamic {",
            "    default 1;",
            "    \"~*\\.(?:css|js|mjs|png|jpg|jpeg|webp|svg|ico|woff|woff2|ttf|map)$\" 0;",
            "}",
        ])
        for site in sites:
            site_id = normalize_site_id(site.get("id"))
            blacklist = site.get("blacklist", []) or []
            whitelist = site.get("whitelist", []) or []
            lines.extend([
                "geo $ng_guard_blacklist_%s {" % site_id,
                "    default 0;",
            ])
            for address in blacklist:
                address = str(address).strip()
                if re.fullmatch(r"(?:[0-9a-fA-F:.]+)(?:/[0-9]{1,3})?", address):
                    lines.append("    %s 1;" % address)
            lines.extend(["}", "geo $ng_guard_whitelist_%s {" % site_id, "    default 0;"])
            for address in whitelist:
                address = str(address).strip()
                if re.fullmatch(r"(?:[0-9a-fA-F:.]+)(?:/[0-9]{1,3})?", address):
                    lines.append("    %s 1;" % address)
            lines.extend([
                "}",
                'map "$ng_guard_blacklist_%s:$ng_guard_whitelist_%s" $ng_guard_ip_block_%s {' %
                (site_id, site_id, site_id),
                "    default 0;",
                '    "1:0" 1;',
                "}",
            ])
            try:
                interface_whitelist = validate_interface_whitelist(site.get("interface_whitelist", []))
            except (PolicyError, ValueError) as exc:
                raise NginxCommandError("接口白名单无效：%s" % exc)
            lines.extend([
                'map "$host:$server_port$uri" $ng_guard_interface_whitelist_%s {' % site_id,
                "    default 0;",
            ])
            for entry in interface_whitelist:
                host_pattern = re.escape(entry["host"]).replace('"', '\\"')
                port_pattern = str(entry["port"]) if entry.get("port") is not None else r"[0-9]+"
                path = str(entry.get("path") or "/")
                if entry.get("whole_host") or (entry.get("match") == "prefix" and path == "/"):
                    path_pattern = r"/"
                    suffix = ""
                elif entry.get("match") == "prefix":
                    path_pattern = re.escape(path.rstrip("/")).replace('"', '\\"')
                    suffix = r"(?:/|$)"
                else:
                    path_pattern = re.escape(path).replace('"', '\\"')
                    suffix = r"$"
                lines.append(
                    '    "~*^%s:%s%s%s" 1;' %
                    (host_pattern, port_pattern, path_pattern, suffix)
                )
            lines.extend([
                "}",
                'map "$ng_guard_whitelist_%s:$ng_guard_interface_whitelist_%s" $ng_guard_ordinary_bypass_%s {' %
                (site_id, site_id, site_id),
                "    default 0;",
                '    "1:0" 1;',
                '    "0:1" 1;',
                '    "1:1" 1;',
                "}",
                'map "$ng_guard_ordinary_bypass_%s:$ng_guard_native_rule_id" $ng_guard_site_log_rule_id_%s {' %
                (site_id, site_id),
                '    default "";',
                '    "0:NG1001" NG1001;',
                '    "1:NG1001" NG1001;',
                '    "0:NG1002" NG1002;',
                '    "1:NG1002" NG1002;',
                '    "0:NG1003" NG1003;',
                '    "1:NG1003" NG1003;',
                '    "0:NG2001" NG2001;',
                '    "0:NG2002" NG2002;',
                '    "0:NG2003" NG2003;',
                "}",
                'map "$ng_guard_ordinary_bypass_%s:$ng_guard_request_rule" $ng_guard_site_request_rule_%s {' %
                (site_id, site_id),
                '    default "";',
                '    "0:NG2001" NG2001;',
                '    "0:NG2002" NG2002;',
                "}",
                'map "$ng_guard_ordinary_bypass_%s:$ng_guard_ua_rule" $ng_guard_site_ua_rule_%s {' %
                (site_id, site_id),
                '    default "";',
                '    "0:NG2003" NG2003;',
                "}",
            ])
            lines.extend([
                'map "$ng_guard_ordinary_bypass_%s:$ng_guard_dynamic" $ng_guard_rate_key_%s {' %
                (site_id, site_id),
                '    default "";',
                '    "0:1" $binary_remote_addr;',
                "}",
            ])
            rate, _burst = self._rate_settings(site)
            lines.append(
                "limit_req_zone $ng_guard_rate_key_%s zone=ng_guard_rate_site_%s:10m rate=%sr/s;" %
                (site_id, site_id, rate)
            )
            for index, (path, path_rate, _path_burst) in enumerate(self._rate_path_settings(site)):
                key_name = "ng_guard_url_key_%s_%s" % (site_id, index)
                zone_name = "ng_guard_url_%s_%s" % (site_id, index)
                path_pattern = re.escape(path.rstrip("/")).replace('"', '\\"')
                lines.extend([
                    "map $uri $%s {" % key_name,
                    '    default "";',
                    '    "~*^%s(?:/|$)" $ng_guard_rate_key_%s;' % (path_pattern, site_id),
                    "}",
                    "limit_req_zone $%s zone=%s:1m rate=%sr/s;" %
                    (key_name, zone_name, path_rate),
                ])
            for index, custom in enumerate(site.get("custom_rules", []) or []):
                try:
                    rule = validate_custom_rule(custom)
                except (PolicyError, ValueError) as exc:
                    raise NginxCommandError("invalid custom rule: %s" % exc)
                if not rule["enabled"] or rule["action"] in {"allow", "monitor"}:
                    continue
                try:
                    status = 403 if rule["action"] == "block" else int(rule["action"])
                except (TypeError, ValueError):
                    continue
                if status not in {403, 404, 429, 444}:
                    continue
                match = rule["match"]
                variable = {
                    "uri_contains": "$request_uri",
                    "uri_regex": "$request_uri",
                    "query_contains": "$args",
                    "method": "$request_method",
                    "ip": "$remote_addr",
                    "user_agent": "$http_user_agent",
                    "host": "$host",
                    "header": "$http_%s" % rule.get("header", "x-requested-with"),
                }.get(match)
                if not variable:
                    continue
                pattern = rule["pattern"]
                if match in {"uri_contains", "query_contains", "method", "ip", "user_agent", "host", "header"}:
                    pattern = re.escape(pattern)
                if match == "method":
                    pattern = "^" + pattern + "$"
                match_var = "ng_guard_custom_match_%s_%s" % (site_id, index)
                hit_var = "ng_guard_custom_%s_%s" % (site_id, index)
                lines.extend([
                    "map %s $%s {" % (variable, match_var),
                    "    default 0;",
                    '    "~*%s" 1;' % pattern.replace('"', '\\"'),
                    "}",
                    'map "$ng_guard_ordinary_bypass_%s:$%s" $%s {' % (site_id, match_var, hit_var),
                    "    default 0;",
                    '    "0:1" 1;',
                    "}",
                ])
        if lua_available:
            lines.extend([
                "lua_shared_dict ng_guard_cc 4m;",
                "lua_shared_dict ng_guard_ban 4m;",
                "init_by_lua_file %s;" % (self.data_root / "engine" / "init.lua").as_posix(),
                "init_worker_by_lua_file %s;" % (self.data_root / "engine" / "worker.lua").as_posix(),
            ])
        if not global_enabled:
            lines.append("# engine disabled; fragments remain inert")
        return "\n".join(lines) + "\n"

    def _render_site(self, site, lua_available=False, limit_req_dry_run=True):
        site_id = normalize_site_id(site.get("id"))
        mode = str(site.get("mode", "MONITOR")).upper()
        rate, burst = self._rate_settings(site)
        patterns = native_patterns()
        streaming_paths = []
        for value in site.get("streaming_paths") or []:
            try:
                streaming_paths.append(validate_streaming_path(value))
            except ValidationError as exc:
                raise NginxCommandError("流式路径无效：%s" % exc) from exc
        use_rate_limit = mode == "BLOCK" or bool(limit_req_dry_run)
        use_lua = lua_available and str(site.get("engine", "auto")).lower() in {"auto", "lua"}
        lines = [
            "# Generated by Nginx Guard for site %s." % site_id,
            'set $ng_guard_site_id "%s";' % site_id,
            'set $ng_guard_lua_rule_id $ng_guard_site_log_rule_id_%s;' % site_id,
        ]
        if mode != "OFF":
            lines.append("access_log %s ng_guard_json buffer=64k flush=5s;" % (
                (self.data_root / "logs" / ("events-site-%s.jsonl" % site_id)).as_posix()
            ))
            if use_rate_limit:
                lines.append("limit_req_log_level notice;")
                lines.append("limit_req_status 429;")
                lines.append("limit_req zone=ng_guard_rate_site_%s burst=%s nodelay;" % (site_id, burst))
                for index, (_path, _path_rate, path_burst) in enumerate(self._rate_path_settings(site)):
                    lines.append(
                        "limit_req zone=ng_guard_url_%s_%s burst=%s nodelay;" %
                        (site_id, index, path_burst)
                    )
            if mode == "BLOCK":
                lines.append('if ($ng_guard_ip_block_%s = 1) { return 403; }' % site_id)
                # Native maps identify the rule; when Lua is available the
                # access hook makes the decision and updates temporary-ban
                # counters.  Direct returns remain the no-Lua fallback.
                if not use_lua:
                    for rule_id, variable, pattern in (
                        ("NG1001", "$request_uri", patterns["sensitive"]),
                        ("NG1002", "$request_uri", patterns["traversal"]),
                        ("NG1003", "$args", patterns["metadata"]),
                    ):
                        status = self._builtin_status(site, rule_id)
                        if status is not None:
                            lines.append('if (%s ~* "%s") { return %s; }' % (variable, pattern, status))
                    for rule_id, variable in (
                        ("NG2001", "$ng_guard_site_request_rule_%s" % site_id),
                        ("NG2002", "$ng_guard_site_request_rule_%s" % site_id),
                        ("NG2003", "$ng_guard_site_ua_rule_%s" % site_id),
                    ):
                        status = self._builtin_status(site, rule_id)
                        if status is not None:
                            lines.append('if (%s = %s) { return %s; }' % (variable, rule_id, status))
            elif limit_req_dry_run:
                lines.append("limit_req_dry_run on;")
            else:
                lines.append("# 当前 Nginx 不支持 limit_req_dry_run，监控模式不启用限流以避免误拦截。")
            lines.append(
                "# Native mode handles metadata rules and primary CC; Lua, when available, handles bounded text bodies."
            )
            for index, custom in enumerate(site.get("custom_rules", []) or []):
                if use_lua:
                    continue
                try:
                    rule = validate_custom_rule(custom)
                except (PolicyError, ValueError) as exc:
                    raise NginxCommandError("invalid custom rule: %s" % exc)
                action = rule["action"]
                if action in {"allow", "monitor"} or not rule["enabled"]:
                    continue
                status = 403 if action == "block" else int(action)
                if status not in {403, 404, 429, 444}:
                    continue
                if rule["match"] == "method" and not re.fullmatch(r"[A-Za-z]+", rule["pattern"]):
                    raise NginxCommandError("custom method must contain letters only")
                lines.append(
                    "if ($ng_guard_custom_%s_%s = 1) { return %s; }" %
                    (site_id, index, status)
                )
            if streaming_paths:
                lines.append("# WebSocket/SSE compatibility paths (keep original proxy, Upgrade, Connection and buffering settings):")
                for path in streaming_paths:
                    lines.append("# NGINX_GUARD_STREAMING %s" % path)
            if use_lua:
                lines.extend([
                    "access_by_lua_file %s;" % (self.data_root / "engine" / "access.lua").as_posix(),
                ])
        return "\n".join(lines) + "\n"

    def apply(
        self,
        global_enabled=True,
        sites=None,
        lua_available=False,
        cloudflare=None,
        limit_req_dry_run=True,
        real_ip_available=True,
    ):
        sites = list(sites or [])
        global_target = self.http_config_path() if global_enabled else None
        marker_paths = self._global_marker_paths()
        global_paths = list(marker_paths)
        if global_target is not None:
            global_paths.append(global_target)
        if not global_paths:
            global_paths = [self.nginx_conf]
        global_paths = self._unique_paths(global_paths)
        self.generated_root.mkdir(parents=True, exist_ok=True)
        self.backup_root.mkdir(parents=True, exist_ok=True)
        vhosts = []
        normalized_sites = []
        for site in sites:
            site_id, vhost = self._find_vhost(site)
            vhosts.append(vhost)
            normalized_sites.append((site_id, vhost, site))
        all_vhosts = [
            path for path in self.vhost_dir.glob("*.conf")
            if path.is_file() and not path.is_symlink()
        ] if self.vhost_dir.is_dir() else []
        generated = [
            self.generated_root / "global.conf",
            self.data_root / "runtime" / "snapshot.lua",
            self.data_root / "runtime" / "version",
        ] + [self.generated_root / ("site-%s.conf" % site_id) for site_id, _vhost, _site in normalized_sites]
        expected_generated = {path.absolute() for path in generated}
        stale_generated = [
            path
            for path in self.generated_root.glob("site-*.conf")
            if path.is_file() and not path.is_symlink() and path.absolute() not in expected_generated
        ]
        generated.extend(stale_generated)
        touched = self._unique_paths([self.nginx_conf] + global_paths + all_vhosts + generated)
        backup_dir, records = self._backup(touched)
        try:
            version = int(time.time() * 1000)
            global_fragment = self.generated_root / "global.conf"
            _atomic_write(
                global_fragment,
                self._render_global(
                    global_enabled,
                    lua_available,
                    sites,
                    cloudflare=cloudflare,
                    real_ip_available=real_ip_available,
                ),
                mode=0o644,
            )
            _atomic_write(
                self.data_root / "runtime" / "snapshot.lua",
                self._render_snapshot(sites, version=version),
                mode=0o644,
            )
            _atomic_write(
                self.data_root / "runtime" / "version",
                "return %s\n" % version,
                mode=0o644,
            )
            global_snippet = "%s\ninclude %s;\n%s" % (
                self.global_begin,
                global_fragment.as_posix(),
                self.global_end,
            )
            for path in global_paths:
                current = path.read_text(encoding="utf-8")
                cleaned = _remove_marker(current, self.global_begin, self.global_end)
                if global_enabled and path == global_target:
                    cleaned = _insert_inside_block(cleaned, "http", global_snippet)
                if cleaned != current:
                    _atomic_write(path, cleaned)
            for vhost in all_vhosts:
                current = vhost.read_text(encoding="utf-8")
                cleaned = self._remove_all_site_markers(current)
                if cleaned != current:
                    _atomic_write(vhost, cleaned)
            for site_id, vhost, site in normalized_sites:
                fragment = self.generated_root / ("site-%s.conf" % site_id)
                _atomic_write(
                    fragment,
                    self._render_site(
                        site,
                        lua_available,
                        limit_req_dry_run=limit_req_dry_run,
                    ),
                    mode=0o644,
                )
                current = vhost.read_text(encoding="utf-8")
                if global_enabled and str(site.get("mode", "MONITOR")).upper() != "OFF":
                    _atomic_write(vhost, self._patch_site(current, site_id, fragment))
            for path in stale_generated:
                try:
                    path.unlink()
                except OSError as exc:
                    raise NginxCommandError("无法清理旧的生成配置：%s" % path) from exc
            self.runner.test_config()
            self.runner.reload()
        except Exception as exc:
            self._rollback_and_revalidate(records, exc, "应用配置")
        return {
            "ok": True,
            "backup": str(backup_dir),
            "sites": [site_id for site_id, _vhost, _site in normalized_sites],
        }

    def restore_backup(self, name):
        """Restore one owned backup directory, validate it, then reload safely."""

        backup_name = safe_filename(name)
        directory = self.backup_root / backup_name
        if (
            directory.is_symlink()
            or not directory.is_dir()
            or directory.parent != self.backup_root
        ):
            raise NginxCommandError("backup does not exist")
        manifest_path = directory / "manifest.json"
        if not manifest_path.is_file() or manifest_path.is_symlink():
            raise NginxCommandError("backup manifest is missing")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise NginxCommandError("backup manifest is invalid") from exc
        allowed = {self.nginx_conf}
        try:
            allowed.update(self.config_graph_paths())
        except NginxCommandError:
            # The main file may itself be the damaged file being restored;
            # the manifest/root checks below still protect the restore target.
            pass
        if self.vhost_dir.is_dir():
            allowed.update(self.vhost_dir.glob("*.conf"))
        allowed.update({
            self.generated_root / "global.conf",
            self.data_root / "runtime" / "snapshot.lua",
            self.data_root / "runtime" / "version",
        })
        if self.generated_root.is_dir():
            allowed.update(self.generated_root.glob("site-*.conf"))
        if not isinstance(manifest, list):
            raise NginxCommandError("backup manifest is invalid")
        records = []
        for item in manifest:
            if not isinstance(item, dict):
                raise NginxCommandError("backup manifest is invalid")
            try:
                path = Path(item.get("path", ""))
                backup_path = directory / safe_filename(item.get("backup", ""))
            except (TypeError, ValueError, ValidationError) as exc:
                raise NginxCommandError("backup manifest is invalid") from exc
            existed = item.get("exists")
            if (
                (path not in allowed and not self._restore_path_is_safe(path))
                or backup_path.parent != directory
                or backup_path.is_symlink()
                or not path.is_absolute()
                or not isinstance(existed, bool)
                or (existed and not backup_path.is_file())
                or (not existed and backup_path.exists())
            ):
                raise NginxCommandError("backup contains an unexpected path")
            records.append((path, backup_path, existed))

        # Save the currently active state before applying a user-selected
        # backup.  This makes a corrupt/obsolete selected backup recoverable.
        _before_directory, before_records = self._backup(
            self._transaction_paths(records),
            prune=False,
        )
        try:
            self._restore(records)
            self.runner.test_config()
            self.runner.reload()
        except Exception:
            try:
                self._restore(before_records)
                self.runner.test_config()
                self.runner.reload()
            except Exception as recovery_error:
                raise NginxCommandError(
                    "备份恢复失败，且恢复当前配置后验证或 reload 也失败：%s"
                    % recovery_error
                ) from recovery_error
            raise
        self._prune_backups()
        return {"ok": True, "backup": str(directory)}

    def remove(self):
        """Remove plugin markers and reload only after nginx -t succeeds."""

        targets = [self.nginx_conf]
        targets.extend(self._global_marker_paths())
        if self.vhost_dir.is_dir():
            targets.extend(
                path for path in self.vhost_dir.glob("*.conf")
                if path.is_file() and not path.is_symlink()
            )
        targets = self._unique_paths(targets)
        backup_dir, records = self._backup(targets)
        try:
            for path in targets:
                text = path.read_text(encoding="utf-8")
                patched = _remove_marker(text, self.global_begin, self.global_end)
                patched = self._remove_all_site_markers(patched)
                if patched != text:
                    _atomic_write(path, patched)
            self.runner.test_config()
            self.runner.reload()
        except Exception as exc:
            self._rollback_and_revalidate(records, exc, "停用防护")
        return {"ok": True, "backup": str(backup_dir)}
