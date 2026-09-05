# Nginx Guard 架构

## 请求流程

    Client / Cloudflare
            ↓
    Nginx realip（仅当 remote_addr 在已保存的 Cloudflare 网段）
            ↓
    站点 marker → generated/site-<id>.conf
            ↓
    Native server-level high-confidence checks
            ↓
    可选 Lua access phase（最多 1 MB 文本 Body、pcall fail-open）
            ↓
    原有 location / proxy_pass / PHP-FPM / 静态文件

MONITOR 只记录和 dry-run，不返回阻断状态；BLOCK 才返回 403 或 429。高风险规则为敏感文件、路径穿越和云元数据 SSRF。接口/IP 白名单可绕过普通规则、请求体检查和 CC，但不能绕过高风险规则。

## 配置边界

Python 只维护期望状态。站点配置存储在 config/desired.json 和 config/sites/site-<id>.json，关键写入使用同目录临时文件、fsync 和 os.replace。

Nginx Manager 只在两个位置加自有 marker。全局 marker 会写入当前配置树中真正拥有 `http {}` 的文件，并紧跟在开括号之后，确保 `log_format`、`map` 和 `geo` 定义先于 aaPanel 的 vhost include 被解析；如果 `nginx.conf` 通过 `include` 引入了 http 配置块，则写入被引入的文件，主配置本身不会被误改：

    # BEGIN NGINX_GUARD_GLOBAL
    include /www/server/nginx_guard/generated/global.conf;
    # END NGINX_GUARD_GLOBAL

    # BEGIN NGINX_GUARD_SITE:123
    include /www/server/nginx_guard/generated/site-123.conf;
    # END NGINX_GUARD_SITE:123

它不会根据用户输入拼接 shell 命令，也不会覆盖 aaPanel 的其他行。一个站点文件中如果有 HTTP/HTTPS 多个 server 块，会在每个块中插入相同的站点 include。

## 引擎

Native 模式使用 map、geo、limit_req、安全的 server-level if ... return，NG2001–NG2003 默认拦截并使用明确的 429 限速状态。静态扩展名在 rate key map 中使用空 key，不占用动态请求额度。

Lua 模式由 init_by_lua_file 加载缓存模块，由 worker timer 每 5 秒检查 runtime/version，从 runtime/snapshot.lua 更新规则。请求 hook 只调用缓存对象；仅在非 GET、非升级请求中读取声明长度不超过 1 MB 的 JSON、表单、XML 或 text/* Body；未知长度、压缩、multipart、二进制和媒体请求不读取并跳过，不读取临时文件，不使用响应过滤器。Lua 异常通过 pcall 记录并放行，避免把应用变成 503；主要 CC 统一由 Native limit_req 执行。

## 应用事务

    读取站点 / 生成片段 / 备份原文件
                    ↓
    临时写入并原子替换
                    ↓
    nginx -t
           ├─失败 → 恢复本次备份，不 reload
           └─成功 → reload
                        └─失败 → 恢复本次备份

插件不注册 systemd/timer，也不启动独立常驻进程。marker 校正和日志轮转只由 aaPanel 页面中的显式操作触发；保存配置不会 reload，点击“应用配置”才执行完整事务。
