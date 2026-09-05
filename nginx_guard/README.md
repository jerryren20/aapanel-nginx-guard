# Nginx Guard 1.0.13

Nginx Guard 是一个面向 aaPanel Nginx 的轻量、按站点启用的 WAF 插件。生产界面使用 aaPanel 风格的绿色主题，安装后默认关闭，不会在安装阶段改写 Nginx。

## 设计重点

- 原生 Nginx 高置信度规则优先，检测到 Lua 模块时可按站点选择 Lua 运行时。
- 只使用受控 BEGIN/END marker 和独立 include；不会整体重写 aaPanel 的 nginx.conf 或站点文件。
- 每次应用按 backup → 生成 → nginx -t → 原子替换 → reload 执行，失败自动恢复；事务备份最多保留最近 3 个。
- Lua 可用时仅对声明长度不超过 1 MB、且属于 JSON/表单/XML/text/* 的请求体做检查；未知长度、压缩、multipart、二进制和媒体请求直接跳过。不执行响应过滤，不创建新的覆盖式 location，因此不会改变 Node、Python、Java、PHP、Docker 反代的应用协议。
- WebSocket 只保留 Upgrade/Connection 兼容配置；SSE 走原有 proxy location，不做 body/response filter。
- 日志使用 Nginx buffered JSONL，默认单文件 20 MB、保留 7 天、总量最多 100 MB；插件查询和应用配置时会兜底清理，系统 logrotate 可用时也会轮转。
- 攻击日志支持保留网站筛选、仅显示实际拦截记录，并分别展示 Cloudflare 边缘 IP（CFIP）和真实客户端 IP；历史日志缺少字段时自动兼容。
- Cloudflare 页面支持输入单个 IPv4/IPv6 查询当前生效网段及来源（官方/手动），查询不会保存配置或 reload Nginx。

## v1 功能

网站 OFF / MONITOR / BLOCK、敏感文件、路径穿越、云元数据 SSRF、IP 黑白名单、静态资源排除的 CC 限流、Cloudflare Real IP、攻击日志、Dashboard、备份/恢复、SSH 紧急停用、可控自定义 URI/Query/Method/Host/User-Agent 规则。

SQLi、XSS 和扫描器 User-Agent 内置默认为拦截，可在规则页切换为监控；已有明确覆盖配置继续保留。高风险敏感文件、路径穿越和云元数据 SSRF 不受接口白名单绕过。

Lua 可用时，站点的攻击阈值可写入 Nginx shared dict，按 TTL 临时封禁 IP；Native 降级模式不使用防火墙，保留原生限流和静态黑名单。

## 安装

1. 在 aaPanel 的 App Store → Third-party Plugin → Import 导入 dist/nginx_guard-1.0.13.zip。
2. 打开 Nginx Guard，确认网站列表和诊断信息。
3. 先将站点设为 MONITOR，保存后点击右上角“应用配置”。
4. 观察日志确认误报，再切换到 BLOCK。

安装脚本只创建 /www/server/nginx_guard/ 目录，不注册 systemd/timer，不启动常驻进程，也不接管 Nginx；引擎保持关闭，所有配置和“应用配置”操作都在 aaPanel 插件页面完成。marker 只在页面点击“应用配置”时校正。

## 紧急恢复

如果 aaPanel 页面无法打开，SSH 执行：

    bash /www/server/nginx_guard/bin/disable.sh

脚本只移除 Nginx Guard 自己的 marker，执行 nginx -t，成功后 reload；失败会恢复本次备份。备份默认保留在 /www/server/nginx_guard/backup/。

## 路径

插件代码：/www/server/panel/plugin/nginx_guard/

运行数据：/www/server/nginx_guard/

核心配置：/www/server/nginx_guard/config/desired.json

生成片段：/www/server/nginx_guard/generated/

日志：/www/server/nginx_guard/logs/events-site-*.jsonl

## 文档

- 架构与请求流程：docs/ARCHITECTURE.md
- 安装与操作：docs/INSTALL.md
- 安全模型：docs/SECURITY.md
- 测试与兼容性：docs/TESTING.md
- 恢复与回滚：docs/RECOVERY.md
- WAFPro 参考分析：docs/WAFPRO_ANALYSIS.md

## 已知限制

Native 模式不解析 POST Body，也不提供 JavaScript Challenge、CAPTCHA、GeoIP 或云端恶意 IP 库。Lua 请求体检查只处理 JSON、表单、XML、text/* 和不超过 1 MB 的内存文本；multipart、二进制、压缩包、媒体和超限请求跳过。站点已有的 location 仍然是 WebSocket/SSE 的最终代理配置来源，插件不创建同路径的第二个 location。
