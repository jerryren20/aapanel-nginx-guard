# 测试和兼容性

## 自动测试

在源码目录执行：

    python -m unittest discover -s tests -v

覆盖输入校验、原子 JSON、Nginx marker、多 server 块、备份恢复、Cloudflare 信任边界、规则匹配、日志聚合/轮转、Lua 请求路径约束和 aaPanel 包布局。

## Nginx 集成测试建议

在 Rocky Linux / AlmaLinux / RHEL 9 的 aaPanel 测试机上准备 PHP、静态、proxy_pass、Node、Python、Java/Docker、WebSocket 和 SSE 站点。按以下顺序验证：

    curl -i https://example.com/
    curl -i https://example.com/.env
    curl -i https://example.com/.git/HEAD
    curl -i 'https://example.com/?file=../../../../etc/passwd'
    curl -i 'https://example.com/webhook?url=http://169.254.169.254/latest/meta-data/'

正常请求应保持应用原状态；BLOCK 站点对四类高风险请求应返回 403。MONITOR 站点不阻断但应在访问 JSONL 中出现 rule_id。对动态路径做 100/500 req/s 压测时，应观察 Nginx worker、PHP-FPM、应用进程、CPU、RAM 和磁盘 IO。

WebSocket 要确认 Upgrade/Connection 仍能握手；SSE 要确认 text/event-stream 长连接没有被 Lua body/response filter 干扰。插件不创建新 location，因此如果原 vhost 没有正确的 proxy_http_version 1.1、超时或 SSE buffering 配置，应在原站点 location 中补齐。

Windows 开发机只能完成 Python 单元测试、UI 静态检查和 ZIP 内容检查，不能替代目标 Linux/Nginx 集成压测。

