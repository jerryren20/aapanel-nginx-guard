# 安全模型

## 输入校验

- 站点 ID 只接受 1-19 位正整数，并在真实 aaPanel 环境中再次与 sites 表比对。
- IP 地址使用标准库 ipaddress 校验，支持 IPv4、IPv6 和 CIDR。
- 文件名只允许 ASCII 字母、数字、点、下划线和短横线。
- 自定义规则限制长度、动作和匹配类型；明显的嵌套量词、回溯、反向引用、控制字符和 Nginx directive 字符拒绝。
- 查询字符串在展示/聚合前脱敏，Token、密码、Authorization、Cookie 等不进入攻击日志字段。

## 命令与文件

Nginx 命令使用固定绝对路径和参数列表，subprocess.run 不使用 shell=True。关键文件不直接 open(path, w) 覆盖，而是同目录临时文件 + flush + fsync + replace。

Marker、生成目录、站点 ID 和备份 manifest 都有范围校验。检测到关键输入是符号链接时拒绝操作，避免通过链接写到插件范围外。

## Cloudflare

只有 remote_addr 命中已保存网段时才使用 CF-Connecting-IP。网段只能通过官方 IPv4/IPv6 地址获取或由安全管理员导入；没有有效网段时保持 remote_addr。不能只因为 Header 存在就信任它。

## 运行时策略

Nginx 配置生成或 nginx -t 失败是 fail-closed：不 reload 并自动回滚。请求阶段 Lua 错误是 fail-open：记录错误并继续应用流量，优先保持 Node、Python、Java、PHP、Docker、WebSocket 和 SSE 可用。高风险规则不受普通白名单绕过。

## 日志

日志使用 buffered access log，默认单文件不超过 20 MB，保留 7 天、总量不超过 100 MB。正常请求也可能出现在站点访问日志中；Dashboard 通过 rule_id、状态和动作统计，不把密码、Cookie、Authorization、Token 或请求 Body 写入日志。插件只清理自己的 events-site-*.jsonl、生成片段和事务备份。

## 当前不包含

没有主机防火墙、nftables/ipset、远程恶意 IP 云库、JS Challenge、CAPTCHA 或响应内容过滤。Lua 可选地对声明长度不超过 1 MB 的 JSON、表单、XML 和 text/* 请求体做检查；未知长度、multipart、二进制、媒体、压缩包和超限请求跳过。这些边界用于避免扩大 Docker、Node、Python、Java、PHP、静态站点、WebSocket 和 SSE 的故障面。
