# aaPanel Nginx Guard

Nginx Guard 是面向 aaPanel Nginx 的轻量级、按站点启用的 WAF 插件。它通过 Nginx 原生规则提供请求检测和限流；检测到 Lua 模块时，还可选择启用有限的请求体检查。

插件默认关闭。安装不会改写 Nginx 配置；只有在 aaPanel 页面点击“应用配置”后，插件才会备份并更新自己管理的配置片段。

## 功能概览

- 按站点选择 `OFF`、`MONITOR` 或 `BLOCK` 模式。
- 检测敏感文件探测、路径穿越、云元数据 SSRF、SQL 注入、XSS 和扫描器 User-Agent。
- 使用 Nginx `limit_req` 做 CC 限流，支持按站点和 URL 路径配置。
- 管理 IP 黑名单、白名单、接口白名单和自定义规则。
- 可选配置 Cloudflare Real IP；仅当连接来源匹配已保存的 Cloudflare 网段时才信任转发 IP。
- 查看和分析结构化攻击日志，导出聚合 CSV。
- 应用配置前创建事务备份；`nginx -t` 或 reload 失败时自动恢复。

## 环境要求

- aaPanel 与其管理的 Nginx，使用 aaPanel 插件导入方式安装。
- 插件按 aaPanel 常见目录布局查找 Nginx 和站点配置。首次应用前，建议在“诊断”页确认检测到的 Nginx、HTTP 配置和 vhost 状态。
- Lua/OpenResty 模块是可选项。没有 Lua 时，Native 规则和 Nginx 原生限流仍可用；请求体检查和 Lua 临时封禁不可用。

## 构建插件 ZIP

在仓库根目录运行：

```powershell
python scripts/build_zip.py
```

脚本从 `nginx_guard/info.json` 读取版本号，并生成：

```text
dist/nginx_guard-<版本号>.zip
```

当前版本生成 `dist/nginx_guard-1.0.15.zip`。压缩包的顶层目录是 `nginx_guard/`，可直接导入 aaPanel。打包脚本只收录 `nginx_guard/` 插件目录；仓库根目录的 README、测试和构建脚本不会放入插件包。

项目使用 Python 标准库构建，无需额外安装 Python 包。可运行单元测试：

```powershell
python -m unittest discover -s tests -v
```

测试覆盖配置存储、规则、Nginx 配置事务、日志、Cloudflare、Lua 边界和 ZIP 布局。目标 Linux/Nginx 的集成检查建议参考[测试说明](nginx_guard/docs/TESTING.md)。

## 在 aaPanel 中安装和使用

1. 运行上面的构建命令，在 aaPanel 的 **App Store → Third-party Plugin → Import** 导入生成的 ZIP。
2. 打开 Nginx Guard，先查看“诊断”页，确认 Nginx 路径、配置文件和 Lua 能力。
3. 在“网站防护”中选择一个站点，先设置为 `MONITOR` 并保存。
4. 点击右上角“应用配置”。插件会备份相关文件、生成配置、运行 `nginx -t`，通过后才 reload Nginx。
5. 检查攻击日志和站点行为；确认没有误报后，再将该站点切换为 `BLOCK` 并再次应用配置。

保存配置不会立即改动 Nginx。每次保存后，都需要点击“应用配置”使期望配置生效。

Cloudflare 用户可在 Cloudflare 页面更新官方网段、添加需要的手动网段，启用 Real IP 后再应用配置。刷新官方网段不会覆盖手动网段。

## 运行行为与限制

- Native 模式使用 Nginx 原生 `map`、`geo`、`limit_req` 和 server 级规则，不需要独立 WAF 服务。
- Lua 只检查声明长度不超过 1 MB 的 JSON、表单、XML 或 `text/*` 请求体。未知长度、压缩、multipart、二进制、媒体和超限请求体会跳过；不检查响应内容。
- 插件不会新建覆盖式 `location`，WebSocket、SSE 和反向代理继续使用站点原有的代理配置。
- 请求阶段 Lua 异常会记录并放行；配置生成或 Nginx 校验失败会回滚。
- 项目不提供主机防火墙、JavaScript Challenge、CAPTCHA、GeoIP 或云端恶意 IP 库。

## 配置与恢复路径

| 内容 | 路径 |
|---|---|
| aaPanel 插件代码 | `/www/server/panel/plugin/nginx_guard/` |
| 插件运行数据 | `/www/server/nginx_guard/` |
| 全局期望配置 | `/www/server/nginx_guard/config/desired.json` |
| 生成的 Nginx 配置片段 | `/www/server/nginx_guard/generated/` |
| 结构化日志 | `/www/server/nginx_guard/logs/events-site-*.jsonl` |
| 事务备份 | `/www/server/nginx_guard/backup/` |

如果 aaPanel 页面无法打开，可通过 SSH 执行紧急停用脚本。它只移除 Nginx Guard 自己的配置 marker，并在校验成功后 reload：

```bash
bash /www/server/nginx_guard/bin/disable.sh
```

恢复步骤和卸载行为见[恢复说明](nginx_guard/docs/RECOVERY.md)及[安装说明](nginx_guard/docs/INSTALL.md)。

## 项目结构

```text
nginx_guard/          aaPanel 插件源码、界面、Lua 引擎和文档
scripts/build_zip.py  构建 aaPanel 导入包
tests/                Python 单元测试
dist/                 构建生成的 ZIP（由 Git 忽略）
```

更多资料：

- [插件说明](nginx_guard/README.md)
- [架构与请求流程](nginx_guard/docs/ARCHITECTURE.md)
- [安装、配置和卸载](nginx_guard/docs/INSTALL.md)
- [安全模型](nginx_guard/docs/SECURITY.md)
- [恢复和回滚](nginx_guard/docs/RECOVERY.md)
- [测试和兼容性](nginx_guard/docs/TESTING.md)
