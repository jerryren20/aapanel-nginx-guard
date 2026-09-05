# 安装、配置和卸载

## 导入

构建产物为 dist/nginx_guard-1.0.15.zip，ZIP 顶层目录为 nginx_guard/，aaPanel 解压后应位于 /www/server/panel/plugin/nginx_guard/。info.json、install.sh、uninstall.sh、index.html、nginx_guard_main.py 和 icon.png 均位于该目录根部。

安装脚本创建：

    /www/server/nginx_guard/
    ├── config/
    ├── rules/
    ├── sites/
    ├── cache/
    ├── logs/
    ├── backup/
    ├── generated/
    ├── runtime/
    ├── engine/
    └── bin/

默认 engine_enabled=false。若机器没有 Lua 模块，Native 仍负责元数据规则、SQLi/XSS/扫描器和 CC，只有请求体检查不可用；lua 选择会在应用结果中明确提示已安全降级为 Native。

安装过程不注册 systemd/timer，不启动独立 WAF 服务。插件只由 aaPanel 页面后端按需执行；Nginx Guard 的规则运行在 Nginx 自身的 Native/Lua 配置中。

## 建议操作顺序

1. 诊断页确认 Nginx 路径、http 配置块实际所在文件、vhost 目录和 Lua 能力。
2. 网站页选择一个站点，设为 MONITOR，填 WebSocket/SSE 路径（只作为兼容声明，不创建新 location）。
3. 保存，然后点击“应用配置”，等待 backup、nginx -t、reload 全部成功。事务备份只保留最近 3 个。
4. 查看攻击日志和规则 ID；确认正常请求、反代、WebSocket、SSE。
5. 只把确认过的站点切换为 BLOCK。
6. Cloudflare 页面先更新官方网段，可在同页添加手动网段，再显式打开 Real IP，最后应用配置。刷新官方列表不会覆盖手动网段。

日志默认单文件 20 MB、保留 7 天、总量 100 MB；应用配置、日志查询和显式轮转都会清理 Nginx Guard 自己的日志。安装时若系统允许，会写入 /etc/logrotate.d/nginx_guard；不创建常驻服务。事务备份只保留最近 3 份。

保存和应用是两个动作。保存不会 reload，避免用户编辑多个字段时反复打断业务。

## 卸载

aaPanel 调用 uninstall.sh。脚本先执行紧急 disable，确认 Nginx 配置可测且已 reload，再移除自身运行目录中的配置、日志、运行时和引擎文件。backup/ 保留用于审计和恢复；插件代码目录由 aaPanel 处理。
