# 恢复和回滚

## 页面应用失败

应用时如果 nginx -t 失败，插件自动恢复本次事务涉及的主配置、实际拥有 `http {}` 的 include 配置文件、站点 vhost 和生成片段，不会 reload。UI 会返回错误并展示备份目录。

如果 reload 本身返回失败，插件仍恢复文件；运行中的旧 worker 通常继续使用旧配置。恢复后应在诊断页再次执行检查。

## 手工恢复备份

备份目录包含 manifest.json，记录原始路径和备份文件。页面的“备份与恢复”只展示最近 3 个事务备份；后端恢复接口只接受备份目录名，并限制在 /www/server/nginx_guard/backup/ 下面，恢复后重新执行 nginx -t 和 reload。插件创建新备份时会清理更早的备份目录。

## SSH 紧急停用

    bash /www/server/nginx_guard/bin/disable.sh

它会：

1. 备份当前 Nginx 主配置、可达的 include 配置和 vhost；
2. 删除 NGINX_GUARD_GLOBAL 与 NGINX_GUARD_SITE:<id> 自有 marker；
3. 执行固定路径的 nginx -t；
4. 成功后 reload，失败则恢复备份。

卸载前也会自动执行同一流程。不要手工删除 aaPanel vhost 文件或整个 nginx.conf。
