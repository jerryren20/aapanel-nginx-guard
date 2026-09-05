# WAFPro 参考分析

本项目从 https://github.com/ByEzel93/wafpro 的浅克隆版本读取并分析了 README.md、info.json、install.sh、engine/init.lua、engine/worker.lua、engine/waf.lua、engine/wafpro.lua 和 engine/wafpro.conf，​​只借鉴结构和思路，没有复制项目。

## aaPanel 部分

WAFPro 展示了 aaPanel 第三方插件的常见根目录：info.json、install.sh、Python controller、index.html 和 icon.png。Python 类名与 plugin_main.py 对齐，前端通过 /plugin?action=a&name=plugin&s=method 访问后端，网站数据可从 aaPanel 的 sites 模型读取。Nginx 相关数据和运行时文件放在插件/系统目录中，安装脚本负责准备目录与 Lua 资源。

Nginx 操作上，参考实现会备份、生成 include、执行 nginx -t 并 reload；它还使用 shared dict、init/init-worker 和版本文件缓存规则。

## WAF 部分

参考实现包含 IP 黑名单/白名单、CC、URI/GET/POST/Cookie/User-Agent 检查、规则和攻击日志、Dashboard、自动封禁以及 Lua 缓存。shared dict 适合保存短 TTL 计数和动态封禁，不需要每次封 IP 都 reload。

## 不直接采用的部分

WAFPro 的核心接入是 Nginx 全局 access phase。其 README 已经提示这种全局 hook 对 Node.js、Nuxt、Next.js、反向代理、WebSocket 和流式请求有兼容风险，可能出现 503。全局 hook 还扩大了所有站点的故障半径；对本项目“已有反代、WebSocket、SSE 不受影响”的目标不合适。

因此 Nginx Guard 采用：

- 全局只放 map/geo/limit zone/可选 Lua 初始化，不放统一拦截逻辑；
- 站点独立 marker + include，OFF 站点不接入；
- Native 高风险规则在 server 级安全 return；
- Lua 只在选择的站点和 access 元数据阶段运行；
- 不读 Body，不加 body filter/response filter，不创建覆盖式 location；
- Lua 异常 fail-open，配置生成和 nginx -t 失败 fail-closed；
- 自动封禁只使用 shared dict TTL，不 reload Nginx；
- 每次写配置都保留 manifest 备份，卸载只删除自有 marker。

## 重新实现的原因

原项目的 aaPanel UI/API 约定和 Lua 缓存概念可以参考，但站点隔离、反代兼容、streaming 路径语义、日志脱敏、配置事务和安全边界必须重新实现。特别是 Cloudflare Real IP 不能只看 Header，必须先判断 remote_addr 是否在官方网段；这一点在本项目中由 Nginx realip 配置和 Python 校验共同约束。

