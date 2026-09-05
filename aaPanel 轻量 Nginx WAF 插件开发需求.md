# aaPanel 轻量 Nginx WAF 插件开发需求

## 一、项目目标

开发一个可以直接导入 aaPanel 的第三方插件：

项目暂定名称：

`Nginx Guard`

插件标识：

`nginx_guard`

项目参考：

https://github.com/ByEzel93/wafpro

首先完整下载并分析上述 wafpro 项目。

这个项目只能作为：

- aaPanel 插件目录结构参考
- Python 后端接口参考
- aaPanel 前端 UI 调用方式参考
- install.sh / uninstall.sh 参考
- Nginx 配置安全修改方式参考
- WAF 规则管理方式参考
- 日志统计 Dashboard 参考
- Lua WAF 架构参考

不要直接复制整个项目。

特别注意 wafpro 已知存在的架构限制：

它通过 Nginx 全局 access phase 挂载 Lua WAF，对于 Node.js、Nuxt、Next.js、WebSocket、proxy_pass、SSR、流式请求可能产生兼容问题。

我们的插件必须解决或绕开这个问题。

---

# 二、运行环境

目标服务器：

Rocky Linux / AlmaLinux / RHEL 9 系列。

控制面板：

aaPanel / 宝塔国际版。

Nginx：

aaPanel 编译安装的 Nginx。

常见路径：

```text
/www/server/nginx/
/www/server/nginx/conf/nginx.conf

/www/server/panel/
/www/server/panel/plugin/

/www/server/panel/vhost/nginx/

/www/wwwlogs/
```

插件安装位置：

```text
/www/server/panel/plugin/nginx_guard/
```

WAF 独立数据目录：

```text
/www/server/nginx_guard/
```

结构建议：

```text
/www/server/nginx_guard/
├── config/
├── rules/
├── sites/
├── cache/
├── logs/
├── backup/
└── runtime/
```

不得把大量运行数据存放到 aaPanel 插件代码目录。

---

# 三、开发第一步

在开始写代码之前：

1. Clone：

```bash
git clone https://github.com/ByEzel93/wafpro.git
```

2. 完整阅读：

```text
README.md
info.json
install.sh
wafpro_main.py
wafpro_dash.py
index.html

engine/init.lua
engine/worker.lua
engine/waf.lua
engine/wafpro.lua
engine/wafpro.conf
```

3. 输出一份：

```text
docs/WAFPRO_ANALYSIS.md
```

必须分析：

### aaPanel 插件部分

- info.json 格式
- install.sh 工作方式
- uninstall.sh 工作方式
- Python 后端如何向 aaPanel 暴露 API
- index.html 如何调用 Python API
- 网站列表如何获取
- aaPanel 数据和配置如何访问

### Nginx 部分

分析 wafpro 如何：

- 注入 Nginx
- nginx -t
- reload
- rollback
- backup
- 加载 Lua
- 使用 shared_dict
- 初始化 worker
- access phase 检测请求

### WAF 部分

分析：

- IP blacklist
- whitelist
- CC
- URI 检测
- GET
- POST
- Cookie
- User-Agent
- custom rules
- attack logging
- statistics
- auto-ban

然后说明：

哪些设计可以直接参考；

哪些设计不适合我们的目标；

哪些需要重新实现。

完成分析之后再开始编码。

---

# 四、核心设计原则

我们的插件优先目标不是：

“实现功能最多的 WAF”。

而是：

“低资源占用、稳定、不会把服务器拖死的轻量 WAF”。

服务器可能只有：

```text
2 CPU
1.5～2 GB RAM
```

所以必须严格控制：

CPU
RAM
磁盘 IO
日志量

禁止设计：

每个 HTTP 请求启动 Python。

禁止：

每个 HTTP 请求读取大量规则文件。

禁止：

每个 HTTP 请求执行 shell。

禁止：

每个 HTTP 请求重新解析完整 JSON 配置。

禁止：

高频写磁盘。

---

# 五、核心架构

请求链：

```text
Internet
   ↓
Cloudflare（可选）
   ↓
Nginx
   ↓
Nginx Guard
   ↓
安全请求
   ↓
PHP / Proxy / Static
```

攻击请求：

```text
Internet
   ↓
Nginx
   ↓
Nginx Guard
   ↓
Block
   ↓
444 / 403 / 429
```

尽量不要让明显攻击进入：

```text
PHP-FPM
Node.js
Java
Python
```

后端。

---

# 六、兼容性设计

必须支持：

### PHP 网站

例如：

WordPress
ThinkPHP
Laravel
ThinkCMF

### 静态网站

HTML
Vue build
React build

### Reverse Proxy

```nginx
proxy_pass
```

### Node.js

Node
Nuxt
Next.js

### WebSocket

```text
Upgrade
Connection: upgrade
```

### API

REST API

插件不能因为开启 WAF 导致：

```text
WebSocket 断开
SSE 失效
Next.js API 503
Nuxt navigation 503
proxy_pass 异常
```

---

# 七、不要默认采用 wafpro 的全局 access phase

wafpro 采用类似：

```nginx
lua_shared_dict ...
init_by_lua_file ...
init_worker_by_lua_file ...
access_by_lua_file ...
```

我们的实现必须首先评估这种方式的兼容性。

优先设计：

```text
全局基础配置
+
每站点独立 include
```

例如：

```text
/www/server/nginx_guard/sites/example.com.conf
```

站点配置：

```nginx
include /www/server/nginx_guard/sites/example.com.conf;
```

关闭某站点 WAF 时：

删除或禁用这个 include。

不能因为关闭一个网站 WAF：

reload 或影响其他网站配置内容。

---

# 八、第一阶段使用 Nginx 原生规则

v1.0 优先使用 Nginx 原生能力实现：

```text
map
location
if（仅安全 return 场景）
limit_req
limit_conn
geo
deny
allow
```

主要解决：

### Sensitive File Scan

默认检测：

```text
.env
.env.local
.env.production

.git
.git/HEAD
.git/config
.git-credentials

.aws
.aws/credentials

.azure

.vscode

wp-config.php.bak
wp-config.php.old
wp-config.php~
wp-config.php.swp

terraform.tfstate

docker-compose.yml
docker-compose.yaml

serverless.yml
serverless.yaml

application.yml
application.yaml

config.json
```

---

# 九、路径穿越攻击

检测：

```text
../
..%2f
%2e%2e
/etc/passwd
/etc/shadow
/proc/self/environ
/proc/1/environ
```

支持 URL decode 后再判断。

例如：

```text
/?file=../../../../etc/passwd
```

必须阻止。

---

# 十、Cloud Metadata SSRF

检测：

```text
169.254.169.254
```

包括：

```text
?url=http://169.254.169.254/
```

以及常见 metadata 路径。

---

# 十一、扫描器检测

识别短时间大量请求：

例如：

```text
一个 IP
1 分钟
超过 100 个动态请求
```

触发：

```text
Rate Limit
```

并记录：

```text
RATE_LIMIT
```

攻击类型。

---

# 十二、CC 防护

支持：

### 每 IP 请求速率

例如：

```text
5 req/s
10 req/s
20 req/s
```

### burst

例如：

```text
20
50
100
```

### URL 独立限流

例如：

```text
/wp-login.php
/xmlrpc.php
/api/
/search
```

### 动态请求和静态资源分离

以下默认不计入严格动态限速：

```text
.css
.js
.png
.jpg
.jpeg
.webp
.svg
.ico
.woff
.woff2
.ttf
```

---

# 十三、IP 管理

支持：

## Blacklist

IPv4
IPv6
CIDR

例如：

```text
1.2.3.4
1.2.3.0/24
```

## Whitelist

Whitelist 优先级必须高于普通 block 规则。

但涉及明显危险路径：

可以设计：

```text
strict mode
```

决定白名单是否可以绕过。

---

# 十四、自动封禁

支持：

```text
10 秒内 20 次攻击
```

或者：

```text
60 秒内 50 次攻击
```

自动封：

```text
10分钟
1小时
6小时
24小时
永久
```

禁止每次封 IP 都 reload Nginx。

需要设计动态 blacklist。

可以考虑：

Lua shared dict

或者：

nftables/ipset

但要充分评估资源消耗。

---

# 十五、观察模式

非常重要。

每网站支持：

```text
OFF
MONITOR
BLOCK
```

含义：

### OFF

完全关闭。

### MONITOR

检测攻击；

记录日志；

不拦截。

### BLOCK

检测并拦截。

新网站第一次启用 WAF：

默认：

```text
MONITOR
```

防止误杀。

---

# 十六、攻击日志

记录：

```text
time
site
client_ip
real_ip
method
host
uri
query
status
rule_id
rule_name
attack_type
user_agent
country
action
```

不要默认记录：

Cookie
Authorization
POST 密码
API Token

避免日志泄漏敏感信息。

---

# 十七、Cloudflare Real IP

插件必须识别：

如果网站使用 Cloudflare：

Nginx 看到的源地址可能是 Cloudflare IP。

必须支持：

```text
CF-Connecting-IP
```

但：

绝对不能无条件信任这个 Header。

只有请求来源 IP 位于 Cloudflare 官方 IP 段时：

才允许使用：

```text
CF-Connecting-IP
```

作为真实客户端 IP。

否则：

使用：

```text
remote_addr
```

避免攻击者伪造 Header 绕过 IP 限流。

---

# 十八、Dashboard

参考 wafpro 的 UI 思路，但重新实现。

首页显示：

```text
今日请求
今日攻击
今日封禁IP
当前WAF状态

最近24小时攻击趋势
```

Top：

```text
Top Attack IP
Top URI
Top Rule
Top Country
```

---

# 十九、网站页面

显示 aaPanel 所有网站：

```text
Domain
Type
Protection
Mode
Requests
Attacks
```

每网站支持：

```text
Enable
Disable

Monitor
Block
```

以及：

```text
CC配置
规则配置
白名单
黑名单
日志
```

---

# 二十、规则页面

内置规则分类：

```text
Sensitive File
Traversal
SSRF
Scanner
WordPress
PHP
SQL Injection
XSS
Bad Bot
Method
Header
Upload
```

每条规则：

```text
rule_id
name
description
enabled
severity
action
pattern
```

例如：

```json
{
  "id": "NG1001",
  "name": "Sensitive Environment File",
  "severity": "high",
  "enabled": true,
  "action": "block"
}
```

---

# 二十一、自定义规则

允许用户创建：

```text
URI contains
URI regex
Query contains
Method
IP
Country
User-Agent
Header
Host
```

Action：

```text
Allow
Monitor
Block
403
404
444
429
```

所有正则表达式必须：

检测合法性。

禁止：

导致 catastrophic backtracking 的明显危险正则。

---

# 二十二、日志轮转

不能无限增长。

实现：

```text
最大文件大小
保留天数
最大日志数量
```

默认：

```text
单文件 <= 50MB
保留 7 天
```

支持配置。

---

# 二十三、日志性能

禁止：

每请求同步 flush。

使用：

Nginx buffered logging

或者批量写入。

攻击日志绝对不能再次制造：

磁盘 IO 风暴。

---

# 二十四、配置热更新

参考 wafpro 的：

```text
version file
```

思路。

如果最终采用 Lua：

规则变化时：

```text
保存配置
↓
更新 version
↓
worker 定期检查
↓
reload rule cache
```

不要：

```text
每保存一个IP
↓
nginx reload
```

---

# 二十五、Nginx 配置修改安全机制

这是最高优先级。

任何修改必须：

```text
原配置
 ↓
backup
 ↓
生成临时配置
 ↓
nginx -t
 ↓
成功？
 ├── YES
 │     ↓
 │   原子替换
 │     ↓
 │   reload
 │
 └── NO
       ↓
     rollback
       ↓
     UI显示错误
```

不能：

```text
直接写 nginx.conf
然后 reload
```

---

# 二十六、禁止破坏 aaPanel 配置

不能整体重写：

```text
/www/server/nginx/conf/nginx.conf
```

不能整体重写：

```text
/www/server/panel/vhost/nginx/*.conf
```

如果必须修改：

只能通过：

受控 include

或者：

带唯一 BEGIN / END marker 的代码块。

例如：

```text
# BEGIN NGINX_GUARD
include /www/server/nginx_guard/sites/example.com.conf;
# END NGINX_GUARD
```

卸载时：

只删除自己的 marker。

---

# 二十七、原子写文件

Python 写配置：

禁止直接：

```python
open(path, "w")
```

然后覆盖关键配置。

必须：

```text
tempfile
fsync
rename
```

实现原子替换。

---

# 二十八、安全要求

插件具有高权限。

因此所有 Python API 必须防止：

## Command Injection

禁止：

```python
os.system("nginx " + user_input)
```

禁止：

```python
subprocess.run(..., shell=True)
```

拼接用户输入。

使用：

```python
subprocess.run([
    "/www/server/nginx/sbin/nginx",
    "-t"
])
```

---

# 二十九、Path Traversal

所有文件名：

site
domain
config
rule

必须严格校验。

禁止：

```text
../../
/
\
%2f
null byte
```

---

# 三十、域名验证

站点名必须：

从 aaPanel 已存在网站列表中选择。

不能让 API 任意传：

```text
../../etc/passwd
```

形成文件路径。

---

# 三十一、权限

配置文件：

```text
root
```

可写。

Nginx Worker：

只读规则；

仅可以写：

指定日志目录。

禁止让：

```text
www
```

用户拥有插件 Python 代码目录写权限。

---

# 三十二、安装程序

最终目录至少：

```text
nginx_guard/
├── info.json
├── install.sh
├── uninstall.sh
├── index.html
├── nginx_guard_main.py
├── nginx_guard_dash.py
├── icon.png
│
├── engine/
│
├── rules/
│
└── README.md
```

参考 wafpro 结构。

---

# 三十三、install.sh

安装时：

创建：

```text
/www/server/nginx_guard
```

创建：

```text
config
rules
sites
logs
backup
runtime
```

复制必要资源。

但：

安装阶段不要直接接管 Nginx。

安装完成：

插件默认：

```text
Engine Disabled
```

用户在 UI 点击：

```text
Enable Engine
```

后才安装 Nginx wiring。

这一点可以参考 wafpro。

---

# 三十四、卸载

卸载前：

找到所有：

```text
NGINX_GUARD
```

include marker。

删除。

执行：

```bash
nginx -t
```

成功：

reload。

失败：

rollback。

然后再删除：

```text
/www/server/nginx_guard
```

以及：

```text
/www/server/panel/plugin/nginx_guard
```

不能破坏任何网站配置。

---

# 三十五、Emergency Recovery

必须提供：

```bash
/www/server/nginx_guard/bin/disable.sh
```

即使 aaPanel 页面打不开：

SSH 执行：

```bash
bash /www/server/nginx_guard/bin/disable.sh
```

即可：

1. 移除 WAF wiring
2. nginx -t
3. reload nginx

README 必须明确记录恢复方式。

---

# 三十六、版本一功能范围

V1.0 不要追求功能太多。

必须完成：

### 必需

- aaPanel 插件导入
- 网站列表
- 网站独立开关
- Monitor / Block
- Sensitive File
- Traversal
- Metadata SSRF
- IP blacklist
- IP whitelist
- CC rate limit
- 动态请求限流
- Cloudflare Real IP
- Attack Log
- Dashboard
- nginx -t
- backup
- rollback
- emergency disable

### 可以延后

SQL Injection

XSS

GeoIP

国家封禁

恶意 IP 云数据库

复杂 Bot 指纹

JS Challenge

CAPTCHA

机器学习

---

# 三十七、性能要求

目标：

WAF 开启后：

正常 PHP 网站延迟增加尽量：

```text
< 1ms
```

轻量规则处理：

不得进行大量磁盘 IO。

目标内存：

```text
WAF额外常驻内存尽量 < 30～50MB
```

不能因为攻击：

无限创建进程。

不能因为攻击：

无限创建日志。

不能因为攻击：

产生数 GB/s 的磁盘读取。

---

# 三十八、测试

必须自己生成测试请求。

### 正常

```bash
curl https://example.com/
```

必须：

```text
200
```

---

### ENV

```bash
curl https://example.com/.env
```

Block：

```text
403/444
```

---

### Git

```bash
curl https://example.com/.git/HEAD
```

必须 Block。

---

### Traversal

```bash
curl 'https://example.com/?file=../../../../etc/passwd'
```

必须 Block。

---

### Metadata SSRF

```bash
curl 'https://example.com/webhook?url=http://169.254.169.254/latest/meta-data/'
```

必须 Block。

---

### CC

使用：

```bash
seq 1 200 | xargs -P20 -I{} curl ...
```

测试。

必须出现：

```text
429
```

同时：

Nginx
PHP-FPM
系统

不能出现异常资源增长。

---

# 三十九、兼容测试

至少建立：

```text
PHP site
Static site
Reverse proxy site
WebSocket test
```

全部验证。

尤其：

WebSocket 和 reverse proxy。

不能出现 wafpro README 描述的：

```text
503 Service Temporarily Unavailable
```

兼容问题。

---

# 四十、故障测试

人工制造：

错误 Nginx 配置。

验证：

```text
nginx -t fail
```

插件：

不能 reload。

必须：

自动 rollback。

---

# 四十一、性能压测

测试：

```text
100 req/s
500 req/s
```

监控：

```text
CPU
RAM
Disk IO
load average
Nginx worker
```

同时测试恶意扫描流量。

---

# 四十二、交付物

最终必须提供：

```text
nginx-guard/
```

完整源码。

以及：

```text
dist/nginx_guard-x.x.x.zip
```

该 ZIP：

必须可以直接通过：

```text
aaPanel
→ App Store
→ Third-party Plugin
→ Import
```

安装。

---

# 四十三、文档

必须提供：

```text
README.md

docs/
├── ARCHITECTURE.md
├── INSTALL.md
├── SECURITY.md
├── TESTING.md
├── WAFPRO_ANALYSIS.md
└── RECOVERY.md
```

---

# 四十四、开发流程要求

不要一次性生成整个项目然后宣布完成。

按照以下阶段：

## Phase 1

分析 wafpro。

输出：

```text
WAFPRO_ANALYSIS.md
ARCHITECTURE.md
```

然后检查设计。

## Phase 2

建立 aaPanel 插件骨架。

确保：

能安装、打开、卸载。

## Phase 3

实现网站列表和配置管理。

## Phase 4

实现 Nginx 基础防护。

## Phase 5

实现限流。

## Phase 6

实现攻击日志。

## Phase 7

实现 Dashboard。

## Phase 8

实现 Cloudflare Real IP。

## Phase 9

安全审计。

## Phase 10

兼容性和压力测试。

## Phase 11

生成 ZIP。

---

# 四十五、Codex 工作规则

你拥有当前工作区权限。

可以：

创建文件
修改代码
运行测试
执行 lint
构建 ZIP

不要只告诉我：

“应该怎么写”。

直接完成代码。

发现问题：

先分析根因；

修改；

测试；

继续。

不要在每个小步骤询问确认。

只有涉及：

删除重要数据
修改生产服务器配置
覆盖已有项目

才需要停止确认。

---

# 四十六、代码审计

完成开发以后：

重新从攻击者角度审计插件本身。

重点检查：

```text
RCE
Command Injection
Path Traversal
Arbitrary File Write
Arbitrary File Read
XSS
CSRF
Regex DoS
Log Injection
Privilege Escalation
Symlink Attack
Race Condition
```

插件本身绝对不能变成：

新的服务器漏洞。

---

# 四十七、关于参考 wafpro

可以学习 wafpro：

- aaPanel plugin skeleton
- info.json
- install.sh
- Python API structure
- index.html UI structure
- rules/config separation
- attack dashboard
- hot reload
- nginx test / rollback
- Lua engine caching

但是：

不要机械复制。

尤其重新设计：

- reverse proxy compatibility
- WebSocket compatibility
- global access phase
- per-site isolation
- logging performance
- safe configuration editing

优先保证：

```text
稳定 > 功能
兼容 > 功能
安全 > UI
低资源 > 复杂检测
```

---

# 四十八、最终验收标准

只有同时满足以下条件才算完成：

```text
✓ aaPanel可以导入
✓ 插件页面可以正常打开
✓ PHP正常
✓ WordPress正常
✓ 静态站正常
✓ reverse proxy正常
✓ WebSocket正常
✓ .env攻击被拦截
✓ .git攻击被拦截
✓ traversal被拦截
✓ metadata SSRF被拦截
✓ CC限流有效
✓ IP blacklist有效
✓ Cloudflare真实IP正确
✓ nginx -t失败自动回滚
✓ 卸载不会破坏网站
✓ SSH可以一键Emergency Disable
✓ 日志不会无限增长
✓ 大量攻击不会导致PHP-FPM被拉满
✓ 大量攻击不会导致明显Page Cache Thrashing
✓ 最终ZIP可以直接导入aaPanel
```

最后生成：

```text
dist/nginx_guard-1.0.0.zip
```

并输出：

```text
SHA256
版本号
安装方法
卸载方法
紧急恢复方法
已测试环境
已知限制
```