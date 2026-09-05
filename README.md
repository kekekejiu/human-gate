# human-gate

一个可本地/私有化部署的**人机验证网关**。用 nginx `auth_request` 在业务前面加一道滑块验证闸门，访客首次访问需拖动滑块通过验证，之后凭签名 Cookie 放行。适合拦截爬虫、脚本刷单、批量注册。

不依赖 Cloudflare、reCAPTCHA 等境外服务，验证码在本机生成与校验，**中国大陆访问无额外延迟**。

## 特性

- **行为式滑块验证**，基于 [go-captcha](https://github.com/wenlng/go-captcha)，图片本地生成
- **一次部署，多站复用**：一个服务保护同机上任意多个站点
- **零侵入**：不改业务代码，只在 nginx 层加两行配置
- **签名 Cookie + UA 绑定**：HMAC-SHA256 签名，防伪造、防跨客户端复用
- **精细放行**：只拦页面导航，API / 支付回调 / 静态资源自动放行

## 工作原理

```
用户访问 → nginx auth_request → /__gate/check
  ├─ 无有效 Cookie → 401 → 302 跳转滑块验证页 → 通过 → 签发 Cookie
  └─ 有有效 Cookie → 放行
```

## 快速开始

### 1. 编译

```bash
go build -o human-gate .
```

### 2. 运行

```bash
GATE_LISTEN=127.0.0.1:9200 ./human-gate
```

首次运行会在 `GATE_SECRET_FILE` 路径自动生成随机密钥 `secret.key`。

### 3. systemd 托管（可选）

```bash
cp deploy/human-gate.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now human-gate
```

## 接入 nginx

在 `server {}` 中引入公共片段，并在需要保护的 `location` 加一行：

```nginx
server {
    server_name example.com;

    # 引入闸门 location 与跳转逻辑
    include /path/to/deploy/nginx-human-gate.inc;

    location / {
        auth_request /__gate/check;   # ← 保护页面导航
        # ...你的 proxy_pass / try_files...
    }
}
```

> 前提：nginx 编译时带 `--with-http_auth_request_module`（大多数发行版默认已带）。

## 配置项（环境变量）

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `GATE_LISTEN` | `127.0.0.1:9200` | 监听地址 |
| `GATE_COOKIE` | `hg_pass` | 通行 Cookie 名 |
| `GATE_SECRET_FILE` | `./secret.key` | HMAC 密钥文件路径 |
| `GATE_PASS_TTL_HOURS` | `12` | 通行有效期（小时） |
| `GATE_SUPPORT_ENABLE` | 自动 | 是否显示客服；配置任一客服项后自动启用，设 `off` 强制关闭 |
| `GATE_SUPPORT_SCRIPT_URL` | 空 | 外链客服脚本地址，如 SaleSmartly 提供的 JS URL |
| `GATE_SUPPORT_URL` | 空 | 不依赖 JavaScript 的静态客服/工单链接（强烈建议配置） |
| `GATE_SUPPORT_TEXT` | `验证遇到问题？联系客服` | 静态客服入口文字 |
| `GATE_SUPPORT_HTML_B64` | 空 | 任意可信客服底部 HTML 的 Base64（部署者自行提供） |
| `GATE_SUPPORT_HTML_FILE` | 空 | 任意可信客服 HTML 文件路径，如 `/data/support.html` |
| `GATE_GEO_CITY` | 空 | GeoLite2-City.mmdb 路径（填了才启用分析） |
| `GATE_GEO_ASN` | 空 | GeoLite2-ASN.mmdb 路径（填了才启用分析） |
| `GATE_ADMIN_PASS` | 空 | 分析面板密码（填了才启用分析） |
| `GATE_ADMIN_USER` | `admin` | 分析面板用户名 |
| `GATE_DB` | `./visits.db` | SQLite 数据库路径 |
| `GATE_RETAIN_DAYS` | `30` | 访问记录保留天数（自动清理） |
| `GATE_IP2REGION_V4` | 空 | ip2region_v4.xdb 路径（国内地市级+运营商兜底，可选） |
| `GATE_IP2REGION_V6` | 空 | ip2region_v6.xdb 路径（同上，可选） |
| `GATE_INGEST_TOKEN` | 空 | 中心侧：接收远程节点上报的密钥（填了才开放 ingest） |
| `GATE_REPORT_URL` | 空 | 节点侧：中心 ingest 地址，如 `https://中心IP:9443/__gate/ingest` |
| `GATE_REPORT_TOKEN` | 空 | 节点侧：与中心 `GATE_INGEST_TOKEN` 一致 |
| `GATE_REPORT_INSECURE` | 空 | 节点侧：中心用自签证书时置 `1` 跳过证书校验 |
| `GATE_POLICY_URL` | 从 `GATE_REPORT_URL` 推导 | 节点侧：签名策略下发地址，通常无需设置 |
| `GATE_POLICY_INTERVAL_SEC` | `60` | 节点侧：策略同步间隔，最小10秒 |

## 访客分析（可选）

同时配置 `GATE_GEO_CITY`、`GATE_GEO_ASN`、`GATE_ADMIN_PASS` 后，闸门会记录每一次经过的访客并做 IP 画像：

- **采集**：IP、UA、站点、路径、是否已通过、时间
- **IP 画像**：国家/省/市、ASN、运营商（电信/联通/移动）、IP 类型（IDC 机房 / 运营商宽带）
- **风险标记**（只标记不封）：爬虫 UA、空 UA、机房 IP、高频访问 → `ok` / `suspect` / `danger`
- **面板**：访问 `/__gate/admin`（用户名/密码登录），含统计卡片、运营商/类型/地区分布、高频 IP 排行、最近访问明细，支持按风险等级过滤
- **JSON 接口**：`/__gate/admin/api/{summary,recent,top_ip,by_isp,by_type,by_country}`

GeoLite2 库可从 MaxMind 官方或公开镜像获取（`GeoLite2-City.mmdb` + `GeoLite2-ASN.mmdb`），放到 `GATE_DB` 同目录即可。**数据库与 mmdb 库不入 git**（已在 `.gitignore` 排除）。

> 运营商识别同时使用 **ASN 号 + 组织名关键词** 双重判据，覆盖 `Shandong Mobile`、`Zhejiang Telecom` 这类省级子公司命名，IPv4/IPv6 均可正确归类到电信/联通/移动。

## 真实客户端 IP 还原（前置反代/CDN 必看）

如果站点前面有 Cloudflare 或自建反代，源站 nginx 看到的 `$remote_addr` 是 **CF/反代节点的 IP**，分析系统会把所有真实用户都记成那几个反代 IP。需在站点 `server{}` 内还原真实 IP：

- **Cloudflare 前置**：include [`deploy/realip-cloudflare.conf`](deploy/realip-cloudflare.conf)，采信 `CF-Connecting-IP`。
- **自建反代前置**（转发时带 `X-Forwarded-For`）：include [`deploy/realip-proxy.conf`](deploy/realip-proxy.conf)，把**你自己的反代节点 IP**填入 `set_real_ip_from` 白名单。

安全要点：

- `X-Forwarded-For` 可伪造。**若源站 IP 对外暴露、可被直连，切勿用 `set_real_ip_from 0.0.0.0/0`**，否则任何人都能伪造访客 IP。只信任已知反代 IP，名单外直连来源不被采信、其真实来源会被如实记录（扫描器因此会暴露自身 IP，正好被风控标记）。
- 放置位置：`set_real_ip_from`/`real_ip_header` 在同一 server 只能出现一次。**不要**把这些 `.conf` 放进会被 `include .../nginx/*.conf` 通配符扫到的目录，否则会报 `real_ip_header directive is duplicate`；建议放到 `realip/` 子目录再显式 include。

## 多服务器接入（分布式 + 中心汇总）

其他业务、部署在**其他服务器**的站点也能接入同一套分析面板。采用「每台本地闸门 + 事件上报中心」的架构：

- **中心节点**（跑 GeoLite2/ip2region/SQLite/面板）：配置 `GATE_INGEST_TOKEN` 开放 `/__gate/ingest`，并通过 nginx 用 HTTPS 把该端点暴露给其他服务器（示例见 [`deploy/nginx-ingest-endpoint.conf.example`](deploy/nginx-ingest-endpoint.conf.example)，记得放行对应端口）。
- **远程节点**（部署在其他服务器）：只需同一个二进制，配置 `GATE_REPORT_URL` + `GATE_REPORT_TOKEN` 即可。节点本地做闸门（低延迟、无单点），把原始事件异步批量上报中心，**不需要** geo 库和数据库。示例见 [`deploy/human-gate-node.service.example`](deploy/human-gate-node.service.example)。

要点：

- **画像在中心统一做**：节点只上报 IP/UA/站点/路径/是否通过；地理与运营商画像、风险打分、入库都在中心，面板按站点（`site`）区分各业务。
- **真实 IP 在节点侧还原**：每个节点的 nginx 按前置情况 include `realip-*.conf`，还原后的真实 IP 随事件上报，中心直接信任。
- **上报是尽力而为**：缓冲满或网络失败直接丢弃，绝不阻塞闸门；单站/网络故障不影响放行与其他站点。
- **共享 Cookie（可选）**：若希望多站点互认通行证，各节点使用**同一份 `secret.key`**；否则各站独立验证。
- **安全**：`GATE_INGEST_TOKEN` 用强随机值、走 HTTPS；公网入口仅精确暴露 `/__gate/ingest` 与只读 `/__gate/policy`，其余路径 `return 444`。

### 跨站联防（第一阶段：观察模式）

中心会把高置信 `danger` 公网 IP 生成24小时候选规则，并通过签名策略下发给所有节点。节点默认每60秒拉取、验签并原子更新；命中候选后**只回传观察证据，不会拦截、限速或302**。管理面板可查看候选规则与观察命中，用于人工调优风险权重。

策略安全基线：

- 白名单优先于候选规则；EZ主题4个可信反代节点、回环地址和RFC1918私网段已作为基础设施白名单。
- 策略包含版本号、5分钟租约和HMAC签名；篡改、过期或格式错误的策略不会生效。
- 拉取失败继续使用当前未过期版本；租约过期后安全失效，不执行处置。
- 当前数据库策略固定为 `mode=observe`，后续只有人工确认后才切换执行模式。

## 重要：安全须知

- **绝不能拦 API / 支付回调 / webhook**。只给"给人看的 HTML 页面"那个 `location` 加 `auth_request`；未加的 `location` 自动放行。
- **`secret.key` 是机密**，已在 `.gitignore` 中排除，切勿提交或泄露。多台机器共享 Cookie 时需使用同一份密钥。
- **务必放行 `.well-known/acme-challenge/`**，否则 SSL 证书续期会失败。
- **前置反代场景务必保留 `absolute_redirect off`**（片段中已内置）。否则 nginx 会把闸门的 `302 /__gate/...` 相对跳转补全成**源站绝对地址**，导致访客从前置反代被弹到源站、暴露源站 IP。保持相对跳转，浏览器才会停留在当前访问的反代地址上。

## License

MIT
