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

## 重要：安全须知

- **绝不能拦 API / 支付回调 / webhook**。只给"给人看的 HTML 页面"那个 `location` 加 `auth_request`；未加的 `location` 自动放行。
- **`secret.key` 是机密**，已在 `.gitignore` 中排除，切勿提交或泄露。多台机器共享 Cookie 时需使用同一份密钥。
- **务必放行 `.well-known/acme-challenge/`**，否则 SSL 证书续期会失败。

## License

MIT
