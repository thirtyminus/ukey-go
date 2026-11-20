# UKey 网页登录（最小化 Demo）需求

## 1. 背景与硬约束

浏览器运行在沙箱里，**无法直接读取 U 盘文件**。因此网页登录必然是三段式：

```
浏览器（登录页） ──HTTP──> 认证服务端（验签、发会话）
        │
        └──HTTP──> 本机 UKey Agent（读盘、拿私钥签名）
                    ↑ 仅监听 127.0.0.1
```

本机 Agent 是必需的，不是设计冗余：它是唯一能访问介质私钥的进程。真实 U 盾也是同一形态（银行控件 / 驱动常驻进程）。

## 2. 目标与范围

**做**：用 UKey 完成一次网页登录（挑战-响应），无口令输入之外的任何交互；未插盘或签名不符时登录失败。

**不做**：账号密码体系、用户注册、权限模型、多机并发控制、在线吊销、HTTPS 部署细节。

**可扩展点**：本方案只把 UKey 当唯一因子。接入现有系统时，把它挂在密码校验之后即可变成二次因子——服务端只需在密码通过后再走 challenge/login 两个接口。

## 3. 组件职责

| 组件 | 职责 | 信任级别 |
|---|---|---|
| `ukey-agent` | 监听 `127.0.0.1:18765`；解锁 UKey 一次并持有会话；对指定前缀的消息签名 | 本机可信 |
| `ukey-web` | 生成一次性 challenge；验 SM2 签名；签发会话 Cookie；托管登录页 | 服务端 |
| 登录页 | 串起「取 challenge → 请求本机签名 → 提交」三步 | 浏览器 |

## 4. 流程

```
1. 浏览器 GET /                     → 登录页
2. 浏览器 GET agent/ping            → {keyId, publicKey}，确认插着 UKey
3. 浏览器 POST /api/challenge       → {sessionId, messageHex}
     服务端生成 sid(16B) + nonce(32B)，保存 5 分钟
     message = "ukey-web-login|<sid>|<nonce-hex>"
4. 浏览器 POST agent/sign {messageHex}
     agent 校验消息前缀，用 UKey 私钥 SM2 签名，返回 DER 签名
5. 浏览器 POST /api/login {sessionId, signature}
     服务端取 challenge（取即删，保证一次性）→ 验签 → 下发 HttpOnly Cookie
6. 浏览器 GET /api/me               → {loggedIn:true}
```

## 5. 接口

### 认证服务端

| 方法 | 路径 | 请求 | 响应 |
|---|---|---|---|
| POST | `/api/challenge` | `{}` | `{sessionId, messageHex, expiresIn}` |
| POST | `/api/login` | `{sessionId, signature}` | `{ok:true}` + `Set-Cookie` |
| GET | `/api/me` | - | `{loggedIn, subject}` |
| POST | `/api/logout` | - | `{ok:true}` |

错误统一 `{error:"..."}`，状态码 400/401。

### 本机 Agent

| 方法 | 路径 | 请求 | 响应 |
|---|---|---|---|
| GET | `/ping` | - | `{ok, keyId, publicKey}` |
| POST | `/sign` | `{messageHex}` | `{signature}` |

## 6. 安全需求

| 威胁 | 对策 |
|---|---|
| 重放已截获的签名 | challenge 一次性，验签前即删除；有效期 5 分钟 |
| 跨站调用本机 Agent | Agent 校验 `Origin` 白名单，非白名单 403；预检请求单独处理 |
| Agent 被当作通用签名机 | 只签以 `ukey-web-login|` 开头的消息，其余 400 |
| XSS 窃取会话 | 会话 Cookie 设 `HttpOnly` + `SameSite=Lax` |
| 口令泄露在进程列表 | 口令从 stdin 读取，不接受命令行参数 |
| 拔盘后仍用内存私钥签名 | Agent 每次 `/sign` 前校验介质，拔盘返回 401，`/ping` 返回 503 |

**信任根**：服务端在启动时注册 UKey 公钥（`-pubkey`），不从浏览器或 Agent 动态接受新公钥。`-agent` 模式仅用于演示便利。

## 7. 非功能

- 登录全程 < 1 秒（不含人工操作）。
- Agent 与 Web 均为单二进制，无外部依赖，可离线运行。
- 服务端不落库，challenge/session 全在内存，重启即失效。

## 8. 验收标准

1. 插盘且 Agent 已启动：点击登录成功，`/api/me` 返回已登录。
2. 未启动 Agent：页面提示「未检测到本机签名服务」，不误报成功。
3. 复用同一 challenge 第二次提交：401。
4. challenge 超过 5 分钟：401。
5. 用其他密钥签名：401。
6. 非白名单 Origin 调 `/sign`：403；curl 无 Origin：允许。
7. 登录后登出：Cookie 清除，`/api/me` 返回未登录。
8. 拔盘后：Agent 打印移除提示，`/ping` 503、`/sign` 401，页面登录失败；插回即恢复。

## 9. 已知风险

- Agent 持有已解锁的 UKey 会话，本机恶意进程可在 Agent 存活期间借其签名。生产应缩短会话、增加进程鉴权或改为每次签名输入口令。
- Demo 用 HTTP，生产必须 HTTPS，且 Agent 只允许 `https://` 的 Origin。
- 未做防 DNS rebinding（恶意域名解析到 127.0.0.1）。生产应校验 `Host` 头为本机地址。
