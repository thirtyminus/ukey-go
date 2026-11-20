# UKey 最小化授权机制

算法合规（SM2/SM3/SM4）、载体为普通 U 盘的软件授权方案。私钥驻留在 U 盘上的加密文件中，拔盘即失效。

## 威胁模型

**能防住的**

- 把软件目录拷到另一台机器：License 绑定机器码，拒绝。
- 把 `license.dat` 拷到别的机器：机器码不符，拒绝。
- 把 `ukey.dat` 拷到另一块 U 盘：密钥派生盐含介质指纹，解密失败。
- 篡改 License 的功能位或有效期：SM2 验签失败。
- 拔盘后继续使用：1 秒左右进入受限模式。
- 系统时间回拨绕过到期：`lastSeen` 单调递增，回拨超过 5 分钟拒绝。
- 暴力猜口令：连续 5 次失败锁定介质（正确口令仍可解锁）。

**防不住的（已知风险）**

- 私钥可被专业工具从内存或 U 盘密文中提取；真正的不可导出私钥需要经 GM/T 0028 认证的密码模块。
- 整盘 `dd` 镜像克隆：卷 UUID 与物理序列号会一起被复制，无法在纯软件层区分。
- 拿到 U 盘写权限的攻击者若同时能改客户端二进制：可替换 `vendor.pub` 自签 License。缓解手段是编译期注入信任根（见下文）。
- 用户整盘备份后回滚 `ukey.dat`，可绕过 `lastSeen` 回拨检测。
- 多机共用同一 U 盘（需要在线心跳才能约束，本方案不含在线能力）。

## 目录结构

```
cmd/keygen/         签发与自检工具
cmd/demo-app/       业务集成示例（含拔盘降级）
cmd/ukey-agent/     本机签名 Agent（网页登录用，监听 127.0.0.1）
cmd/ukey-web/       网页登录演示服务（challenge / 验签 / 会话）
internal/smcrypto/  SM2/SM3/SM4、PBKDF2-SM3、内存清零
internal/format/    ukey.dat / license.dat 的编解码与校验
internal/machine/   机器码（darwin/linux/windows）
internal/media/     介质定位与指纹（物理序列号优先，回退卷 UUID）
internal/sdk/       业务侧 API
internal/weblogin/  网页登录的 challenge/验签/会话逻辑
internal/localagent/本机 Agent 的签名接口与 Origin 白名单
docs/               本文档、manual.md（使用手册）、web-login.md（网页登录需求）
```

## 快速开始

U 盘挂载为 `/Volumes/KEY`（Windows 为 `E:\`，Linux 为 `/media/user/KEY`）。

```bash
# 1. 初始化介质，生成 UKey 密钥对与厂商签名密钥
go run ./cmd/keygen init --dir /Volumes/KEY --vendor ./vendor.key

# 2. 查看介质状态（不需要口令）
go run ./cmd/keygen info --dir /Volumes/KEY

# 3. 签发 License，绑定本机机器码，2027 年底到期
go run ./cmd/keygen issue --key /Volumes/KEY --vendor ./vendor.key \
  --features pro,basic --expire 2027-12-31 --serial L-001

# 4. 全量自检：口令、介质、私钥可用性、License 约束
go run ./cmd/keygen verify --dir /Volumes/KEY

# 5. 业务侧演示
go run ./cmd/demo-app --vol /Volumes/KEY --feature pro
```

客户机器上只需要执行 `keygen machine-code` 把机器码报给你，即可离线签发。

本地目录调试（不插 U 盘）时，所有命令追加 `--salt none`。

## 网页登录演示

浏览器沙箱无法读 U 盘，所以网页登录用三段式：登录页 → 认证服务端 → 本机 Agent。需求与流程见 [web-login.md](web-login.md)。

```bash
# 1. 启动本机 Agent（读盘 + 签名），口令从标准输入读入
go run ./cmd/ukey-agent --vol /Volumes/KEY

# 2. 启动认证服务（默认从 Agent 拉公钥，生产请用 -pubkey 静态注册）
go run ./cmd/ukey-web --listen 127.0.0.1:8080

# 3. 浏览器打开 http://127.0.0.1:8080/ ，点“使用 UKey 登录”
```

## 业务集成

```go
passphrase := readFromUser()

session, err := sdk.Open("/Volumes/KEY", passphrase) // 留空字符串则自动扫描挂载点
if err != nil {
    // ErrMediaNotFound / ErrBadPassphrase / ErrMediaMismatch / ErrLocked / ErrClockTamper
    return err
}
defer session.Close()

lic, err := session.VerifyLicense()
if err != nil {
    // ErrLicenseInvalid / ErrMachineMismatch / ErrExpired / ErrNotYetValid / ErrKeyIDMismatch
    return err
}
if err := session.RequireFeature("pro"); err != nil {
    return err
}

ctx, cancel := context.WithCancel(context.Background())
defer cancel()
go session.Watch(ctx, func() {
    cancel()          // UKey 被拔出，切换到受限模式
})
```

敏感操作前再调一次 `session.CheckAlive()`；需要挑战响应时用 `session.Sign(nonce)`，对方用 `session.PublicKey()` 验签。

### 生产构建必须注入信任根

默认情况下 SDK 会回退读取介质上的 `.ukey/vendor.pub`，这在开发期方便，但意味着能写 U 盘的人可以自签 License。生产构建要把厂商公钥编译进二进制：

```bash
go build -ldflags "-X ukey/internal/sdk.VendorPublicKeyHex=<65字节公钥hex>" ./cmd/demo-app
```

`keygen init` 的输出里会直接打印这行命令。

## 文件与格式

介质根目录下的 `.ukey/`：

| 文件 | 内容 | 是否敏感 |
|---|---|---|
| `ukey.dat` | 明文头 + SM4-CBC 加密的私钥材料 | 密文，但仍需防拷贝 |
| `license.dat` | `LIC1` 头 + License JSON + SM2 签名 | 否 |
| `vendor.pub` | 厂商验签公钥（hex） | 否 |
| `media.id` | 介质指纹摘要，用于区分错盘与错口令 | 否 |
| `keyid` | KeyID 明文，供签发端识别介质 | 否 |

`ukey.dat` 布局：

```
magic "UKY1" | version(1) | saltType(1) | iter(4) | saltLen(1) | salt |
ivLen(1) | iv | failCount(2) | locked(1) | cipherLen(4) | cipher
```

密钥派生：`SM4Key = PBKDF2-SM3(口令, salt ‖ 介质指纹, iter, 16)`。换口令或换介质都无法解密，这是防拷贝的核心。

`license.dat` 的签名字节直接覆盖 JSON 原文，验签时不对原文做任何重编码。

## 验收对照

| # | 场景 | 验证方式 | 结果 |
|---|---|---|---|
| 1 | 正常介质正常启动 | `keygen verify` + `demo-app` | 通过 |
| 2 | 拔盘后降级 | `demo-app` 拔盘，1s 内停业务 | 通过 |
| 3 | License 拷到异机 | 机器码不符，`ErrMachineMismatch` | 通过 |
| 4 | `ukey.dat` 拷到异盘 | 介质指纹不符，`ErrMediaMismatch` | 通过 |
| 5 | 系统时间回拨 | `ErrClockTamper` | 通过 |
| 6 | 篡改 License 功能位 | `ErrLicenseInvalid` | 通过 |
| 7 | 错口令 5 次 | 第 5 次 `ErrLocked`，正确口令仍可解锁 | 通过 |

测试执行：

```bash
go test ./...
go test -race ./...
```

## 跨平台差异

| 平台 | 介质指纹 | 说明 |
|---|---|---|
| Linux | 物理序列号 → 卷 UUID | 从 `/sys/block/<dev>/device/serial` 读取，最可靠 |
| macOS | 卷 UUID | 多数 U 盘不暴露 USB 串号，`physicalSerial` 直接回退 |
| Windows | 卷序列号 | 多块 USB 盘时物理串号易取错，统一用 `vol` 的卷序列号 |

机器码统一为 `SM3("ukey-machine-v1|平台UUID|硬件序列号")[:16]`，刻意避开网卡 MAC。

## 维护说明

- 更换 U 盘：原 `ukey.dat` 无法在新盘解密，需重新 `init` 并重新签发 License。
- 遗忘口令：无法恢复，只能重新 `init`。
- 遗失厂商私钥 `vendor.key`：已发出的 UKey 再也无法补签 License，请离线备份。
