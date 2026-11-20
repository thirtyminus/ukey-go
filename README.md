# ukey-go

基于国密算法（SM2 / SM3 / SM4）的文件型 UKey 最小实现，覆盖两个场景：

- **软件授权绑定**：License 绑定机器码与介质指纹，支持有效期、功能项、拔盘降级。
- **网页登录**：挑战-响应二次认证，浏览器 + 本机 Agent + 认证服务三段式。

纯 Go，无外部运行时依赖，可离线部署。

## 快速开始

```bash
# 初始化 U 盘（设置口令，生成 UKey 密钥对与厂商密钥）
go run ./cmd/keygen init --dir /Volumes/KEY --vendor ./vendor.key

# 签发 License（默认绑定本机机器码）
go run ./cmd/keygen issue --key /Volumes/KEY --vendor ./vendor.key \
  --features pro --expire 2027-12-31

# 验证授权
go run ./cmd/demo-app --vol /Volumes/KEY --feature pro
```

不插 U 盘时，用普通目录加 `--salt none` 即可跑通全流程。

## 文档

- [使用手册](docs/manual.md)：从初始化到网页登录的完整操作步骤与效果截图
- [设计与威胁模型](docs/README.md)：格式、指纹、错误码、跨平台差异
- [网页登录需求](docs/web-login.md)：架构、接口、安全需求与验收标准

## 网页登录

```bash
go run ./cmd/ukey-agent --vol /Volumes/KEY      # 本机签名服务，输入口令
go run ./cmd/ukey-web --listen 127.0.0.1:8080   # 认证服务与登录页
```

打开 http://127.0.0.1:8080/ 即可。

## 注意

- 这是最小化 Demo，未做在线激活、吊销与远程心跳。
- `vendor.key` 是签发 License 的唯一私钥，务必离线保管，已加入 `.gitignore`。
- `ukey-web` 默认从本机 Agent 拉取公钥，仅便于演示；生产必须用 `-pubkey` 静态注册信任根。
