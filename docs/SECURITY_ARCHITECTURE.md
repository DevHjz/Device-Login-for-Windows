# 云端验证设备认证服务：安全架构

## 设计目标

**云端验证设备认证服务（Cloud Verify Device Auth）** 面向 Windows 10+，为受信任网页提供回环地址设备认证与用户确认能力。应用运行时兼容 Windows x86、x64 与 ARM64，发布流程生成 x64 与 ARM64 安装程序。为保持既有身份服务配置可用，OAuth 回调协议继续使用 `cloud-verify-device-login://oauth/callback`。

## 认证数据边界

| 数据类别 | 存放位置 | 保护措施 |
| --- | --- | --- |
| 租户名称、服务地址、应用标识、组织、证书 | 内置租户预设或本机租户配置 | 仅非敏感配置；额外允许网页来源必须为 HTTPS。 |
| 租户认证信息 | 当前 Windows 用户的本机租户配置 | 使用 Electron `safeStorage`，在 Windows 上由当前用户的数据保护能力加密；保存后不回显。 |
| 访问令牌与设备凭据 | 当前 Windows 用户的本机会话文件 | 使用 `safeStorage` 加密；不会出现在界面、通知或日志中。 |
| GitHub Actions 配置占位项 | GitHub Secrets | 仅可选存在性检查；不会写入工作区、日志、安装包或可执行文件。 |

客户端可执行文件中的静态认证信息可被提取，因此不应把认证信息写入 Git 仓库、文档、Actions 日志或安装产物。

## Native SSO 授权

本机服务仅监听 `127.0.0.1` 端口范围并验证网页来源。每次网页请求都使用 Windows 通知中心展示“授权登录 / 拒绝”，一次性审批标识仅存在内存中。启用 Windows Hello 后，应用会在授权前调用 Windows `UserConsentVerifier` 请求系统凭据验证。[1]

对于未发送 `state` 和 `redirectUri` 的默认网页应用，服务不会按空字段组合进行重复请求限制，以保证同一应用可连续发起登录；带有请求标识的请求仅在处理中进行并发防护。

## 会话与启动周期

标准退出、切换租户、删除当前租户以及检测到新的 Windows 启动周期时，应用均执行以下顺序：停止本机设备服务、向身份服务 `/api/logout` 发送退出请求、删除本地加密会话、清除应用 Cookies。新的 Windows 启动周期若设置为内置登录窗口，会直接显示认证窗口，主窗口保持隐藏。

## 设备态势与悬浮窗

设备安全检查仅以只读方式采集 Windows 登录密码要求、C 盘 BitLocker、Windows 安全中心已注册的杀毒软件状态、可读取的病毒库状态和防火墙配置。检查每 30 分钟自动运行一次，也支持手动刷新。无法从第三方产品读取的状态会明确标记为无法确认，不会伪造检测结果。

悬浮窗是独立的原生 Windows 窗口，默认显示在右上角，支持拖动和调整大小，位置与尺寸保存到当前 Windows 用户的应用数据目录。它不显示在任务栏，可在系统设置中关闭。

## References

[1]: https://learn.microsoft.com/en-us/uwp/api/windows.security.credentials.ui.userconsentverifier.requestverificationasync?view=winrt-28000 "Microsoft Learn — UserConsentVerifier.RequestVerificationAsync"
