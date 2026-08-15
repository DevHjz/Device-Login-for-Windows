# 云端验证设备登录助手：安全与租户架构

## 1. 设计目标

本项目面向 Windows 10 及更高版本，为受信任网页提供 Native SSO 设备确认能力。应用在 Windows x86、x64 与 ARM64 上保持运行时兼容；发布流程只生成 x64 与 ARM64 安装包。应用品牌名称为 **云端验证设备登录助手（Cloud Verify Device Login）**。

> 客户端密钥是机密资产。任何可分发安装包中的常量都可以被提取，因此不能把客户端密钥编译进 EXE、写入 Git 仓库、写入 Actions 日志或写入文档。

## 2. 租户数据分层

| 数据类别 | 位置 | 是否可见 | 保护方式 |
| --- | --- | --- | --- |
| 租户显示名称、服务地址、客户端 ID、组织、应用名称、证书 | `src/main/tenant-presets.ts` 与用户租户配置 | 可由租户管理员查看与编辑 | 版本控制与本机文件权限 |
| 客户端密钥 | 仅本机 `tenants.json` | 保存后永不回显 | Electron `safeStorage`，Windows 上使用当前用户数据保护能力 |
| 登录令牌与 `device_secret` | 仅本机会话文件 | 不在界面、日志或通知中显示 | Electron `safeStorage`，退出登录立即删除 |
| Actions 构建密钥 | GitHub Actions Secrets | 不写入工作区、产物或日志 | 工作流仅校验 Secrets 是否配置，绝不注入应用二进制 |

初始租户预置两条不含密钥的记录：**黄发科技集团**与**公共认证服务**。首次使用或编辑租户时，管理员在本机输入各租户客户端密钥。保存后该字段仅显示为“已安全保存”，不能再次读取。

## 3. 客户端密钥与 GitHub Actions

GitHub Actions Secrets 不可供最终 EXE 在客户现场运行时读取。若把 Secret 注入安装包，仍会变成可提取的静态密钥，违背机密保护要求。因此工作流只使用 Secrets 做受保护的构建前置检查，并确保不会输出其值。

工作流支持以下**可选** Secrets 名称：

| Secret 名称 | 用途 |
| --- | --- |
| `TENANT_HUANGFA_CLIENT_SECRET` | 确认黄发科技集团密钥已在组织 Secrets 中配置；不会写入文件或产物。 |
| `TENANT_PUBLIC_IAM_CLIENT_SECRET` | 确认公共认证服务密钥已在组织 Secrets 中配置；不会写入文件或产物。 |

客户现场使用时，管理员在桌面应用中为相应租户录入密钥。这样既满足预置租户参数，也不会在 GitHub 或安装包中泄露密钥。

## 4. Native SSO 审批

每次网页发起 Native SSO 时，本机服务创建单次、限时的审批请求。应用调用 Windows 通知中心展示“允许登录”和“拒绝”操作；每个按钮通过已注册的专用协议回传一次性随机令牌。令牌仅保存在内存中，审批、拒绝、超时或停止服务时都会失效。

如果管理员开启 Windows Hello，应用在批准前调用 Windows 的 `UserConsentVerifier` 请求 PIN、人脸或指纹验证；开关状态变更本身也必须先完成一次验证。Microsoft 将此 API 定义为敏感操作的用户同意验证接口。[1]

## 5. 本机生命周期

应用可启用 Windows 开机自启。窗口点击关闭时仅隐藏至托盘，普通最小化保持在任务栏；托盘图标始终可见，右键菜单提供“显示主窗口”“开始/停止设备服务”和“退出”。只有托盘菜单的“退出”会关闭进程。

“退出并停止设备登录”会停止本机回环服务、清除加密会话、清除身份服务域的 Cookie，并返回未登录状态。切换租户要求用户明确确认；确认后也会停止旧租户服务并清除旧租户会话与 Cookie，避免跨租户令牌使用。

## References

[1]: https://learn.microsoft.com/en-us/uwp/api/windows.security.credentials.ui.userconsentverifier.requestverificationasync?view=winrt-28000 "Microsoft Learn — UserConsentVerifier.RequestVerificationAsync"
