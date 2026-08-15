# 云端验证设备登录助手

> **Cloud Verify Device Login** 是面向 Windows 的网页设备登录确认助手。它在本机回环地址提供受限的 Native SSO 服务，并通过 Windows 通知中心请求用户批准网页登录。应用名称、桌面快捷方式和开始菜单均显示为“云端验证设备登录助手”。

## 一、支持范围

| 项目 | 交付标准 |
| --- | --- |
| 最低系统 | Windows 10；Windows on Arm 的功能验证基线为 Windows 10 版本 1903 或更高版本。[1] |
| 运行时兼容性 | Windows x86、x64、ARM64。 |
| 发布安装包 | GitHub Actions 仅输出 Windows x64 与 ARM64 NSIS EXE。 |
| 内部命名 | 安装目录和可执行文件使用英文：`cloud-verify-device-login`。 |
| 用户可见命名 | 窗口标题、桌面快捷方式和开始菜单使用中文品牌名称。 |
| 登录确认 | Windows 通知中心“允许登录 / 拒绝”操作；每次请求均需单独确认。 |
| Windows Hello | 可选。启用、关闭以及实际批准登录时均会调用系统验证。 |

Windows Hello 使用 `UserConsentVerifier` 请求 PIN、人脸或指纹等本机验证；应用会先检查当前 Windows 用户是否可使用该功能。[2] Windows 通知中心需要正确的 AppUserModelID 与开始菜单快捷方式，应用和 NSIS 安装器已据此配置。[3]

## 二、内置租户

以下租户的**非敏感参数**已在应用中预置；租户管理员无需重复填写服务地址、客户端 ID、组织、应用名称或证书。

| 租户显示名称 | 服务地址 | 客户端 ID | 组织 | 应用名称 |
| --- | --- | --- | --- | --- |
| 黄发科技集团 | `https://sso.devhjz.com` | `b39a5ad6d95848ffde82` | `Cloud` | `Cloud` |
| 公共认证服务 | `https://sso.devhjz.com` | `6f6a7b4337ffb3d3ee3f` | `Public-IAM` | `Public-APP` |

每个桌面租户应用还必须在身份服务的允许重定向地址中添加：

```text
cloud-verify-device-login://oauth/callback
```

桌面租户应用应保留 `authorization_code` 授权类型并允许 `device_sso` scope。每一个会作为网页登录目标的应用还必须启用 `urn:ietf:params:oauth:grant-type:token-exchange`，否则网页端会收到“网页应用尚未启用设备登录授权”的提示。

客户端密钥属于机密资产，**不会**写入 Git 仓库、README、日志或任何分发安装包。管理员首次使用相应租户时，在“编辑租户”中输入客户端密钥；保存后，应用只显示“已安全保存”，并使用 Windows 当前用户的数据保护能力加密保存，不能回显。

> 将密钥通过 GitHub Actions Secret 注入最终 EXE 仍会形成可被提取的静态密钥，不能构成安全保护。工作流仅检查 Secrets 是否已配置，绝不把其值写入工作区、日志或产物。

## 三、客户使用说明

首次启动后，在“当前租户”中选择服务组织。如果显示“需要由管理员保存客户端密钥”，请点击“编辑”，输入该租户客户端密钥并安全保存。随后点击“登录账户”，在身份页面完成认证。登录成功后，设备状态会变为“设备服务正在运行”。

网页登录需要此设备确认时，Windows 通知中心会显示请求；请在通知中选择“允许登录”或“拒绝”。如果在“系统设置”中启用了 Windows Hello，选择允许后还必须完成系统 PIN、指纹或人脸验证。

切换租户前应用会要求确认，并会停止设备服务、退出当前账户并清除 Cookie，以避免不同组织间复用登录信息。“退出并停止设备登录”执行同样的会话和 Cookie 清理。关闭主窗口只会隐藏至托盘；要完全退出，请右键系统托盘图标并选择“退出”。

## 四、租户管理

应用支持添加、编辑和删除租户。添加租户时可设置租户显示名称、服务地址、客户端 ID、客户端密钥、组织、应用名称、证书、设备显示名称和额外允许的网页地址。密钥保存后不可显示；留空编辑已保存租户时会保留原密钥。

额外允许的网页地址必须为 HTTPS。默认情况下，本机服务仅接受与当前租户服务地址相同来源的网页请求；添加额外地址前，应确认该网页确实需要发起设备登录。

## 五、GitHub Actions 构建

工作流文件为 [`.github/workflows/windows-release.yml`](.github/workflows/windows-release.yml)。推送 `main`、推送 `v*` 标签、提交拉取请求或手动触发时，工作流执行类型检查、Native SSO 协议回归测试，并在 Windows 运行器上生成两个安装包：

```text
cloud-verify-device-login-2.0.0-win-x64-setup.exe
cloud-verify-device-login-2.0.0-win-arm64-setup.exe
```

最终工件 `cloud-verify-device-login-windows-x64-arm64.zip` **只包含上述两个 EXE 文件**。不在工作流内签名时，Windows 可能显示未知发布者提示；生产分发建议在受保护的签名流程中使用组织的 Authenticode 证书。

### GitHub Secrets

下列 Secrets 为可选的构建前置检查项。它们不会被写入应用或发布包：

| Secret | 目的 |
| --- | --- |
| `TENANT_HUANGFA_CLIENT_SECRET` | 验证黄发科技集团的受保护密钥已由仓库管理员配置。 |
| `TENANT_PUBLIC_IAM_CLIENT_SECRET` | 验证公共认证服务的受保护密钥已由仓库管理员配置。 |

手动运行工作流时，将“Validate protected secret placeholders”设为开启，可检查这两个 Secret 是否存在。工作流只输出配置状态，不输出任何值。

## 六、从源码开发

开发机需要 Node.js 22 与 pnpm。安装依赖、执行类型检查并启动应用：

```bash
pnpm install --frozen-lockfile
pnpm run check
pnpm run build
pnpm run verify:native-sso
pnpm run start
```

本项目不要求在本地打包。GitHub Actions 负责 x64 和 ARM64 安装包的构建与汇总。

## 七、安全验收清单

| 检查项 | 预期结果 |
| --- | --- |
| 客户端密钥扫描 | 源码、文档、工作流和产物中不含实际客户端密钥。 |
| 本机保存 | 密钥、访问令牌和设备凭据仅以当前 Windows 用户可解密的形式保存。 |
| 退出登录 | 停止服务、删除会话、清除应用 Cookie。 |
| 租户切换 | 必须确认；确认后清除旧租户会话和 Cookie。 |
| Native SSO | 仅监听 `127.0.0.1:47321–47325`，并保持来源校验、请求大小限制与重复请求防护。 |
| 审批 | 每次登录使用通知中心单独确认；Windows Hello 开启时需要额外验证。 |
| 发布 | 双架构压缩包只含 x64 与 ARM64 两个安装程序。 |

## References

[1]: https://www.electronjs.org/docs/latest/tutorial/windows-arm "Electron — Windows on Arm"
[2]: https://learn.microsoft.com/en-us/uwp/api/windows.security.credentials.ui.userconsentverifier.requestverificationasync?view=winrt-28000 "Microsoft Learn — UserConsentVerifier.RequestVerificationAsync"
[3]: https://www.electronjs.org/docs/latest/tutorial/notifications "Electron — Notifications"
