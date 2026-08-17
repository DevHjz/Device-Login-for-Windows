# 云端验证设备认证服务：安全与租户架构

## 1. 设计目标

**云端验证设备认证服务（Cloud Verify Device Auth）** 面向 Windows 10 及更高版本，为受信任网页提供 Native SSO 设备认证与登录确认能力。运行时兼容 Windows x86、x64 与 ARM64；发布流程只生成 x64 与 ARM64 安装包。

> 桌面 EXE 是公共原生客户端。任何随软件分发给多个安装实例的共享 `client_secret` 都不能视为机密，因此本应用不保存、不传输、也不要求客户录入该类密钥。[1]

## 2. 租户数据与凭据边界

| 数据类别 | 保存位置 | 保护方式 | 生命周期 |
| --- | --- | --- | --- |
| 服务地址、客户端 ID、组织、应用名称、公开证书 | 租户预设与当前 Windows 用户配置 | 公开配置与本机文件权限 | 删除租户时删除自定义配置。 |
| PKCE `code_verifier` | 应用内存 | 不写入磁盘 | 单次登录完成、失败或 10 分钟超时后删除。 |
| access token、refresh token、`device_secret` | `session.json` | Electron `safeStorage`；Windows 当前用户数据保护 | 手动退出、切换租户、会话过期或系统重启后删除。 |
| 共享 `client_secret` | 不保存 | 不进入 EXE、租户表单、CI、日志或产物 | 不适用。 |
| 悬浮窗位置和尺寸 | `status-float-bounds.json` | 当前用户应用数据目录 | 移动或缩放后延迟保存。 |

旧版本遗留的 `builtInOverrides` 与 `clientSecretEncrypted` 字段会在 3.0 首次读取租户存储时移除，避免继续保留过时编辑覆盖或历史敏感数据。

## 3. 账户登录

两种登录方式都使用 OAuth 2.0 授权码流程、PKCE S256 和回调地址：

```text
cloud-verify-device-login://oauth/callback
```

| 登录方式 | 行为 | 适用场景 |
| --- | --- | --- |
| 应用内登录窗口（默认） | 使用受隔离的 Electron WebView 窗口加载身份服务；认证成功后由协议回调自动关闭窗口并刷新全部状态。 | 需要完整、连续的桌面引导体验。 |
| 系统默认浏览器 | 通过操作系统默认浏览器打开身份服务；结果通过同一自定义协议回调返回。 | 需要使用现有浏览器会话或组织浏览器策略。 |

两种方式都为每次登录生成独立 verifier，并在令牌换取时仅发送 `client_id`、授权码与 verifier。RFC 8252 要求公共原生客户端使用 PKCE；RFC 7636 定义 S256 以保护授权码回调。[1] [2]

## 4. 标准退出与重启策略

标准退出顺序如下：先停止本机 Native SSO 服务；随后向当前服务地址的 `/api/logout` 发送 `POST` 注销请求；最后删除本机加密会话并清除应用 Cookie。即使网络或服务端暂时不可用，也会继续完成本机清理，避免下次启动恢复旧账户。

会话中保存 Windows 启动标识。下次应用启动时，如发现标识变化，则视为系统已经关机或重启并执行标准退出。若已启用开机自启且首选 WebView 登录，只显示登录窗口与可选悬浮窗，不创建或显示主窗口。

## 5. Native SSO 审批与组织边界

首次登录返回的 `device_secret` 与 access token 共同作为受信任设备凭据。Native SSO Token Exchange 会验证设备凭据、令牌绑定、有效期、用户与目标应用权限。Casdoor 的实现允许当前桌面会话应用与网页目标应用处于**同一组织**时省略 client secret；跨组织请求应切换至对应租户。[3]

每次网页请求都会创建单次、限时的审批操作。Windows 通知中心展示“授权登录”和“拒绝”；通知回调令牌仅存在于内存，在审批、拒绝、超时或停止服务时失效。启用 Windows Hello 时，授权前会调用 `UserConsentVerifier`，并使用应用名称作为认证提示。[4]

## 6. 设备安全态势

安全态势模块只读取状态，不会修改系统策略、杀毒软件、防火墙或网络设置。应用启动时立即检测，随后每 30 分钟检测一次；主窗口和悬浮窗均可手动刷新。

| 检测项 | Windows 数据来源 | 通过条件 |
| --- | --- | --- |
| 设备登录凭据 | `Win32_ComputerSystem` 与当前本地账户信息 | Windows 登录需要密码或受保护凭据。 |
| 已注册杀毒软件 | `root/SecurityCenter2:AntivirusProduct` | 检测到并启用至少一个已注册产品。 |
| 病毒库 | 已注册产品状态；Defender 的 `Get-MpComputerStatus` | Defender 签名在 7 天内，或已注册产品返回当前状态。 |
| 防火墙 | `Get-NetFirewallProfile` | 所有可用网络配置文件启用。 |
| 网络展示 | `Get-NetIPAddress` 与 `Test-NetConnection 1.1.1.1:443` | 选取优先局域网 IPv4；可出站时标注“公网接入”。 |

四项安全检查全部通过时显示“通过检测”；有 1–2 项不通过或无法确认时显示“存在隐患”；超过 2 项时显示“高危风险”。

## 7. 设备态势悬浮窗

悬浮窗是无边框、浅蓝半透明的独立 Windows 窗口，默认显示、不在任务栏出现，并保存位置和尺寸。创建后，应用通过 Windows 原生桌面宿主层将其关联到桌面，而不使用普通应用的始终置顶层级；因此激活的普通应用应覆盖它，而返回桌面时仍可显示。标题区域支持拖动，窗口边缘支持调整大小。窗口通过主进程状态推送同步用户、租户、网域、IP、设备安全认证与登录状态；鼠标悬停在用户、租户和安全认证字段上会显示详细信息。

悬浮窗的登录/退出按钮调用与主窗口相同的操作，因此会遵循当前“应用内登录窗口 / 系统默认浏览器”设置。关闭悬浮窗开关时仅隐藏该窗口，不影响本机 Native SSO 服务。

## References

[1]: https://www.rfc-editor.org/rfc/rfc8252 "RFC 8252 — OAuth 2.0 for Native Apps"
[2]: https://www.rfc-editor.org/rfc/rfc7636 "RFC 7636 — Proof Key for Code Exchange by OAuth Public Clients"
[3]: https://github.com/casdoor/casdoor/blob/783cd64/object/token_native_sso.go#L54-L114 "Casdoor Native SSO token exchange"
[4]: https://learn.microsoft.com/en-us/uwp/api/windows.security.credentials.ui.userconsentverifier.requestverificationasync?view=winrt-28000 "Microsoft Learn — UserConsentVerifier.RequestVerificationAsync"
