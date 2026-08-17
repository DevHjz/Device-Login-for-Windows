# 云端验证设备认证服务

> **Cloud Verify Device Auth 3.0** 是面向 Windows 的网页设备认证与登录确认服务。它在本机回环地址提供受限的 Native SSO 服务，通过 Windows 通知中心请求用户授权网页登录，并提供设备安全态势与桌面状态悬浮窗。

| 项目 | 交付标准 |
| --- | --- |
| 最低系统 | Windows 10；Windows on Arm 的功能验证基线为 Windows 10 版本 1903 或更高版本。[1] |
| 运行时兼容性 | Windows x86、x64、ARM64。 |
| 发布安装包 | GitHub Actions 输出 x64 与 ARM64 NSIS EXE，并汇总为仅包含两个 EXE 的 ZIP。 |
| 软件名称 | 用户可见名称为“云端验证设备认证服务”；内部安装目录与可执行文件为 `cloud-verify-device-auth`。 |
| 登录方式 | 默认应用内 WebView；可在系统设置切换为系统默认浏览器。两种方式均使用授权码流程与 PKCE S256。 |
| 审批方式 | Windows 通知中心“授权登录 / 拒绝”；可选 Windows Hello 二次认证。 |

## 一、无共享密钥模型

本应用是公共原生客户端，不保存、传输或要求录入共享 `client_secret`。每次账户登录都生成一次性 PKCE verifier，并将其 S256 challenge 发往身份服务；verifier 仅保留在内存，回调完成、失败或超时后失效。RFC 8252 要求公共原生客户端使用 PKCE，而静态随桌面应用分发的共享 secret 不能被视为安全边界。[2] [3]

| 数据 | 保存方式 | 说明 |
| --- | --- | --- |
| 服务地址、客户端 ID、组织、应用名称、公开证书 | 租户预设或本机配置 | 公开参数。 |
| PKCE verifier | 仅内存，最长 10 分钟 | 单次账户登录完成后删除。 |
| access token、refresh token、`device_secret` | 当前 Windows 用户的受保护本机存储 | 退出、切换租户或检测到系统重启后删除。 |
| 共享 `client_secret` | 不保存 | 不进入租户表单、配置、日志、CI 或安装包。 |

## 二、内置租户与服务端要求

| 租户显示名称 | 服务地址 | 客户端 ID | 组织 | 应用名称 |
| --- | --- | --- | --- | --- |
| 黄发科技集团 | `https://sso.devhjz.com` | `b39a5ad6d95848ffde82` | `Cloud` | `Cloud` |
| 公共认证服务 | `https://sso.devhjz.com` | `6f6a7b4337ffb3d3ee3f` | `Public-IAM` | `Public-APP` |

两个桌面租户应用都需在身份服务登记以下回调地址：

```text
cloud-verify-device-login://oauth/callback
```

请确认已启用 **Authorization Code**、**PKCE**、`device_sso` scope、**Token Exchange** 和 **Companion Approval**。Native SSO 的桌面会话应用与网页目标应用必须处于同一组织；跨组织情况应切换至对应租户。Casdoor 的 Native SSO 同组织交换可基于受保护的设备凭据完成，而无需桌面端提交共享 secret。[4]

## 三、账户登录与退出

系统设置中的“账户登录方式”默认是**应用内登录窗口（WebView）**。认证成功时，WebView 会自动关闭，主窗口与悬浮窗会立即刷新登录用户、设备服务和安全认证状态。选择“系统默认浏览器”后，应用会打开默认浏览器并通过同一自定义协议回调接收登录结果。

标准退出会先向当前租户的 `https://<服务地址>/api/logout` 发起 `POST` 注销请求，然后停止本机服务、清除本机会话和应用 Cookie。网络不可用时，应用仍会清除本机会话，确保下次不能恢复旧账户。

每次 Windows 关机或重启后，应用会检测本机启动标识变化，并在下一次启动时执行上述退出流程。启用开机自启且使用 WebView 时，只显示账户登录窗口和可选状态悬浮窗，**不会显示主窗口**。

## 四、设备安全态势

应用启动时会自动检查一次；运行中每 30 分钟自动检查一次。主窗口“设备安全态势”区域和悬浮窗“刷新”按钮可随时执行手动检查。所有检查均为**只读展示**，不会更改杀毒软件、防火墙、密码策略或网络设置。

| 检查项 | 检测方式 | 风险说明 |
| --- | --- | --- |
| 设备登录凭据 | `Get-CimInstance -ClassName Win32_UserAccount`，读取 `PasswordRequired` | 未检测到登录凭据要求时标为隐患。 |
| C 盘 BitLocker | `Get-BitLockerVolume -MountPoint 'C:'`，读取卷状态、保护状态和加密百分比 | 未完全加密或保护未启用时标为隐患。 |
| 杀毒软件 | `Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct`，解析 `productState` | 适用于 Defender、360、火绒等向 Windows Security Center 注册的产品。 |
| 病毒库 | `Get-MpComputerStatus` 的 Defender 签名更新时间；其它产品使用 Security Center `productState` 作有限判断 | 超过 7 天或明确过期时标为隐患。 |
| Windows 防火墙 | `Get-NetFirewallProfile -PolicyStore ActiveStore`，读取 Domain、Private、Public 配置文件 | 任一配置文件未启用时标为隐患。 |
| 网络 | `Get-NetIPAddress -AddressFamily IPv4`；保留 `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16` 私网地址，并用 `Test-NetConnection 172.64.36.1` 探测公网连通性 | 可联通时显示“（公网接入）”。 |

检测由应用通过 `powershell.exe -NoProfile -NonInteractive -OutputFormat Text -EncodedCommand …` 在本机执行，**不调用云端安全检测 API**。检测结果会先 `ConvertTo-Json`，再以 UTF-8 Base64 输出，避免 PowerShell 控制台代码页造成中文乱码。

安全认证结果按照五项安全检查计算：全部通过显示**通过检测**；出现 1–2 项隐患或无法确认的状态显示**存在隐患**；出现超过 2 项明确问题显示**高危风险**。

## 五、桌面状态悬浮窗

默认显示“云端验证设备认证状态”悬浮窗。可在系统设置中关闭或重新开启；窗口位置与大小会保存，支持手动拖动标题区域和在边缘调整尺寸。悬浮窗包含下列内容：

| 字段 | 展示规则 |
| --- | --- |
| 登录用户 | 显示账户昵称；鼠标悬停显示用户名。 |
| 所属租户 | 显示租户名称；鼠标悬停显示组织名称。 |
| 租户网域 | 个人邮箱域名显示“个人用户”；包含 `devhjz` 的域名显示为 `DevHjz`；其它显示邮箱域名。 |
| IP 地址 | 显示优先局域网 IPv4；可联通公网时追加“（公网接入）”。 |
| 安全认证 | 绿色“通过检测”、黄色“存在隐患”、红色“高危风险”；鼠标悬停显示五项检查详情。 |

悬浮窗为无边框 Windows 桌面状态窗口，使用浅蓝半透明样式，不出现在任务栏。它通过 Windows 桌面宿主层显示，不采用覆盖普通应用的始终置顶模式；普通应用激活时应覆盖它，返回桌面时仍可显示。它会随应用内状态变化自动刷新；登录/退出按钮遵循系统设置中选择的登录方式。

## 六、租户管理与托盘

租户界面仅提供**添加租户**和**删除租户**，不提供编辑入口。添加时可填写租户显示名称、服务地址、客户端 ID、组织、应用名称、公开证书、设备显示名称和额外允许网页地址。额外网页地址必须使用 HTTPS。

切换租户前会要求确认；确认后执行标准退出，清除旧租户的本机会话与 Cookie。关闭主窗口只会隐藏至托盘；右键托盘图标并选择“退出”才会关闭进程。

## 七、GitHub Actions 构建

工作流文件为 [`.github/workflows/windows-release.yml`](.github/workflows/windows-release.yml)。推送 `main`、推送 `v*` 标签、提交拉取请求或手动触发时，工作流执行类型检查、Native SSO 回归、Windows 外壳回归、设备安全态势回归、公共客户端 PKCE 回归与发布配置校验。

```text
cloud-verify-device-auth-3.0.3-win-x64-setup.exe
cloud-verify-device-auth-3.0.3-win-arm64-setup.exe
```

最终工件 `cloud-verify-device-auth-windows-x64-arm64.zip` 只包含上述两个 EXE 文件。工作流不引用、校验或注入任何租户 client secret。生产环境建议在受保护的签名流程中使用组织的 Authenticode 证书。

## 八、从源码开发

```bash
pnpm install --frozen-lockfile
pnpm run check
pnpm run build
pnpm run verify:native-sso
pnpm run verify:windows-shell
pnpm run verify:device-security
pnpm run verify:public-client
node scripts/verify-release-config.cjs
pnpm run start
```

## References

[1]: https://www.electronjs.org/docs/latest/tutorial/windows-arm "Electron — Windows on Arm"
[2]: https://www.rfc-editor.org/rfc/rfc8252 "RFC 8252 — OAuth 2.0 for Native Apps"
[3]: https://www.rfc-editor.org/rfc/rfc7636 "RFC 7636 — Proof Key for Code Exchange by OAuth Public Clients"
[4]: https://github.com/casdoor/casdoor/blob/783cd64/object/token_native_sso.go#L54-L114 "Casdoor Native SSO token exchange"
