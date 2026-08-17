# 云端验证设备认证服务

> **Cloud Verify Device Auth 3.0** 是面向 Windows 10+ 的桌面伴随应用。它在本机回环地址提供受限的设备认证服务，通过 Windows 通知中心确认网页授权请求，并提供设备安全态势展示与桌面悬浮窗。

## 功能概览

| 功能 | 说明 |
| --- | --- |
| 多租户 | 预置“黄发科技集团”和“公共认证服务”；界面仅提供**添加租户**与**删除租户**。切换或删除当前租户会退出本机账户。 |
| 账户登录 | 系统设置可选“内置登录窗口（默认）”或“系统默认浏览器”。两种方式均使用既有 OAuth 回调协议 `cloud-verify-device-login://oauth/callback`，避免服务端已登记的回调地址失效。 |
| 通知授权 | 网页认证请求通过 Windows 通知中心展示“授权登录 / 拒绝”。可选 Windows Hello 二次验证。 |
| 开机安全退出 | 检测到新的 Windows 启动周期后，应用先请求 `https://sso.devhjz.com/api/logout`，再清除本机会话和应用 Cookies；若选择内置登录窗口，会直接显示登录窗口而不显示主窗口。 |
| 设备安全态势 | 每 30 分钟和手动刷新时，只读检查 Windows 登录密码要求、C 盘 BitLocker、已注册杀毒软件与启用状态、可读取的病毒库状态以及防火墙状态。 |
| 桌面悬浮窗 | 默认在桌面右上角显示账户、租户、邮箱网域、局域网 IP 与安全认证状态。可拖动、调整大小，位置与尺寸会保存；可在系统设置关闭。 |
| 系统托盘 | 主窗口关闭时隐藏至托盘，托盘菜单可显示主窗口或退出。 |
| Windows 支持 | 支持 Windows 10+，发布 x64 和 ARM64 NSIS 安装程序。 |

## 设备安全态势说明

安全检查仅用于展示，不会修改系统设置。状态根据未通过或无法确认的检查数量计算：全部通过显示“通过检测”；1–3 项问题或待确认项显示“存在隐患”；超过 3 项显示“高危风险”。第三方杀毒软件是否能提供病毒库日期取决于其是否向 Windows 安全中心公开该信息；无法读取时会清晰标注而不会伪造结果。

悬浮窗中的“租户网域”按账户邮箱后缀展示。`163`、`126`、`QQ`、`yeah`、`gmail`、`outlook` 等常见个人邮箱域显示为“个人用户”；包含 `devhjz` 的网域固定展示为 `DevHjz`。

## 安全边界

认证信息不会写入 Git 仓库、README、日志或安装包。租户认证信息仅由管理员在客户设备本机保存，并使用当前 Windows 用户的数据保护能力加密。退出、租户切换、删除当前租户及检测到新的 Windows 启动周期时，应用均会停止设备服务、请求服务端退出并清除本机 Cookies 与会话。

## 构建

GitHub Actions 工作流会在 `windows-latest` 上分别构建 x64 和 ARM64 安装程序，并生成一个只包含两个 EXE 文件的合并压缩包。

```text
cloud-verify-device-auth-3.0.0-win-x64-setup.exe
cloud-verify-device-auth-3.0.0-win-arm64-setup.exe
cloud-verify-device-auth-windows-x64-arm64.zip
```

构建前会执行 TypeScript 检查、Native SSO 回归测试、Windows 外壳行为检查及发布配置检查。工作流只验证受保护的认证配置占位项是否存在，不会将任何认证信息写入工作区、日志或发布产物。

## 身份服务配置

目标网页应用应启用 `device_sso` 范围和 RFC 8693 Token Exchange 授权类型，并保留 OAuth 回调地址：

```text
cloud-verify-device-login://oauth/callback
```

> 当前应用未包含 Authenticode 签名。面向大范围生产分发时，应在受保护的发布流程中使用组织的 Windows 代码签名证书。
