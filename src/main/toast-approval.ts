import * as crypto from 'node:crypto'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)
const approvalLifetimeMs = 120_000
const appProtocol = 'cloud-verify-device-login'

function xmlEscape(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')
}

function encodePowerShell(script: string): string {
  return Buffer.from(script, 'utf16le').toString('base64')
}

function buildToastXml(requestId: string, targetName: string, accountName: string): string {
  const allow = `${appProtocol}://approval?request=${encodeURIComponent(requestId)}&decision=allow`
  const deny = `${appProtocol}://approval?request=${encodeURIComponent(requestId)}&decision=deny`
  const show = `${appProtocol}://show`
  return `<toast launch="${xmlEscape(show)}" activationType="protocol"><visual><binding template="ToastGeneric"><text>云端验证设备认证服务</text><text>“${xmlEscape(targetName)}”请求使用当前设备完成登录。</text><text>登录账户：${xmlEscape(accountName)}</text></binding></visual><actions><action content="授权登录" activationType="protocol" arguments="${xmlEscape(allow)}"/><action content="拒绝" activationType="protocol" arguments="${xmlEscape(deny)}"/></actions><audio silent="true"/></toast>`
}

async function showToast(xml: string, appId: string): Promise<void> {
  if (process.platform !== 'win32') {
    throw new Error('当前系统不支持 Windows 通知中心。')
  }

  const script = [
    'Add-Type -AssemblyName System.Runtime.WindowsRuntime',
    '[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime]',
    '[void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType=WindowsRuntime]',
    `$xml = New-Object Windows.Data.Xml.Dom.XmlDocument`,
    `$xml.LoadXml(@'`,
    xml,
    `'@)`,
    '$toast = New-Object Windows.UI.Notifications.ToastNotification $xml',
    `[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('${xmlEscape(appId)}').Show($toast)`,
  ].join('\n')

  await execFileAsync('powershell.exe', [
    '-NoProfile',
    '-NonInteractive',
    '-EncodedCommand',
    encodePowerShell(script),
  ], { windowsHide: true, timeout: 30_000 })
}

type PendingApproval = {
  resolve: (allowed: boolean) => void
  timeout: NodeJS.Timeout
}

export class ToastApprovalManager {
  private readonly pending = new Map<string, PendingApproval>()

  constructor(private readonly appId: string) {}

  public async request(input: { applicationName: string; userName: string; displayName: string }): Promise<boolean> {
    const requestId = crypto.randomUUID()
    const targetName = input.applicationName || '受信任网页'
    const accountName = input.displayName || input.userName

    const approval = new Promise<boolean>((resolve) => {
      const timeout = setTimeout(() => this.finish(requestId, false), approvalLifetimeMs)
      this.pending.set(requestId, { resolve, timeout })
    })

    try {
      await showToast(buildToastXml(requestId, targetName, accountName), this.appId)
    } catch (error) {
      this.finish(requestId, false)
      throw new Error('无法显示 Windows 登录通知。请确认通知中心未被系统策略关闭。')
    }

    return approval
  }

  public handleProtocolUrl(rawUrl: string): boolean {
    const url = new URL(rawUrl)
    if (url.hostname !== 'approval') return false
    const requestId = url.searchParams.get('request') || ''
    const decision = url.searchParams.get('decision')
    if (!requestId || !this.pending.has(requestId)) return true
    this.finish(requestId, decision === 'allow')
    return true
  }

  public cancelAll(): void {
    for (const requestId of this.pending.keys()) {
      this.finish(requestId, false)
    }
  }

  private finish(requestId: string, allowed: boolean): void {
    const pending = this.pending.get(requestId)
    if (!pending) return
    clearTimeout(pending.timeout)
    this.pending.delete(requestId)
    pending.resolve(allowed)
  }
}
