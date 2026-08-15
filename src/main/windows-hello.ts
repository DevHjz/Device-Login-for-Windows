import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

const availabilityScript = [
  "Add-Type -AssemblyName System.Runtime.WindowsRuntime",
  "[void][Windows.Security.Credentials.UI.UserConsentVerifier, Windows.Security.Credentials.UI, ContentType=WindowsRuntime]",
  "$op = [Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync()",
  "$task = [System.WindowsRuntimeSystemExtensions]::AsTask($op)",
  "$task.GetAwaiter().GetResult().ToString()",
].join('; ')

function escapePowerShell(value: string): string {
  return value.replace(/'/g, "''")
}

function verifyScript(reason: string): string {
  return [
    "Add-Type -AssemblyName System.Runtime.WindowsRuntime",
    "[void][Windows.Security.Credentials.UI.UserConsentVerifier, Windows.Security.Credentials.UI, ContentType=WindowsRuntime]",
    `$op = [Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync('${escapePowerShell(reason)}')`,
    "$task = [System.WindowsRuntimeSystemExtensions]::AsTask($op)",
    "$task.GetAwaiter().GetResult().ToString()",
  ].join('; ')
}

async function runPowerShell(script: string): Promise<string> {
  const { stdout } = await execFileAsync('powershell.exe', [
    '-NoProfile',
    '-NonInteractive',
    '-Command',
    script,
  ], { windowsHide: true, timeout: 30_000 })
  return stdout.trim()
}

export type WindowsHelloAvailability = {
  available: boolean
  message: string
}

export async function getWindowsHelloAvailability(): Promise<WindowsHelloAvailability> {
  if (process.platform !== 'win32') {
    return { available: false, message: '当前系统不支持 Windows Hello 验证。' }
  }

  try {
    const result = await runPowerShell(availabilityScript)
    if (result === 'Available') {
      return { available: true, message: 'Windows Hello 已可用。' }
    }
    if (result === 'DeviceNotPresent') {
      return { available: false, message: '此设备未配置 Windows Hello。' }
    }
    if (result === 'NotConfiguredForUser') {
      return { available: false, message: '当前 Windows 用户尚未设置 Windows Hello。' }
    }
    if (result === 'DisabledByPolicy') {
      return { available: false, message: 'Windows Hello 已被系统策略禁用。' }
    }
    return { available: false, message: 'Windows Hello 当前不可用。' }
  } catch {
    return { available: false, message: '无法调用 Windows Hello。请检查系统设置或安全策略。' }
  }
}

export async function verifyWithWindowsHello(reason: string): Promise<boolean> {
  const availability = await getWindowsHelloAvailability()
  if (!availability.available) {
    throw new Error(availability.message)
  }

  try {
    const result = await runPowerShell(verifyScript(reason))
    if (result === 'Verified') return true
    if (result === 'Canceled') {
      throw new Error('您已取消 Windows Hello 验证。')
    }
    if (result === 'DeviceBusy') {
      throw new Error('Windows Hello 正在被使用，请稍后重试。')
    }
    throw new Error('Windows Hello 未能确认本次操作。')
  } catch (error) {
    if (error instanceof Error && /Windows Hello|取消/.test(error.message)) {
      throw error
    }
    throw new Error('Windows Hello 验证未完成。')
  }
}
