import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

function encodePowerShell(script: string): string {
  return Buffer.from(script, 'utf16le').toString('base64')
}

function awaitWinRt(operationExpression: string): string[] {
  return [
    'Add-Type -AssemblyName System.Runtime.WindowsRuntime',
    '[void][Windows.Security.Credentials.UI.UserConsentVerifier, Windows.Security.Credentials.UI, ContentType=WindowsRuntime]',
    `$operation = ${operationExpression}`,
    '$task = [System.WindowsRuntimeSystemExtensions]::AsTask($operation)',
    '$task.GetAwaiter().GetResult().ToString()',
  ]
}

const availabilityScript = awaitWinRt('[Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync()').join('\n')

function escapePowerShell(value: string): string {
  return value.replace(/'/g, "''")
}

function verifyScript(reason: string): string {
  return awaitWinRt(`[Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync('${escapePowerShell(reason)}')`).join('\n')
}

function resultLine(output: string): string {
  const knownResult = output.trim().split(/\r?\n/).map((line) => line.trim()).find((line) => (
    /^(Available|DeviceBusy|DeviceNotPresent|DisabledByPolicy|NotConfiguredForUser|Verified|Canceled|RetriesExhausted)$/
  ).test(line))
  return knownResult ?? output.trim()
}

async function runPowerShell(script: string): Promise<string> {
  const { stdout } = await execFileAsync('powershell.exe', [
    '-NoLogo',
    '-NoProfile',
    // Windows Hello 需要 STA 线程与交互式会话；不能使用 -NonInteractive。
    '-STA',
    '-EncodedCommand',
    encodePowerShell(script),
  ], { windowsHide: true, timeout: 60_000 })
  return resultLine(stdout)
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
    if (result === 'DeviceBusy') {
      return { available: false, message: 'Windows Hello 正在被使用，请稍后重试。' }
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
    return { available: false, message: 'Windows Hello 当前不可用。请确认已在 Windows 设置中完成 PIN、人脸或指纹验证。' }
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
    if (result === 'RetriesExhausted') {
      throw new Error('Windows Hello 验证失败次数过多，请稍后重试。')
    }
    if (result === 'DeviceNotPresent') {
      throw new Error('此设备未配置 Windows Hello。')
    }
    if (result === 'NotConfiguredForUser') {
      throw new Error('当前 Windows 用户尚未设置 Windows Hello。')
    }
    if (result === 'DisabledByPolicy') {
      throw new Error('Windows Hello 已被系统策略禁用。')
    }
    throw new Error('Windows Hello 未能确认本次操作。')
  } catch (error) {
    if (error instanceof Error && /Windows Hello|取消|此设备|当前 Windows 用户/.test(error.message)) {
      throw error
    }
    throw new Error('Windows Hello 验证未完成。请确认已在 Windows 设置中完成 PIN、人脸或指纹验证。')
  }
}
