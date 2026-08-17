import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

export type SecurityCheckState = 'pass' | 'warning' | 'unknown'

export type SecurityCheck = {
  id: 'password' | 'bitlocker' | 'antivirus' | 'signatures' | 'firewall'
  title: string
  state: SecurityCheckState
  detail: string
}

export type DeviceSecurityReport = {
  checks: SecurityCheck[]
  risk: 'pass' | 'warning' | 'danger'
  issueCount: number
  checkedAt: string
  localIp: string
  publicAccess: boolean
}

type RawSecurityData = {
  passwordRequired?: boolean
  bitLocker?: { available?: boolean; protected?: boolean; status?: string }
  antivirus?: { registered?: boolean; enabled?: boolean; names?: string[] }
  signatures?: { available?: boolean; upToDate?: boolean; ageDays?: number }
  firewall?: { available?: boolean; enabled?: boolean }
  localIp?: string
  publicAccess?: boolean
}

function encodedPowerShell(script: string): string {
  return Buffer.from(script, 'utf16le').toString('base64')
}

async function runPowerShell(script: string): Promise<RawSecurityData> {
  const { stdout } = await execFileAsync('powershell.exe', [
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy', 'Bypass',
    '-EncodedCommand', encodedPowerShell(script),
  ], { windowsHide: true, timeout: 20_000, maxBuffer: 512 * 1024 })
  return JSON.parse(stdout.trim()) as RawSecurityData
}

function safeText(value: unknown): string {
  return typeof value === 'string' ? value.trim() : ''
}

function asBoolean(value: unknown): boolean | undefined {
  return typeof value === 'boolean' ? value : undefined
}

function buildReport(data: RawSecurityData): DeviceSecurityReport {
  const passwordRequired = asBoolean(data.passwordRequired)
  const bitLockerProtected = asBoolean(data.bitLocker?.protected)
  const antivirusRegistered = asBoolean(data.antivirus?.registered)
  const antivirusEnabled = asBoolean(data.antivirus?.enabled)
  const signaturesCurrent = asBoolean(data.signatures?.upToDate)
  const firewallEnabled = asBoolean(data.firewall?.enabled)
  const antivirusNames = Array.isArray(data.antivirus?.names) ? data.antivirus!.names!.map(safeText).filter(Boolean) : []

  const checks: SecurityCheck[] = [
    {
      id: 'password',
      title: '登录密码',
      state: passwordRequired === true ? 'pass' : passwordRequired === false ? 'warning' : 'unknown',
      detail: passwordRequired === true ? '当前 Windows 登录需要凭据。' : passwordRequired === false ? '未检测到 Windows 登录密码要求。' : '无法读取 Windows 登录密码策略。',
    },
    {
      id: 'bitlocker',
      title: 'C 盘 BitLocker',
      state: bitLockerProtected === true ? 'pass' : bitLockerProtected === false ? 'warning' : 'unknown',
      detail: bitLockerProtected === true ? '系统盘已启用 BitLocker 保护。' : bitLockerProtected === false ? '系统盘未启用 BitLocker 保护。' : '无法确认系统盘 BitLocker 状态，已从安全态势评分中忽略。',
    },
    {
      id: 'antivirus',
      title: '杀毒软件',
      state: antivirusRegistered === true && antivirusEnabled === true ? 'pass' : antivirusRegistered === false || antivirusEnabled === false ? 'warning' : 'unknown',
      detail: antivirusRegistered === true && antivirusEnabled === true
        ? `已启用：${antivirusNames.join('、') || '已注册的杀毒软件'}。`
        : antivirusRegistered === false ? '未检测到已注册并启用的杀毒软件。'
          : antivirusEnabled === false ? '已注册杀毒软件当前未启用。' : '无法确认杀毒软件状态。',
    },
    {
      id: 'signatures',
      title: '病毒库',
      state: signaturesCurrent === true ? 'pass' : signaturesCurrent === false ? 'warning' : 'unknown',
      detail: signaturesCurrent === true ? '已检测到有效的病毒库更新。' : signaturesCurrent === false
        ? `病毒库可能已过期${typeof data.signatures?.ageDays === 'number' ? `（约 ${data.signatures.ageDays} 天）` : ''}。`
        : '当前杀毒软件未提供可读取的病毒库状态。',
    },
    {
      id: 'firewall',
      title: 'Windows 防火墙',
      state: firewallEnabled === true ? 'pass' : firewallEnabled === false ? 'warning' : 'unknown',
      detail: firewallEnabled === true ? '所有已启用的网络配置文件均受到防火墙保护。' : firewallEnabled === false ? '存在未启用 Windows 防火墙的网络配置文件。' : '无法确认 Windows 防火墙状态。',
    },
  ]

  // BitLocker 在部分 Windows 版本、策略环境或非专业版系统中无法读取；此时只展示，不影响风险分级。
  const issueCount = checks.filter((check) => check.state !== 'pass' && !(check.id === 'bitlocker' && check.state === 'unknown')).length
  const risk = issueCount === 0 ? 'pass' : issueCount <= 3 ? 'warning' : 'danger'
  return {
    checks,
    risk,
    issueCount,
    checkedAt: new Date().toISOString(),
    localIp: safeText(data.localIp) || '未获取到',
    publicAccess: data.publicAccess === true,
  }
}

const securityScript = `
$ErrorActionPreference = 'SilentlyContinue'
$result = [ordered]@{
  passwordRequired = $null
  bitLocker = [ordered]@{ available = $false; protected = $null; status = '' }
  antivirus = [ordered]@{ registered = $null; enabled = $null; names = @() }
  signatures = [ordered]@{ available = $false; upToDate = $null; ageDays = $null }
  firewall = [ordered]@{ available = $false; enabled = $null }
  localIp = ''
  publicAccess = $false
}

try {
  $computer = Get-CimInstance Win32_ComputerSystem
  if ($null -ne $computer.PasswordRequired) { $result.passwordRequired = [bool]$computer.PasswordRequired }
} catch {}

try {
  $volume = Get-BitLockerVolume -MountPoint 'C:'
  $result.bitLocker.available = $true
  $result.bitLocker.status = [string]$volume.ProtectionStatus
  $result.bitLocker.protected = ([string]$volume.ProtectionStatus -eq 'On' -or [int]$volume.ProtectionStatus -eq 1)
} catch {}

try {
  $products = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct)
  $result.antivirus.registered = ($products.Count -gt 0)
  $result.antivirus.names = @($products | ForEach-Object { [string]$_.displayName } | Where-Object { $_ })
  if ($products.Count -gt 0) {
    $result.antivirus.enabled = $false
    foreach ($product in $products) {
      $stateHex = ('{0:X6}' -f [int]$product.productState)
      $providerState = [Convert]::ToInt32($stateHex.Substring(2, 2), 16)
      if (($providerState -band 0x10) -ne 0) { $result.antivirus.enabled = $true }
    }
  }
} catch {}

try {
  $mp = Get-MpComputerStatus
  if ($null -ne $mp) {
    $result.signatures.available = $true
    $age = [math]::Floor(((Get-Date) - [datetime]$mp.AntivirusSignatureLastUpdated).TotalDays)
    $result.signatures.ageDays = [int]$age
    $result.signatures.upToDate = ($age -le 7 -and [bool]$mp.AntivirusSignatureVersion)
    if ($null -eq $result.antivirus.registered) { $result.antivirus.registered = $true }
    if ($null -eq $result.antivirus.enabled) { $result.antivirus.enabled = [bool]$mp.AntivirusEnabled }
    if ($result.antivirus.names.Count -eq 0) { $result.antivirus.names = @('Microsoft Defender') }
  }
} catch {}

try {
  $profiles = @(Get-NetFirewallProfile)
  if ($profiles.Count -gt 0) {
    $result.firewall.available = $true
    $result.firewall.enabled = (@($profiles | Where-Object { -not $_.Enabled }).Count -eq 0)
  }
} catch {}

try {
  $ip = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' -and $_.PrefixOrigin -ne 'WellKnown'
  } | Select-Object -First 1 -ExpandProperty IPAddress
  $result.localIp = [string]$ip
} catch {}

try {
  $result.publicAccess = Test-NetConnection -ComputerName '1.1.1.1' -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
} catch {}

$result | ConvertTo-Json -Depth 6 -Compress
`

export async function collectDeviceSecurityReport(): Promise<DeviceSecurityReport> {
  if (process.platform !== 'win32') {
    return buildReport({})
  }
  try {
    return buildReport(await runPowerShell(securityScript))
  } catch {
    return buildReport({})
  }
}
