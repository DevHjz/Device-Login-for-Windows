import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

export type SecurityCheckState = 'pass' | 'warning' | 'unknown'

export type SecurityCheck = {
  id: 'password' | 'antivirus' | 'signatures' | 'firewall'
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
  antivirus?: { registered?: boolean; enabled?: boolean; names?: string[] }
  signatures?: { available?: boolean; upToDate?: boolean; ageDays?: number; source?: string }
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

function asBoolean(value: unknown): boolean | undefined {
  return typeof value === 'boolean' ? value : undefined
}

function asText(value: unknown): string {
  return typeof value === 'string' ? value.trim() : ''
}

function buildReport(data: RawSecurityData): DeviceSecurityReport {
  const passwordRequired = asBoolean(data.passwordRequired)
  const antivirusRegistered = asBoolean(data.antivirus?.registered)
  const antivirusEnabled = asBoolean(data.antivirus?.enabled)
  const signaturesCurrent = asBoolean(data.signatures?.upToDate)
  const firewallEnabled = asBoolean(data.firewall?.enabled)
  const antivirusNames = Array.isArray(data.antivirus?.names) ? data.antivirus.names.map(asText).filter(Boolean) : []
  const signatureAge = typeof data.signatures?.ageDays === 'number' ? data.signatures.ageDays : undefined

  const checks: SecurityCheck[] = [
    {
      id: 'password',
      title: '设备登录凭据',
      state: passwordRequired === true ? 'pass' : passwordRequired === false ? 'warning' : 'unknown',
      detail: passwordRequired === true
        ? '已检测到 Windows 登录需要密码或受保护的凭据。'
        : passwordRequired === false
          ? '未检测到 Windows 登录必须使用密码或受保护凭据。'
          : '当前系统未返回可用的 Windows 登录凭据策略。',
    },
    {
      id: 'antivirus',
      title: '杀毒软件',
      state: antivirusRegistered === true && antivirusEnabled === true ? 'pass' : antivirusRegistered === false || antivirusEnabled === false ? 'warning' : 'unknown',
      detail: antivirusRegistered === true && antivirusEnabled === true
        ? `已启用：${antivirusNames.join('、') || '已注册的杀毒软件'}。`
        : antivirusRegistered === false
          ? '未检测到已注册的杀毒软件。'
          : antivirusEnabled === false
            ? '已注册杀毒软件当前未启用。'
            : '无法确认已注册杀毒软件的启用状态。',
    },
    {
      id: 'signatures',
      title: '病毒库',
      state: signaturesCurrent === true ? 'pass' : signaturesCurrent === false ? 'warning' : 'unknown',
      detail: signaturesCurrent === true
        ? `病毒库状态正常${signatureAge !== undefined ? `（最近更新约 ${signatureAge} 天前）` : ''}。`
        : signaturesCurrent === false
          ? `病毒库可能已过期${signatureAge !== undefined ? `（最近更新约 ${signatureAge} 天前）` : ''}。`
          : '当前杀毒软件未提供可读取的病毒库状态。',
    },
    {
      id: 'firewall',
      title: 'Windows 防火墙',
      state: firewallEnabled === true ? 'pass' : firewallEnabled === false ? 'warning' : 'unknown',
      detail: firewallEnabled === true
        ? '所有可用网络配置文件均已启用防火墙。'
        : firewallEnabled === false
          ? '至少一个网络配置文件未启用防火墙。'
          : '无法确认 Windows 防火墙状态。',
    },
  ]

  // 无法确认安全状态也需要用户处理；只有四项全部通过才显示“通过检测”。
  const issueCount = checks.filter((check) => check.state !== 'pass').length
  const risk = issueCount === 0 ? 'pass' : issueCount <= 2 ? 'warning' : 'danger'
  return {
    checks,
    risk,
    issueCount,
    checkedAt: new Date().toISOString(),
    localIp: asText(data.localIp) || '未获取到',
    publicAccess: data.publicAccess === true,
  }
}

const securityScript = `
$ErrorActionPreference = 'SilentlyContinue'
$result = [ordered]@{
  passwordRequired = $null
  antivirus = [ordered]@{ registered = $null; enabled = $null; names = @() }
  signatures = [ordered]@{ available = $false; upToDate = $null; ageDays = $null; source = '' }
  firewall = [ordered]@{ available = $false; enabled = $null }
  localIp = ''
  publicAccess = $false
}

try {
  $computer = Get-CimInstance Win32_ComputerSystem
  if ($null -ne $computer.PasswordRequired) { $result.passwordRequired = [bool]$computer.PasswordRequired }
  $account = Get-CimInstance Win32_UserAccount -Filter "Name='$($env:USERNAME.Replace("'", "''"))'" | Select-Object -First 1
  if ($null -ne $account -and [bool]$account.PasswordRequired) { $result.passwordRequired = $true }
} catch {}

$products = @()
try {
  $products = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct)
  $result.antivirus.registered = ($products.Count -gt 0)
  $result.antivirus.names = @($products | ForEach-Object { [string]$_.displayName } | Where-Object { $_ })
  if ($products.Count -gt 0) {
    $result.antivirus.enabled = $false
    $signatureStates = @()
    foreach ($product in $products) {
      $stateHex = ('{0:X6}' -f [int]$product.productState)
      $providerState = [Convert]::ToInt32($stateHex.Substring(2, 2), 16)
      if (($providerState -band 0x10) -ne 0) { $result.antivirus.enabled = $true }
      $signatureStates += $stateHex.Substring(4, 2)
    }
    if ($signatureStates.Count -gt 0) {
      $result.signatures.available = $true
      if ($signatureStates -contains '00') { $result.signatures.upToDate = $true }
      elseif ($signatureStates -contains '10') { $result.signatures.upToDate = $false }
      $result.signatures.source = '已注册的杀毒软件'
    }
  }
} catch {}

try {
  $mp = Get-MpComputerStatus
  if ($null -ne $mp -and [bool]$mp.AntivirusEnabled) {
    $result.signatures.available = $true
    $age = [math]::Max(0, [math]::Floor(((Get-Date) - [datetime]$mp.AntivirusSignatureLastUpdated).TotalDays))
    $result.signatures.ageDays = [int]$age
    $result.signatures.upToDate = ($age -le 7 -and [bool]$mp.AntivirusSignatureVersion)
    $result.signatures.source = 'Microsoft Defender'
    if ($null -eq $result.antivirus.registered) { $result.antivirus.registered = $true }
    if ($null -eq $result.antivirus.enabled) { $result.antivirus.enabled = $true }
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
  $ips = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' -and $_.PrefixOrigin -ne 'WellKnown'
  } | Select-Object -ExpandProperty IPAddress)
  $private = @($ips | Where-Object { $_ -like '10.*' -or $_ -like '192.168.*' -or $_ -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.' })
  $result.localIp = [string](@($private + $ips | Select-Object -Unique | Select-Object -First 1))
} catch {}

try {
  $result.publicAccess = Test-NetConnection -ComputerName '1.1.1.1' -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
} catch {}

$result | ConvertTo-Json -Depth 6 -Compress
`

export async function collectDeviceSecurityReport(): Promise<DeviceSecurityReport> {
  if (process.platform !== 'win32') return buildReport({})
  try {
    return buildReport(await runPowerShell(securityScript))
  } catch {
    return buildReport({})
  }
}
