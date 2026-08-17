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
  unknownCount: number
  checkedAt: string
  localIp: string
  publicAccess: boolean
  platformSupported: boolean
}

type CheckValue = { available?: boolean; value?: boolean; detail?: string }
type RawSecurityData = {
  password?: CheckValue
  antivirus?: CheckValue & { names?: string[] }
  signatures?: CheckValue & { ageDays?: number }
  firewall?: CheckValue
  localIp?: string
  publicAccess?: boolean
  platformSupported?: boolean
}

function encodedPowerShell(script: string): string { return Buffer.from(script, 'utf16le').toString('base64') }

async function runPowerShell(script: string): Promise<RawSecurityData> {
  const { stdout } = await execFileAsync('powershell.exe', [
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encodedPowerShell(script),
  ], { windowsHide: true, timeout: 25_000, maxBuffer: 512 * 1024 })
  const payload = stdout.trim()
  if (!payload) throw new Error('Windows 系统信息接口没有返回数据。')
  return JSON.parse(payload) as RawSecurityData
}

function asBoolean(value: unknown): boolean | undefined { return typeof value === 'boolean' ? value : undefined }
function asText(value: unknown): string { return typeof value === 'string' ? value.trim() : '' }

function stateFrom(value: CheckValue | undefined): SecurityCheckState {
  if (asBoolean(value?.available) !== true || asBoolean(value?.value) === undefined) return 'unknown'
  return value?.value === true ? 'pass' : 'warning'
}

function detailFor(value: CheckValue | undefined, passText: string, warningText: string, unavailableFallback: string): string {
  const available = asBoolean(value?.available)
  const result = asBoolean(value?.value)
  if (available === true && result === true) return passText
  if (available === true && result === false) return warningText
  return asText(value?.detail) || unavailableFallback
}

function buildReport(data: RawSecurityData, platformSupported = true): DeviceSecurityReport {
  const antivirusNames = Array.isArray(data.antivirus?.names) ? data.antivirus.names.map(asText).filter(Boolean) : []
  const signatureAge = typeof data.signatures?.ageDays === 'number' ? data.signatures.ageDays : undefined
  const checks: SecurityCheck[] = [
    {
      id: 'password', title: '设备登录凭据', state: stateFrom(data.password),
      detail: detailFor(data.password, '已检测到当前 Windows 账户需要受保护的登录凭据。', '当前 Windows 账户不要求登录凭据。', '未能读取当前 Windows 账户的凭据策略。'),
    },
    {
      id: 'antivirus', title: '杀毒软件', state: stateFrom(data.antivirus),
      detail: detailFor(data.antivirus, `已启用：${antivirusNames.join('、') || '已注册的安全产品'}。`, '未检测到已启用的杀毒软件。', '未能读取 Windows 安全中心的杀毒软件状态。'),
    },
    {
      id: 'signatures', title: '病毒库', state: stateFrom(data.signatures),
      detail: detailFor(data.signatures, `病毒库状态正常${signatureAge !== undefined ? `（最近更新约 ${signatureAge} 天前）` : ''}。`, `病毒库已过期或需要更新${signatureAge !== undefined ? `（最近更新约 ${signatureAge} 天前）` : ''}。`, '未能读取当前安全产品的病毒库状态。'),
    },
    {
      id: 'firewall', title: 'Windows 防火墙', state: stateFrom(data.firewall),
      detail: detailFor(data.firewall, '所有有效网络配置文件均已启用防火墙。', '至少一个有效网络配置文件未启用防火墙。', '未能读取当前 Windows 防火墙活动策略。'),
    },
  ]
  const issueCount = checks.filter((check) => check.state === 'warning').length
  const unknownCount = checks.filter((check) => check.state === 'unknown').length
  const risk = issueCount === 0 && unknownCount === 0 ? 'pass' : issueCount > 2 ? 'danger' : 'warning'
  return {
    checks, risk, issueCount, unknownCount, checkedAt: new Date().toISOString(), localIp: asText(data.localIp) || '未获取到', publicAccess: data.publicAccess === true,
    platformSupported: data.platformSupported !== false && platformSupported,
  }
}

const securityScript = `
$ErrorActionPreference = 'Stop'
$result = [ordered]@{
  platformSupported = $true
  password = [ordered]@{ available = $false; value = $null; detail = '' }
  antivirus = [ordered]@{ available = $false; value = $null; detail = ''; names = @() }
  signatures = [ordered]@{ available = $false; value = $null; detail = ''; ageDays = $null }
  firewall = [ordered]@{ available = $false; value = $null; detail = '' }
  localIp = ''
  publicAccess = $false
}

# NetUserGetInfo 读取当前账户的 UF_PASSWD_NOTREQD 标志，避免依赖不稳定的 Win32_UserAccount CIM 属性。
try {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
public struct USER_INFO_1 {
  public string usri1_name; public string usri1_password; public int usri1_password_age; public int usri1_priv;
  public string usri1_home_dir; public string usri1_comment; public int usri1_flags; public string usri1_script_path;
}
public static class CloudVerifyNetApi {
  [DllImport("Netapi32.dll", CharSet=CharSet.Unicode)]
  public static extern int NetUserGetInfo(string servername, string username, int level, out IntPtr bufptr);
  [DllImport("Netapi32.dll")]
  public static extern int NetApiBufferFree(IntPtr buffer);
}
'@ -ErrorAction SilentlyContinue
  [IntPtr]$buffer = [IntPtr]::Zero
  $status = [CloudVerifyNetApi]::NetUserGetInfo($null, [Environment]::UserName, 1, [ref]$buffer)
  if ($status -eq 0 -and $buffer -ne [IntPtr]::Zero) {
    $account = [Runtime.InteropServices.Marshal]::PtrToStructure($buffer, [type][USER_INFO_1])
    $result.password.available = $true
    $result.password.value = (($account.usri1_flags -band 0x20) -eq 0)
    [void][CloudVerifyNetApi]::NetApiBufferFree($buffer)
  } else {
    $result.password.detail = "Windows 账户接口返回代码：$status"
  }
} catch { $result.password.detail = $_.Exception.Message }

# 优先使用 Windows Security Center 的 COM 产品清单；它是第三方安全产品向系统注册后的统一状态入口。
try {
  $products = @()
  $list = New-Object -ComObject 'SecurityCenter.WscProductList'
  $list.Initialize(4) # WSC_SECURITY_PROVIDER_ANTIVIRUS
  for ($i = 0; $i -lt $list.Count; $i++) { $products += $list.Item($i) }
  $result.antivirus.available = $true
  $result.antivirus.names = @($products | ForEach-Object { [string]$_.ProductName } | Where-Object { $_ })
  $enabledProducts = @($products | Where-Object { [int]$_.ProductState -eq 0 }) # WSC_SECURITY_PRODUCT_STATE_ON
  $result.antivirus.value = ($enabledProducts.Count -gt 0)
  if ($enabledProducts.Count -gt 0) {
    $signatureStates = @($enabledProducts | ForEach-Object { [int]$_.SignatureStatus })
    $result.signatures.available = $true
    $result.signatures.value = (-not ($signatureStates -contains 1)) # WSC_SECURITY_PRODUCT_UP_TO_DATE = 0
  }
} catch {
  # 兼容无法创建 COM 产品清单的系统；WMI 只作为回退读取路径。
  try {
    $products = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction Stop)
    $result.antivirus.available = $true
    $result.antivirus.names = @($products | ForEach-Object { [string]$_.displayName } | Where-Object { $_ })
    $result.antivirus.value = ($products.Count -gt 0)
    if ($products.Count -gt 0) { $result.signatures.detail = '当前注册安全产品未公开病毒库状态。' }
  } catch { $result.antivirus.detail = $_.Exception.Message }
}

# Defender 是 Windows 内置的稳定状态接口；在它实际运行时可提供更精确的实时保护与病毒库年龄。
try {
  $mp = Get-MpComputerStatus -ErrorAction Stop
  $defenderEnabled = ([bool]$mp.AMServiceEnabled -and [bool]$mp.AntivirusEnabled -and [bool]$mp.RealTimeProtectionEnabled -and [string]$mp.AMRunningMode -eq 'Normal')
  if ($defenderEnabled -or -not [bool]$result.antivirus.available) {
    $result.antivirus.available = $true
    $result.antivirus.value = $defenderEnabled
    $result.antivirus.names = @('Microsoft Defender')
  }
  if ($defenderEnabled) {
    $age = [int]$mp.AntivirusSignatureAge
    $result.signatures.available = $true
    $result.signatures.ageDays = $age
    $result.signatures.value = ($age -ge 0 -and $age -le 7 -and -not [string]::IsNullOrWhiteSpace([string]$mp.AntivirusSignatureVersion))
  }
} catch {}

# HNetCfg.FwPolicy2 读取生效的三类防火墙配置；Get-NetFirewallProfile ActiveStore 用作回退。
try {
  $policy = New-Object -ComObject 'HNetCfg.FwPolicy2'
  $result.firewall.available = $true
  $result.firewall.value = ([bool]$policy.FirewallEnabled(1) -and [bool]$policy.FirewallEnabled(2) -and [bool]$policy.FirewallEnabled(4))
} catch {
  try {
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    $result.firewall.available = ($profiles.Count -gt 0)
    $result.firewall.value = ($profiles.Count -gt 0 -and @($profiles | Where-Object { -not $_.Enabled }).Count -eq 0)
  } catch { $result.firewall.detail = $_.Exception.Message }
}

# 使用 .NET 网络接口读取活动物理网卡的 IPv4；不依赖可选的 NetTCPIP 模块。
try {
  $interfaces = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object {
    $_.OperationalStatus -eq [System.Net.NetworkInformation.OperationalStatus]::Up -and
    $_.NetworkInterfaceType -ne [System.Net.NetworkInformation.NetworkInterfaceType]::Loopback -and
    $_.NetworkInterfaceType -ne [System.Net.NetworkInformation.NetworkInterfaceType]::Tunnel
  }
  $ips = @($interfaces | ForEach-Object { $_.GetIPProperties().UnicastAddresses } | Where-Object {
    $_.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and
    $_.Address.IPAddressToString -notlike '169.254.*'
  } | ForEach-Object { $_.Address.IPAddressToString })
  $private = @($ips | Where-Object { $_ -like '10.*' -or $_ -like '192.168.*' -or $_ -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.' })
  $result.localIp = [string](@($private + $ips | Select-Object -Unique | Select-Object -First 1))
} catch {}

try {
  $client = New-Object System.Net.Sockets.TcpClient
  $task = $client.ConnectAsync('1.1.1.1', 443)
  $result.publicAccess = $task.Wait(2500) -and $client.Connected
  $client.Dispose()
} catch { $result.publicAccess = $false }

$result | ConvertTo-Json -Depth 6 -Compress
`

export async function collectDeviceSecurityReport(): Promise<DeviceSecurityReport> {
  if (process.platform !== 'win32') return buildReport({ platformSupported: false }, false)
  try { return buildReport(await runPowerShell(securityScript)) }
  catch (error) {
    const detail = error instanceof Error ? error.message : 'Windows 系统信息接口调用失败。'
    return buildReport({
      platformSupported: true,
      password: { available: false, detail }, antivirus: { available: false, detail }, signatures: { available: false, detail }, firewall: { available: false, detail },
    })
  }
}
