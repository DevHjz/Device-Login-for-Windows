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
  unknownCount: number
  checkedAt: string
  localIp: string
  publicAccess: boolean
  networkId: string
  platformSupported: boolean
}

type CheckValue = { available?: boolean; value?: boolean; detail?: string }
type RawSecurityData = {
  password?: CheckValue
  bitlocker?: CheckValue & { volumeStatus?: string; protectionStatus?: string; encryptionPercentage?: number }
  antivirus?: CheckValue & { names?: string[] }
  signatures?: CheckValue & { ageDays?: number; ignored?: boolean }
  firewall?: CheckValue
  localIp?: string
  publicAccess?: boolean
  networkId?: string
  platformSupported?: boolean
}

function encodedPowerShell(script: string): string { return Buffer.from(script, 'utf16le').toString('base64') }

/** PowerShell 以 UTF-8 Base64 输出 JSON，避免宿主控制台代码页污染中文内容。 */
async function runPowerShell(script: string): Promise<RawSecurityData> {
  const { stdout } = await execFileAsync('powershell.exe', [
    '-NoProfile', '-NonInteractive', '-OutputFormat', 'Text', '-EncodedCommand', encodedPowerShell(script),
  ], { windowsHide: true, timeout: 30_000, maxBuffer: 512 * 1024 })
  const payload = stdout.trim().split(/\r?\n/).filter(Boolean).at(-1)?.trim()
  if (!payload) throw new Error('Windows 系统信息接口没有返回数据。')
  try { return JSON.parse(Buffer.from(payload, 'base64').toString('utf8')) as RawSecurityData }
  catch { throw new Error('Windows 系统信息接口返回了无法识别的检测数据。') }
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
  const bitLockerStatus = [asText(data.bitlocker?.volumeStatus), asText(data.bitlocker?.protectionStatus), typeof data.bitlocker?.encryptionPercentage === 'number' ? `已加密 ${data.bitlocker.encryptionPercentage}%` : ''].filter(Boolean).join('；')
  const checks: SecurityCheck[] = [
    {
      id: 'password', title: '设备登录凭据', state: stateFrom(data.password),
      detail: detailFor(data.password, '当前 Windows 账户要求使用密码或系统凭据登录。', '当前 Windows 账户未要求密码或系统凭据。', '未能读取当前 Windows 账户的凭据策略。'),
    },
    {
      id: 'bitlocker', title: 'C 盘 BitLocker', state: stateFrom(data.bitlocker),
      detail: detailFor(data.bitlocker, `C 盘 BitLocker 已启用并完成加密${bitLockerStatus ? `（${bitLockerStatus}）` : ''}。`, `C 盘 BitLocker 未完全启用${bitLockerStatus ? `（${bitLockerStatus}）` : ''}。`, '未能读取 C 盘 BitLocker 状态。'),
    },
    {
      id: 'antivirus', title: '杀毒软件', state: stateFrom(data.antivirus),
      detail: detailFor(data.antivirus, `已启用：${antivirusNames.join('、') || '已注册的安全产品'}。`, '未检测到已启用的杀毒软件。', '未能读取 Windows 安全中心的杀毒软件状态。'),
    },
    {
      id: 'signatures', title: '病毒库', state: data.signatures?.ignored === true ? 'pass' : stateFrom(data.signatures),
      detail: data.signatures?.ignored === true
        ? asText(data.signatures.detail) || '已启用第三方杀毒软件，Windows 无法可靠读取其病毒库状态；该项不计入安全风险。'
        : detailFor(data.signatures, `病毒库状态正常${signatureAge !== undefined ? `（最近更新约 ${signatureAge} 天前）` : ''}。`, `病毒库已过期或需要更新${signatureAge !== undefined ? `（最近更新约 ${signatureAge} 天前）` : ''}。`, '未能读取当前安全产品的病毒库状态。'),
    },
    {
      id: 'firewall', title: 'Windows 防火墙', state: stateFrom(data.firewall),
      detail: detailFor(data.firewall, '域、专用与公用网络配置文件均已启用防火墙。', '至少一个 Windows 防火墙配置文件未启用。', '未能读取 Windows 防火墙活动策略。'),
    },
  ]
  const issueCount = checks.filter((check) => check.state === 'warning').length
  const unknownCount = checks.filter((check) => check.state === 'unknown').length
  // 系统接口暂未返回的项目仅供详情展示，不应被当作设备风险或向用户显示为检测异常。
  const risk = issueCount === 0 ? 'pass' : issueCount > 2 ? 'danger' : 'warning'
  return {
    checks, risk, issueCount, unknownCount, checkedAt: new Date().toISOString(), localIp: asText(data.localIp) || '网络未连接', publicAccess: asText(data.localIp) !== '' && data.publicAccess === true,
    networkId: asText(data.networkId) || asText(data.localIp) || 'offline', platformSupported: data.platformSupported !== false && platformSupported,
  }
}

const securityScript = `
$ErrorActionPreference = 'Stop'
function New-Check { [ordered]@{ available = $false; value = $null; detail = '' } }
$result = [ordered]@{
  platformSupported = $true
  password = New-Check
  bitlocker = [ordered]@{ available = $false; value = $null; detail = ''; volumeStatus = ''; protectionStatus = ''; encryptionPercentage = $null }
  antivirus = [ordered]@{ available = $false; value = $null; detail = ''; names = @() }
  signatures = [ordered]@{ available = $false; value = $null; detail = ''; ageDays = $null; ignored = $false }
  firewall = New-Check
  localIp = ''
  publicAccess = $false
  networkId = 'offline'
}

# Win32_UserAccount.PasswordRequired：当前本地账户是否要求 Windows 登录凭据。
try {
  $account = @(Get-CimInstance -ClassName Win32_UserAccount -ErrorAction Stop | Where-Object { $_.Name -eq [Environment]::UserName } | Select-Object -First 1)
  if ($account.Count -eq 1 -and $null -ne $account[0].PasswordRequired) {
    $result.password.available = $true
    $result.password.value = [bool]$account[0].PasswordRequired
  } else { $result.password.detail = '未找到当前 Windows 账户的 PasswordRequired 属性。' }
} catch { $result.password.detail = $_.Exception.Message }

# Get-BitLockerVolume：读取系统盘 C: 的卷状态、保护状态及加密百分比。
try {
  $volume = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop
  $result.bitlocker.available = $true
  $result.bitlocker.volumeStatus = [string]$volume.VolumeStatus
  $result.bitlocker.protectionStatus = [string]$volume.ProtectionStatus
  $result.bitlocker.encryptionPercentage = [int]$volume.EncryptionPercentage
  $result.bitlocker.value = ([string]$volume.VolumeStatus -eq 'FullyEncrypted' -and [string]$volume.ProtectionStatus -ne 'Off' -and [int]$volume.EncryptionPercentage -eq 100)
} catch { $result.bitlocker.detail = $_.Exception.Message }

# Windows Security Center：读取已向系统注册的安全产品，并按 productState 的实时保护与签名字节判断状态。
try {
  $products = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop)
  $result.antivirus.available = $true
  $result.antivirus.names = @($products | ForEach-Object { [string]$_.displayName } | Where-Object { $_ })
  $productStates = @($products | ForEach-Object {
    $hex = ('{0:X6}' -f [int]$_.productState)
    [ordered]@{ name = [string]$_.displayName; realTime = [Convert]::ToInt32($hex.Substring(2, 2), 16); signatures = [Convert]::ToInt32($hex.Substring(4, 2), 16) }
  })
  $enabledProducts = @($productStates | Where-Object { $_.realTime -eq 0x10 })
  $result.antivirus.value = ($enabledProducts.Count -gt 0)
  $enabledThirdParty = @($enabledProducts | Where-Object { $_.name -notmatch '^(Microsoft|Windows) Defender( Antivirus)?$' })
  if ($enabledThirdParty.Count -gt 0) {
    $result.signatures.available = $true
    $result.signatures.value = $true
    $result.signatures.ignored = $true
    $result.signatures.detail = '已启用第三方杀毒软件，Windows 无法可靠读取其病毒库状态；该项不计入安全风险。'
  } elseif ($productStates.Count -gt 0) {
    $result.signatures.available = $true
    $result.signatures.value = (@($productStates | Where-Object { $_.signatures -ne 0x00 }).Count -eq 0)
  }
} catch { $result.antivirus.detail = $_.Exception.Message }

# Defender 的病毒库时间优先于 Security Center productState 的有限签名判断。
try {
  $mp = Get-MpComputerStatus -ErrorAction Stop
  if ([bool]$mp.AntivirusEnabled) {
    $result.antivirus.available = $true
    $result.antivirus.value = [bool]$mp.AntivirusEnabled
    if (@($result.antivirus.names).Count -eq 0) { $result.antivirus.names = @('Microsoft Defender') }
    if (-not [bool]$result.signatures.ignored) {
      $lastUpdated = [datetime]$mp.AntivirusSignatureLastUpdated
      $age = [math]::Max(0, [math]::Floor(((Get-Date) - $lastUpdated).TotalDays))
      $result.signatures.available = $true
      $result.signatures.ageDays = [int]$age
      $result.signatures.value = ($lastUpdated -gt [datetime]::MinValue -and $age -le 7)
    }
  }
} catch {}

# ActiveStore 内的 Domain、Private、Public 三个配置文件是当前生效的防火墙策略。
try {
  $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
  $expected = @('Domain', 'Private', 'Public')
  $activeProfiles = @($profiles | Where-Object { $_.Name -in $expected })
  $result.firewall.available = ($activeProfiles.Count -eq 3)
  if ($result.firewall.available) { $result.firewall.value = (@($activeProfiles | Where-Object { -not $_.Enabled }).Count -eq 0) }
  else { $result.firewall.detail = '未读取到完整的 Domain、Private、Public 防火墙配置文件。' }
} catch { $result.firewall.detail = $_.Exception.Message }

# Get-NetIPAddress 返回本机 IPv4；只接受状态为 Up 的网络适配器，并明确保留 RFC 1918 私网地址（10/8、172.16/12、192.168/16）。
try {
  $activeIfIndex = @((Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { [int]$_.ifIndex }))
  $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
    $_.ifIndex -in $activeIfIndex -and $_.AddressState -eq 'Preferred'
  } | ForEach-Object { [string]$_.IPAddress } | Where-Object {
    $_ -notmatch '^(127\\.|169\\.254\\.|0\\.|2(2[4-9]|[3-5][0-9])\\.|255\\.)'
  })
  $private = @($ips | Where-Object { $_ -like '10.*' -or $_ -like '192.168.*' -or $_ -match '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.' })
  $result.localIp = [string](@($private + $ips | Select-Object -Unique | Select-Object -First 1))
  $profile = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceIndex -in $activeIfIndex } | Select-Object -First 1)
  if ($profile.Count -gt 0) { $result.networkId = "$([string]$profile[0].Name)|$([string]$profile[0].InterfaceAlias)|$($result.localIp)" }
  elseif ($result.localIp) { $result.networkId = [string]$result.localIp }
} catch {}

if ($result.localIp) {
  try { $result.publicAccess = [bool](Test-NetConnection -ComputerName 172.64.36.1 -InformationLevel Quiet -ErrorAction Stop) }
  catch { $result.publicAccess = $false }
}

$json = $result | ConvertTo-Json -Depth 7 -Compress
[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))
`

export async function collectDeviceSecurityReport(): Promise<DeviceSecurityReport> {
  if (process.platform !== 'win32') return buildReport({ platformSupported: false }, false)
  try { return buildReport(await runPowerShell(securityScript)) }
  catch (error) {
    const detail = error instanceof Error ? error.message : 'Windows 系统信息接口调用失败。'
    return buildReport({
      platformSupported: true,
      password: { available: false, detail }, bitlocker: { available: false, detail }, antivirus: { available: false, detail }, signatures: { available: false, detail }, firewall: { available: false, detail },
    })
  }
}


const networkAccessScript = `
$ErrorActionPreference = 'Stop'
$result = [ordered]@{ localIp = ''; publicAccess = $false; networkId = 'offline' }
try {
  $activeIfIndex = @((Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { [int]$_.ifIndex }))
  $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
    $_.ifIndex -in $activeIfIndex -and $_.AddressState -eq 'Preferred'
  } | ForEach-Object { [string]$_.IPAddress } | Where-Object {
    $_ -notmatch '^(127\\.|169\\.254\\.|0\\.|2(2[4-9]|[3-5][0-9])\\.|255\\.)'
  })
  $private = @($ips | Where-Object { $_ -like '10.*' -or $_ -like '192.168.*' -or $_ -match '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.' })
  $result.localIp = [string](@($private + $ips | Select-Object -Unique | Select-Object -First 1))
  $profile = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceIndex -in $activeIfIndex } | Select-Object -First 1)
  if ($profile.Count -gt 0) { $result.networkId = "$([string]$profile[0].Name)|$([string]$profile[0].InterfaceAlias)|$($result.localIp)" }
  elseif ($result.localIp) { $result.networkId = [string]$result.localIp }
} catch {}
if ($result.localIp) {
  try { $result.publicAccess = [bool](Test-NetConnection -ComputerName 172.64.36.1 -InformationLevel Quiet -ErrorAction Stop) }
  catch { $result.publicAccess = $false }
}
$json = $result | ConvertTo-Json -Depth 3 -Compress
[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))
`

export type NetworkAccessState = Pick<DeviceSecurityReport, 'localIp' | 'publicAccess' | 'networkId'>

/**
 * 仅刷新网络状态。该探测会在 Wi-Fi 门户认证等“IP 未变、出网能力变化”的场景定时执行，
 * 不重复读取 BitLocker、杀毒与防火墙等安全项。
 */
export async function collectNetworkAccessState(): Promise<NetworkAccessState> {
  if (process.platform !== 'win32') return { localIp: '网络未连接', publicAccess: false, networkId: 'offline' }
  try {
    const data = await runPowerShell(networkAccessScript)
    const localIp = asText(data.localIp) || '网络未连接'
    return { localIp, publicAccess: localIp !== '网络未连接' && data.publicAccess === true, networkId: asText(data.networkId) || localIp }
  } catch { return { localIp: '网络未连接', publicAccess: false, networkId: 'offline' } }
}
