import { app, BrowserWindow, dialog, ipcMain, Menu, safeStorage, screen, session as electronSession, shell, Tray } from 'electron'
import * as crypto from 'node:crypto'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { IdentityClient } from './identity-client'
import { collectDeviceSecurityReport, type DeviceSecurityReport } from './device-security'
import { NativeSsoService } from './native-sso'
import { BUILT_IN_TENANTS, type TenantPreset } from './tenant-presets'
import { ToastApprovalManager } from './toast-approval'
import { getWindowsHelloAvailability, verifyWithWindowsHello } from './windows-hello'

const PRODUCT_NAME = '云端验证设备认证服务'
// 保留已登记的 OAuth 回调协议，避免服务端既有配置失效。
const PROTOCOL = 'cloud-verify-device-login'
const CALLBACK_URI = `${PROTOCOL}://oauth/callback`
const DEFAULT_PORT = 47321
const APP_USER_MODEL_ID = 'com.devhjz.cloudverify.device-auth'
const START_IN_TRAY_ARGUMENT = '--start-in-tray'
const TENANT_STORE_FILE = 'tenants.json'
const SESSION_FILE = 'session.json'
const BOOT_MARKER_FILE = 'boot-marker.json'
const STATUS_FLOAT_BOUNDS_FILE = 'status-float-bounds.json'
const execFileAsync = promisify(execFile)

type Tenant = TenantPreset & {
  clientSecretEncrypted?: string
  createdAt: string
  updatedAt: string
  source: 'built-in' | 'custom'
}

type TenantInput = {
  id?: string
  displayName?: string
  endpoint?: string
  clientId?: string
  orgName?: string
  appName?: string
  certificate?: string
  allowedOrigins?: unknown
  deviceName?: string
  clientSecret?: string
}

type LoginMode = 'webview' | 'browser'

type Preferences = {
  launchAtLogin: boolean
  requireWindowsHello: boolean
  loginMode: LoginMode
  showStatusFloat: boolean
}

type TenantStore = {
  activeTenantId: string
  customTenants: Tenant[]
  builtInOverrides: Record<string, Tenant>
  deletedBuiltInTenantIds: string[]
  preferences: Preferences
}

type BootMarker = { marker: string }
type StatusFloatBounds = { x: number; y: number; width: number; height: number }

type StoredSession = {
  tenantId: string
  accessTokenEncrypted: string
  refreshTokenEncrypted?: string
  deviceSecretEncrypted?: string
  userName: string
  displayName: string
  avatar: string
  expiresAt?: number
}

type PublicTenant = Omit<Tenant, 'clientSecretEncrypted'> & { hasClientSecret: boolean }

type PendingLoginRequest = {
  tenantId: string
  timeout: NodeJS.Timeout
}

type Status = {
  configured: boolean
  signedIn: boolean
  companionRunning: boolean
  userName?: string
  displayName?: string
  devicePort?: number
  lastError?: string
  activeTenantId?: string
  activeTenantName?: string
  activeTenantOrgName?: string
  requireWindowsHello: boolean
  securityReport?: DeviceSecurityReport
}

let mainWindow: BrowserWindow | null = null
let authWindow: BrowserWindow | null = null
let statusFloatWindow: BrowserWindow | null = null
let statusFloatBoundsSaveTimer: NodeJS.Timeout | null = null
let tray: Tray | null = null
let companion: NativeSsoService | null = null
let companionPort: number | null = null
let sessionExpiryTimer: NodeJS.Timeout | null = null
let securityRefreshTimer: NodeJS.Timeout | null = null
let securityReport: DeviceSecurityReport | undefined
const pendingLoginRequests = new Map<string, PendingLoginRequest>()
const recentOAuthCallbacks = new Map<string, NodeJS.Timeout>()
let companionRunning = false
let lastError = ''
let isQuitting = false
let launchInTray = process.argv.includes(START_IN_TRAY_ARGUMENT)
const approvals = new ToastApprovalManager(APP_USER_MODEL_ID)

function appDataPath(fileName: string): string {
  return path.join(app.getPath('userData'), fileName)
}

function iconPath(): string {
  // 安装后从 resources 目录读取独立图标，避免 Windows 回退到默认应用图标。
  return app.isPackaged
    ? path.join(process.resourcesPath, 'app.ico')
    : path.join(__dirname, '../assets/app.ico')
}

function encodeProtected(value: string): string {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('Windows 数据保护服务不可用，无法安全保存敏感信息。')
  }
  return safeStorage.encryptString(value).toString('base64')
}

function decodeProtected(value: string): string {
  return safeStorage.decryptString(Buffer.from(value, 'base64'))
}

async function readJson<T>(fileName: string): Promise<T | null> {
  try {
    return JSON.parse(await fs.readFile(appDataPath(fileName), 'utf8')) as T
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
    throw new Error('无法读取本机配置。')
  }
}

async function writeJson(fileName: string, value: unknown): Promise<void> {
  await fs.mkdir(app.getPath('userData'), { recursive: true })
  await fs.writeFile(appDataPath(fileName), JSON.stringify(value, null, 2), { encoding: 'utf8', mode: 0o600 })
}

function normalizeEndpoint(endpoint: string): string {
  const value = endpoint.trim().replace(/\/+$/, '')
  const parsed = new URL(value)
  if (!['https:', 'http:'].includes(parsed.protocol)) throw new Error('服务地址格式不正确。')
  return value
}

function parseAllowedOrigins(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  const origins: string[] = []
  for (const raw of value) {
    if (typeof raw !== 'string' || !raw.trim()) continue
    const parsed = new URL(raw.trim())
    if (parsed.protocol !== 'https:') throw new Error('额外允许的网页地址必须使用 HTTPS。')
    origins.push(parsed.origin)
  }
  return [...new Set(origins)]
}

function defaultTenant(id: string): Tenant {
  const preset = BUILT_IN_TENANTS.find((item) => item.id === id) ?? BUILT_IN_TENANTS[0]
  const timestamp = new Date().toISOString()
  return { ...preset, createdAt: timestamp, updatedAt: timestamp, source: 'built-in' }
}

function defaultStore(): TenantStore {
  return {
    activeTenantId: BUILT_IN_TENANTS[0].id,
    customTenants: [],
    builtInOverrides: {},
    deletedBuiltInTenantIds: [],
    preferences: { launchAtLogin: false, requireWindowsHello: false, loginMode: 'webview', showStatusFloat: true },
  }
}

async function getStore(): Promise<TenantStore> {
  let stored: Partial<TenantStore> | null = null
  try {
    stored = await readJson<Partial<TenantStore>>(TENANT_STORE_FILE)
  } catch {
    // 旧版本或异常中断可能留下无法解析的配置；先以安全默认值启动，供用户一键恢复。
    lastError = '本机配置无法读取。请在系统设置中选择“恢复默认设置”。'
  }
  const source = stored ?? defaultStore()
  return {
    activeTenantId: source.activeTenantId || BUILT_IN_TENANTS[0].id,
    customTenants: Array.isArray(source.customTenants) ? source.customTenants : [],
    builtInOverrides: source.builtInOverrides && typeof source.builtInOverrides === 'object' ? source.builtInOverrides : {},
    deletedBuiltInTenantIds: Array.isArray(source.deletedBuiltInTenantIds) ? source.deletedBuiltInTenantIds : [],
    preferences: {
      launchAtLogin: Boolean(source.preferences?.launchAtLogin),
      requireWindowsHello: Boolean(source.preferences?.requireWindowsHello),
      loginMode: source.preferences?.loginMode === 'browser' ? 'browser' : 'webview',
      showStatusFloat: source.preferences?.showStatusFloat !== false,
    },
  }
}

function listTenants(store: TenantStore): Tenant[] {
  const builtIns = BUILT_IN_TENANTS
    .filter((preset) => !store.deletedBuiltInTenantIds.includes(preset.id))
    .map((preset) => ({ ...defaultTenant(preset.id), ...(store.builtInOverrides[preset.id] ?? {}), id: preset.id, source: 'built-in' as const }))
  return [...builtIns, ...store.customTenants]
}

function toPublicTenant(tenant: Tenant): PublicTenant {
  const { clientSecretEncrypted: _secret, ...publicData } = tenant
  return { ...publicData, hasClientSecret: Boolean(tenant.clientSecretEncrypted) }
}

async function getActiveTenant(store?: TenantStore): Promise<Tenant> {
  const currentStore = store ?? await getStore()
  const tenant = listTenants(currentStore).find((item) => item.id === currentStore.activeTenantId)
  if (!tenant) throw new Error('请先添加并选择一个租户。')
  return tenant
}

async function getTenantById(tenantId: string): Promise<Tenant> {
  const store = await getStore()
  const tenant = listTenants(store).find((item) => item.id === tenantId)
  if (!tenant) throw new Error('登录请求对应的租户已不存在，请重新发起登录。')
  return tenant
}

function rememberLoginRequest(state: string, tenantId: string): void {
  const previous = pendingLoginRequests.get(state)
  if (previous) clearTimeout(previous.timeout)
  const timeout = setTimeout(() => pendingLoginRequests.delete(state), 10 * 60 * 1000)
  pendingLoginRequests.set(state, { tenantId, timeout })
}

function consumeLoginRequest(state: string): PendingLoginRequest | null {
  const request = pendingLoginRequests.get(state)
  if (!request) return null
  clearTimeout(request.timeout)
  pendingLoginRequests.delete(state)
  return request
}

function isDuplicateOAuthCallback(url: URL): boolean {
  const key = [
    url.searchParams.get('state') || '',
    url.searchParams.get('code') || '',
    url.searchParams.get('error') || '',
  ].join('|')
  if (recentOAuthCallbacks.has(key)) return true
  const timeout = setTimeout(() => recentOAuthCallbacks.delete(key), 15_000)
  recentOAuthCallbacks.set(key, timeout)
  return false
}

function validateTenantInput(input: TenantInput, existing?: Tenant): Tenant {
  const displayName = String(input.displayName ?? existing?.displayName ?? '').trim()
  const endpoint = normalizeEndpoint(String(input.endpoint ?? existing?.endpoint ?? ''))
  const clientId = String(input.clientId ?? existing?.clientId ?? '').trim()
  const orgName = String(input.orgName ?? existing?.orgName ?? '').trim()
  const appName = String(input.appName ?? existing?.appName ?? '').trim()
  const certificate = String(input.certificate ?? existing?.certificate ?? '').trim()
  const deviceName = String(input.deviceName ?? existing?.deviceName ?? '').trim()
  const suppliedSecret = typeof input.clientSecret === 'string' ? input.clientSecret.trim() : ''
  if (!displayName || !clientId || !orgName || !appName || !certificate.includes('BEGIN CERTIFICATE')) {
    throw new Error('请填写租户名称、客户端 ID、组织、应用名称和有效证书。')
  }
  return {
    id: existing?.id ?? crypto.randomUUID(),
    displayName,
    endpoint,
    clientId,
    orgName,
    appName,
    certificate,
    allowedOrigins: parseAllowedOrigins(input.allowedOrigins ?? existing?.allowedOrigins ?? []),
    deviceName,
    clientSecretEncrypted: suppliedSecret ? encodeProtected(suppliedSecret) : existing?.clientSecretEncrypted,
    createdAt: existing?.createdAt ?? new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    source: existing?.source ?? 'custom',
  }
}

function createIdentityClient(tenant: Tenant): IdentityClient {
  if (!tenant.clientSecretEncrypted) throw new Error('当前租户尚未完成认证配置，请由管理员在租户设置中完成设置。')
  return new IdentityClient({
    endpoint: tenant.endpoint,
    clientId: tenant.clientId,
    clientSecret: decodeProtected(tenant.clientSecretEncrypted),
    certificate: tenant.certificate,
  })
}

function tokenExpiration(token: string): number | undefined {
  try {
    const [, payload] = token.split('.')
    if (!payload) return undefined
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as { exp?: number }
    return typeof data.exp === 'number' ? data.exp * 1000 : undefined
  } catch {
    return undefined
  }
}

function isSessionExpired(stored: StoredSession): boolean {
  return Boolean(stored.expiresAt && stored.expiresAt <= Date.now())
}

async function getStoredSession(): Promise<StoredSession | null> {
  try {
    return await readJson<StoredSession>(SESSION_FILE)
  } catch {
    lastError = '本机登录信息无法读取，已停止恢复旧会话。可在系统设置中恢复默认设置。'
    return null
  }
}

async function clearStoredSession(): Promise<void> {
  await fs.rm(appDataPath(SESSION_FILE), { force: true })
}

async function clearIdentityCookies(): Promise<void> {
  await electronSession.defaultSession.clearStorageData({ storages: ['cookies'] })
}

async function getWindowsBootMarker(): Promise<string> {
  if (process.platform !== 'win32') return `non-windows:${process.uptime()}`
  try {
    const { stdout } = await execFileAsync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', '(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToFileTimeUtc()'])
    const marker = stdout.trim()
    if (marker) return marker
  } catch {
    // 使用进程启动时间作为受限环境下的保守回退，避免恢复旧会话。
  }
  return `fallback:${Date.now()}`
}

async function notifyServerLogout(stored: StoredSession | null): Promise<void> {
  if (!stored) return
  try {
    const tenant = await getTenantById(stored.tenantId)
    const accessToken = decodeProtected(stored.accessTokenEncrypted)
    const cookies = await electronSession.defaultSession.cookies.get({ url: tenant.endpoint })
    const cookieHeader = cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join('; ')
    await fetch(new URL('/api/logout', tenant.endpoint), {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json',
        ...(cookieHeader ? { Cookie: cookieHeader } : {}),
      },
      signal: AbortSignal.timeout(8_000),
    })
  } catch {
    // 无网络或服务端会话已失效时，仍继续清除本机凭据与 Cookies。
  }
}

async function resetToDefaults(): Promise<void> {
  const result = await dialog.showMessageBox({
    type: 'warning',
    buttons: ['恢复默认设置', '取消'],
    defaultId: 1,
    cancelId: 1,
    title: '确认恢复默认设置',
    message: '将清除本机账户、租户添加记录和系统偏好，并恢复预置租户。是否继续？',
    detail: '此操作不会修改身份服务端的数据。',
    noLink: true,
  })
  if (result.response !== 0) return
  await stopCompanion()
  await clearIdentityCookies()
  await Promise.all([
    fs.rm(appDataPath(TENANT_STORE_FILE), { force: true }),
    fs.rm(appDataPath(SESSION_FILE), { force: true }),
    fs.rm(appDataPath(BOOT_MARKER_FILE), { force: true }),
    fs.rm(appDataPath(STATUS_FLOAT_BOUNDS_FILE), { force: true }),
  ])
  const store = defaultStore()
  await writeJson(TENANT_STORE_FILE, store)
  applyLaunchAtLogin(false)
  await setStatusFloatVisible(store.preferences.showStatusFloat)
  lastError = ''
  publishStatus()
}

async function signOutCurrentSession(): Promise<void> {
  const stored = await getStoredSession()
  await stopCompanion()
  await notifyServerLogout(stored)
  await clearStoredSession()
  await clearIdentityCookies()
}

async function signOutOnNewBoot(): Promise<boolean> {
  const marker = await getWindowsBootMarker()
  const previous = await readJson<BootMarker>(BOOT_MARKER_FILE)
  await writeJson(BOOT_MARKER_FILE, { marker })
  if (!previous || previous.marker === marker) return false
  await signOutCurrentSession()
  return true
}

async function stopCompanion(): Promise<void> {
  if (sessionExpiryTimer) { clearTimeout(sessionExpiryTimer); sessionExpiryTimer = null }
  approvals.cancelAll()
  if (companion) { await companion.stop(); companion = null }
  companionPort = null
  companionRunning = false
}

async function showNativeSsoApproval(input: { applicationName?: string; userName: string; displayName?: string }): Promise<boolean> {
  const currentStore = await getStore()
  const allowed = await approvals.request({
    applicationName: input.applicationName || '受信任网页',
    userName: input.userName,
    displayName: input.displayName || input.userName,
  })
  if (!allowed) return false
  if (currentStore.preferences.requireWindowsHello) {
    const applicationName = input.applicationName || '该应用'
    await verifyWithWindowsHello(`您正在请求登录${applicationName}应用，\n请使用您的凭据授权该应用访问您的账号。`)
  }
  return true
}

function scheduleSessionExpiry(stored: StoredSession): void {
  if (sessionExpiryTimer) clearTimeout(sessionExpiryTimer)
  if (!stored.expiresAt) return
  const delay = Math.max(1_000, stored.expiresAt - Date.now())
  sessionExpiryTimer = setTimeout(async () => {
    lastError = '登录会话已过期，请重新登录。'
    await stopCompanion()
    publishStatus()
  }, delay)
}

async function activateSession(tenant: Tenant, stored: StoredSession): Promise<void> {
  await stopCompanion()
  if (!stored.deviceSecretEncrypted || isSessionExpired(stored)) throw new Error('登录会话无效，请重新登录。')
  const nativeSso = new NativeSsoService({
    endpoint: tenant.endpoint,
    preferredPort: DEFAULT_PORT,
    session: {
      accessToken: decodeProtected(stored.accessTokenEncrypted),
      deviceSecret: decodeProtected(stored.deviceSecretEncrypted),
      userName: stored.userName,
      displayName: stored.displayName,
      avatar: stored.avatar,
    },
    approve: showNativeSsoApproval,
  })
  try {
    companionPort = await nativeSso.start()
    companion = nativeSso
    companionRunning = true
    lastError = ''
    scheduleSessionExpiry(stored)
  } catch (error) {
    await nativeSso.stop().catch(() => undefined)
    throw error
  }
}

async function restoreSession(): Promise<void> {
  const [store, stored] = await Promise.all([getStore(), getStoredSession()])
  if (!stored || stored.tenantId !== store.activeTenantId || isSessionExpired(stored)) return
  try {
    await activateSession(await getActiveTenant(store), stored)
  } catch {
    lastError = '设备服务未能恢复，请重新登录。'
  }
}

async function refreshSecurityReport(): Promise<DeviceSecurityReport> {
  securityReport = await collectDeviceSecurityReport()
  publishStatus()
  return securityReport
}

function scheduleSecurityRefresh(): void {
  if (securityRefreshTimer) clearInterval(securityRefreshTimer)
  securityRefreshTimer = setInterval(() => { void refreshSecurityReport() }, 30 * 60 * 1000)
}

async function getStatus(): Promise<Status> {
  const store = await getStore()
  const tenant = listTenants(store).find((item) => item.id === store.activeTenantId)
  const stored = await getStoredSession()
  const currentSession = stored?.tenantId === store.activeTenantId ? stored : null
  return {
    configured: Boolean(tenant?.clientSecretEncrypted),
    signedIn: Boolean(currentSession && !isSessionExpired(currentSession)),
    companionRunning,
    userName: currentSession?.userName,
    displayName: currentSession?.displayName,
    devicePort: companionRunning ? companionPort ?? undefined : undefined,
    lastError: lastError || undefined,
    activeTenantId: tenant?.id,
    activeTenantName: tenant?.displayName,
    activeTenantOrgName: tenant?.orgName,
    requireWindowsHello: store.preferences.requireWindowsHello,
    securityReport,
  }
}

function publishStatus(): void {
  void getStatus().then((status) => {
    mainWindow?.webContents.send('status:changed', status)
    statusFloatWindow?.webContents.send('status:changed', status)
  })
}

function createSignInUrl(tenant: Tenant, state: string): string {
  const url = new URL('/login/oauth/authorize', tenant.endpoint)
  url.search = new URLSearchParams({
    client_id: tenant.clientId,
    response_type: 'code',
    redirect_uri: CALLBACK_URI,
    scope: 'openid profile email offline_access device_sso',
    state,
  }).toString()
  return url.toString()
}

function userFacingError(error: unknown): string {
  const message = error instanceof Error ? error.message : '操作未完成。'
  if (/token-exchange is not supported/i.test(message)) return '您尝试登录的网页应用尚未启用设备登录授权，请联系该应用管理员。'
  if (/client_secret.*cross organizations|across organizations/i.test(message)) return '您尝试登录的应用不属于当前组织，请使用其它账号。'
  if (/device_secret/i.test(message)) return '身份服务未返回设备登录凭据，请联系管理员检查服务配置。'
  if (/Native SSO|identity service/i.test(message)) return '设备登录服务未能完成本次请求，请稍后重试。'
  return message
}

function isProtocolUrl(url: string): boolean {
  return url.toLowerCase().startsWith(`${PROTOCOL}:`)
}

async function handleProtocolUrl(rawUrl: string): Promise<void> {
  const url = new URL(rawUrl)
  if (url.hostname === 'approval') { approvals.handleProtocolUrl(rawUrl); return }
  if (url.hostname === 'show') { showMainWindow(); return }
  if (url.hostname !== 'oauth') return
  // 授权窗口和 second-instance 可能同时收到同一个自定义协议回调，只允许处理一次。
  if (isDuplicateOAuthCallback(url)) return
  const code = url.searchParams.get('code')
  const state = url.searchParams.get('state')
  if (!code || !state) throw new Error('登录回调信息不完整，请返回网页后重新操作。')
  const request = consumeLoginRequest(state)
  if (!request) throw new Error('本次登录请求已失效，请返回网页后重新操作。')
  const tenant = await getTenantById(request.tenantId)
  const sdk = createIdentityClient(tenant)
  const tokens = await sdk.getAuthToken(code)
  const user = sdk.parseAndVerifyAccessToken(tokens.access_token)
  if (!user.name || !tokens.device_secret) throw new Error('身份服务未返回有效的设备登录凭据。')
  const stored: StoredSession = {
    tenantId: tenant.id,
    accessTokenEncrypted: encodeProtected(tokens.access_token),
    refreshTokenEncrypted: tokens.refresh_token ? encodeProtected(tokens.refresh_token) : undefined,
    deviceSecretEncrypted: encodeProtected(tokens.device_secret),
    userName: user.name,
    displayName: user.displayName || user.name,
    avatar: user.avatar || '',
    expiresAt: tokenExpiration(tokens.access_token),
  }
  await writeJson(SESSION_FILE, stored)
  await activateSession(tenant, stored)
  authWindow?.close()
  authWindow = null
  publishStatus()
}

function defaultStatusFloatBounds(): StatusFloatBounds {
  const workArea = screen.getPrimaryDisplay().workArea
  const width = 350
  const height = 300
  return { x: workArea.x + workArea.width - width - 20, y: workArea.y + 20, width, height }
}

async function saveStatusFloatBounds(): Promise<void> {
  if (!statusFloatWindow) return
  const bounds = statusFloatWindow.getBounds()
  await writeJson(STATUS_FLOAT_BOUNDS_FILE, bounds)
}

async function setStatusFloatVisible(visible: boolean): Promise<void> {
  if (!visible) {
    statusFloatWindow?.hide()
    return
  }
  if (!statusFloatWindow) {
    const savedBounds = await readJson<StatusFloatBounds>(STATUS_FLOAT_BOUNDS_FILE)
    const bounds = savedBounds && savedBounds.width >= 280 && savedBounds.height >= 230 ? savedBounds : defaultStatusFloatBounds()
    statusFloatWindow = new BrowserWindow({
      ...bounds,
      minWidth: 280,
      minHeight: 230,
      title: '云端验证设备认证状态',
      icon: iconPath(),
      frame: false,
      transparent: true,
      resizable: true,
      alwaysOnTop: true,
      skipTaskbar: true,
      show: false,
      backgroundColor: '#edf1f5',
      webPreferences: { preload: path.join(__dirname, '../preload/index.js'), contextIsolation: true, sandbox: true, nodeIntegration: false },
    })
    statusFloatWindow.setAlwaysOnTop(true, 'normal')
    statusFloatWindow.setVisibleOnAllWorkspaces(false)
    statusFloatWindow.on('move', () => {
      if (statusFloatBoundsSaveTimer) clearTimeout(statusFloatBoundsSaveTimer)
      statusFloatBoundsSaveTimer = setTimeout(() => { void saveStatusFloatBounds() }, 400)
    })
    statusFloatWindow.on('resize', () => {
      if (statusFloatBoundsSaveTimer) clearTimeout(statusFloatBoundsSaveTimer)
      statusFloatBoundsSaveTimer = setTimeout(() => { void saveStatusFloatBounds() }, 400)
    })
    statusFloatWindow.on('closed', () => { statusFloatWindow = null })
    await statusFloatWindow.loadFile(path.join(__dirname, '../renderer/float.html'))
  }
  statusFloatWindow.showInactive()
  void getStatus().then((status) => statusFloatWindow?.webContents.send('status:changed', status))
}

function showMainWindow(): void {
  if (!mainWindow) { createMainWindow(); return }
  if (mainWindow.isMinimized()) mainWindow.restore()
  mainWindow.show()
  mainWindow.focus()
}

function createMainWindow(): void {
  mainWindow = new BrowserWindow({
    width: 980,
    height: 740,
    minWidth: 820,
    minHeight: 640,
    title: PRODUCT_NAME,
    icon: iconPath(),
    backgroundColor: '#f7f9fc',
    show: false,
    webPreferences: { preload: path.join(__dirname, '../preload/index.js'), contextIsolation: true, sandbox: true, nodeIntegration: false },
  })
  mainWindow.webContents.setWindowOpenHandler(({ url }) => { void shell.openExternal(url); return { action: 'deny' } })
  void mainWindow.loadFile(path.join(__dirname, '../renderer/index.html'))
  mainWindow.once('ready-to-show', () => {
    if (!launchInTray) mainWindow?.show()
  })
  mainWindow.on('close', (event) => {
    if (!isQuitting) { event.preventDefault(); mainWindow?.hide() }
  })
  mainWindow.on('closed', () => { mainWindow = null })
}

function createTray(): void {
  tray = new Tray(iconPath())
  tray.setToolTip(PRODUCT_NAME)
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: '显示主窗口', click: showMainWindow },
    { type: 'separator' },
    { label: '退出', click: () => { isQuitting = true; app.quit() } },
  ]))
  tray.on('click', showMainWindow)
}

function createAuthWindow(url: string): void {
  authWindow?.close()
  authWindow = new BrowserWindow({
    width: 540,
    height: 760,
    minWidth: 440,
    minHeight: 620,
    title: '账户登录',
    icon: iconPath(),
    parent: mainWindow ?? undefined,
    modal: Boolean(mainWindow),
    webPreferences: { contextIsolation: true, sandbox: true, nodeIntegration: false },
  })
  const capture = (target: string): void => {
    if (!isProtocolUrl(target)) return
    void handleProtocolUrl(target).catch((error) => { lastError = userFacingError(error); publishStatus() })
  }
  authWindow.webContents.on('will-navigate', (event, target) => { if (isProtocolUrl(target)) { event.preventDefault(); capture(target) } })
  authWindow.webContents.on('will-redirect', (event, target) => { if (isProtocolUrl(target)) { event.preventDefault(); capture(target) } })
  authWindow.on('closed', () => { authWindow = null })
  void authWindow.loadURL(url)
}

async function beginLogin(): Promise<void> {
  const store = await getStore()
  const tenant = await getActiveTenant(store)
  if (!tenant.clientSecretEncrypted) throw new Error('当前租户尚未完成认证配置，请联系管理员完成设置。')
  const state = crypto.randomBytes(32).toString('base64url')
  rememberLoginRequest(state, tenant.id)
  const signInUrl = createSignInUrl(tenant, state)
  if (store.preferences.loginMode === 'browser') {
    await shell.openExternal(signInUrl)
    return
  }
  createAuthWindow(signInUrl)
}

function registerProtocol(): void {
  if (process.defaultApp && process.argv.length >= 2) app.setAsDefaultProtocolClient(PROTOCOL, process.execPath, [path.resolve(process.argv[1])])
  else app.setAsDefaultProtocolClient(PROTOCOL)
}

function extractProtocolUrl(argv: string[]): string | undefined {
  return argv.find((argument) => isProtocolUrl(argument))
}

async function selectTenant(tenantId: string): Promise<PublicTenant> {
  const store = await getStore()
  const next = listTenants(store).find((tenant) => tenant.id === tenantId)
  if (!next) throw new Error('所选租户不存在。')
  if (store.activeTenantId === tenantId) return toPublicTenant(next)
  const current = listTenants(store).find((tenant) => tenant.id === store.activeTenantId)
  const result = await dialog.showMessageBox({
    type: 'warning', buttons: ['切换租户', '取消'], defaultId: 1, cancelId: 1, title: '确认切换租户',
    message: `切换到“${next.displayName}”后，当前账户将退出。是否继续？`,
    detail: '为保护不同组织的身份信息，应用会停止设备服务并清除当前账户的登录信息。', noLink: true,
  })
  if (result.response !== 0) throw new Error('已取消切换租户。')
  await signOutCurrentSession()
  store.activeTenantId = tenantId
  await writeJson(TENANT_STORE_FILE, store)
  lastError = ''
  publishStatus()
  return toPublicTenant(next)
}

async function saveTenant(input: TenantInput): Promise<PublicTenant> {
  if (input.id) throw new Error('租户不支持编辑。如需变更，请删除后重新添加。')
  const store = await getStore()
  const next = validateTenantInput(input)
  const duplicate = listTenants(store).find((tenant) => tenant.displayName === next.displayName)
  if (duplicate) throw new Error('租户显示名称已存在。')
  store.customTenants.push({ ...next, source: 'custom' })
  await writeJson(TENANT_STORE_FILE, store)
  publishStatus()
  return toPublicTenant(next)
}

async function deleteTenant(tenantId: string): Promise<void> {
  const store = await getStore()
  const tenant = listTenants(store).find((item) => item.id === tenantId)
  if (!tenant) throw new Error('要删除的租户不存在。')
  if (listTenants(store).length <= 1) throw new Error('至少需要保留一个租户。')
  const result = await dialog.showMessageBox({
    type: 'warning', buttons: ['删除租户', '取消'], defaultId: 1, cancelId: 1, title: '确认删除租户',
    message: `确定删除“${tenant.displayName}”吗？`,     detail: '该租户的本机认证信息和登录状态将一并删除。', noLink: true,
  })
  if (result.response !== 0) return
  if (tenant.source === 'built-in') {
    store.deletedBuiltInTenantIds = [...new Set([...store.deletedBuiltInTenantIds, tenant.id])]
    delete store.builtInOverrides[tenant.id]
  } else store.customTenants = store.customTenants.filter((item) => item.id !== tenant.id)
  if (store.activeTenantId === tenant.id) {
    await signOutCurrentSession()
    store.activeTenantId = listTenants(store)[0]?.id ?? ''
  }
  await writeJson(TENANT_STORE_FILE, store)
  publishStatus()
}

function applyLaunchAtLogin(enabled: boolean): void {
  if (process.platform === 'win32') {
    app.setLoginItemSettings({
      openAtLogin: enabled,
      openAsHidden: true,
      args: enabled ? [START_IN_TRAY_ARGUMENT] : [],
    })
  }
}

function registerIpc(): void {
  ipcMain.handle('app:load', async () => {
    const store = await getStore()
    const active = await getActiveTenant(store)
    return { tenants: listTenants(store).map(toPublicTenant), activeTenant: toPublicTenant(active), preferences: store.preferences, helloAvailability: await getWindowsHelloAvailability(), status: await getStatus() }
  })
  ipcMain.handle('tenant:select', async (_event, tenantId: string) => selectTenant(tenantId))
  ipcMain.handle('tenant:save', async (_event, input: TenantInput) => saveTenant(input))
  ipcMain.handle('tenant:delete', async (_event, tenantId: string) => deleteTenant(tenantId))
  ipcMain.handle('preferences:save', async (_event, input: Partial<Preferences>) => {
    const store = await getStore()
    const nextHello = Boolean(input.requireWindowsHello)
    if (nextHello !== store.preferences.requireWindowsHello) await verifyWithWindowsHello('确认更改登录授权验证设置')
    store.preferences = {
      launchAtLogin: Boolean(input.launchAtLogin),
      requireWindowsHello: nextHello,
      loginMode: input.loginMode === 'browser' ? 'browser' : 'webview',
      showStatusFloat: input.showStatusFloat !== false,
    }
    applyLaunchAtLogin(store.preferences.launchAtLogin)
    await writeJson(TENANT_STORE_FILE, store)
    await setStatusFloatVisible(store.preferences.showStatusFloat)
    publishStatus()
    return store.preferences
  })
  ipcMain.handle('auth:status', getStatus)
  ipcMain.handle('app:reset-defaults', resetToDefaults)
  ipcMain.handle('security:refresh', refreshSecurityReport)
  ipcMain.handle('auth:login', beginLogin)
  ipcMain.handle('auth:logout', async () => {
    await signOutCurrentSession()
    lastError = ''
    publishStatus()
  })
}

const gotLock = app.requestSingleInstanceLock()
if (!gotLock) app.quit()
else {
  app.on('second-instance', (_event, commandLine) => {
    const callbackUrl = extractProtocolUrl(commandLine)
    if (callbackUrl) {
      // “允许/拒绝”通知只完成审批，不得干扰用户当前窗口。
      void handleProtocolUrl(callbackUrl).catch((error) => { lastError = userFacingError(error); publishStatus() })
      return
    }
    showMainWindow()
  })
  app.on('open-url', (event, url) => {
    event.preventDefault()
    void handleProtocolUrl(url).catch((error) => { lastError = userFacingError(error); publishStatus() })
  })
  void app.whenReady().then(async () => {
    app.setName(PRODUCT_NAME)
    app.setAppUserModelId(APP_USER_MODEL_ID)
    // 客户交付版不显示 Electron 默认的 File、Edit 等顶部菜单。
    Menu.setApplicationMenu(null)
    const loginItemSettings = app.getLoginItemSettings()
    launchInTray = launchInTray || Boolean(loginItemSettings.wasOpenedAtLogin)
    registerProtocol()
    registerIpc()
    const initialStore = await getStore()
    applyLaunchAtLogin(initialStore.preferences.launchAtLogin)
    const signedOutAfterBoot = await signOutOnNewBoot()
    const bootStore = await getStore()
    // 新启动周期使用内置登录窗口时，主界面必须保持隐藏，不能在认证窗口前闪现。
    if (signedOutAfterBoot && bootStore.preferences.loginMode === 'webview') launchInTray = true
    createTray()
    createMainWindow()
    await setStatusFloatVisible(bootStore.preferences.showStatusFloat)
    scheduleSecurityRefresh()
    void refreshSecurityReport()
    if (!signedOutAfterBoot) await restoreSession()
    if (signedOutAfterBoot && bootStore.preferences.loginMode === 'webview') {
      void beginLogin().catch((error) => { lastError = userFacingError(error); publishStatus() })
    }
    publishStatus()
    const startupCallback = extractProtocolUrl(process.argv)
    if (startupCallback) await handleProtocolUrl(startupCallback)
    app.on('activate', showMainWindow)
  })
  app.on('window-all-closed', () => undefined)
  app.on('before-quit', () => {
    isQuitting = true
    if (securityRefreshTimer) clearInterval(securityRefreshTimer)
    void stopCompanion()
  })
}
