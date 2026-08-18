import { app, BrowserWindow, dialog, ipcMain, Menu, safeStorage, screen, session as electronSession, shell, Tray } from 'electron'
import * as crypto from 'node:crypto'
import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import { collectDeviceSecurityReport, type DeviceSecurityReport } from './device-security'
import { IdentityClient } from './identity-client'
import { NativeSsoService } from './native-sso'
import { BUILT_IN_TENANTS, type TenantPreset } from './tenant-presets'
import { ToastApprovalManager } from './toast-approval'
import { getWindowsHelloAvailability, verifyWithWindowsHello } from './windows-hello'
import { attachWindowToDesktop } from './windows-desktop-layer'

const PRODUCT_NAME = '云端验证设备认证服务'
// 保持既有回调协议，避免要求管理员在身份服务端重新登记回调地址。
const PROTOCOL = 'cloud-verify-device-login'
const CALLBACK_URI = `${PROTOCOL}://oauth/callback`
const DEFAULT_PORT = 47321
const APP_USER_MODEL_ID = 'com.devhjz.cloudverify.device-auth'
const START_IN_TRAY_ARGUMENT = '--start-in-tray'
const TENANT_STORE_FILE = 'tenants.json'
const SESSION_FILE = 'session.json'
const STATUS_FLOAT_BOUNDS_FILE = 'status-float-bounds.json'
const SECURITY_REFRESH_INTERVAL = 30 * 60 * 1000
const STATUS_FLOAT_DEFAULT_WIDTH = 200
const STATUS_FLOAT_DEFAULT_HEIGHT = 210
const STATUS_FLOAT_ASPECT_RATIO = STATUS_FLOAT_DEFAULT_WIDTH / STATUS_FLOAT_DEFAULT_HEIGHT
const STATUS_FLOAT_MIN_HEIGHT = 180
const STATUS_FLOAT_MIN_WIDTH = Math.ceil(STATUS_FLOAT_MIN_HEIGHT * STATUS_FLOAT_ASPECT_RATIO)
const STATUS_FLOAT_MAX_WIDTH = 720

type LoginMode = 'webview' | 'browser'
type StatusFloatBounds = { x: number; y: number; width: number; height: number }
type StatusFloatSizeSource = 'width' | 'height'
type Tenant = TenantPreset & { createdAt: string; updatedAt: string; source: 'built-in' | 'custom' }
type TenantInput = { displayName?: string; endpoint?: string; clientId?: string; orgName?: string; appName?: string; certificate?: string; allowedOrigins?: unknown; deviceName?: string }
type Preferences = { launchAtLogin: boolean; requireWindowsHello: boolean; loginMode: LoginMode; showStatusFloat: boolean; floatWidth: number; floatHeight: number; floatOpacity: number; lockStatusFloat: boolean }
type PreferenceInput = Partial<Preferences> & { floatSizeSource?: StatusFloatSizeSource }
type TenantStore = { activeTenantId: string; customTenants: Tenant[]; deletedBuiltInTenantIds: string[]; preferences: Preferences }
type StoredSession = { tenantId: string; accessTokenEncrypted: string; refreshTokenEncrypted?: string; deviceSecretEncrypted?: string; userName: string; displayName: string; email?: string; emailLookupAttempted?: boolean; avatar: string; expiresAt?: number; bootMarker: string }
type PendingLoginRequest = { tenantId: string; codeVerifier: string; timeout: NodeJS.Timeout }
type Status = {
  configured: boolean; signedIn: boolean; companionRunning: boolean; userName?: string; displayName?: string; email?: string; devicePort?: number
  lastError?: string; activeTenantId?: string; activeTenantName?: string; activeTenantOrgName?: string
  requireWindowsHello: boolean; loginMode: LoginMode; floatOpacity: number; securityReport?: DeviceSecurityReport
}

let mainWindow: BrowserWindow | null = null
let authWindow: BrowserWindow | null = null
let statusFloatWindow: BrowserWindow | null = null
let tray: Tray | null = null
let companion: NativeSsoService | null = null
let companionPort: number | null = null
let sessionExpiryTimer: NodeJS.Timeout | null = null
let securityRefreshTimer: NodeJS.Timeout | null = null
let networkChangeWatchTimer: NodeJS.Timeout | null = null
let networkChangeRefreshTimer: NodeJS.Timeout | null = null
let statusFloatBoundsSaveTimer: NodeJS.Timeout | null = null
let securityReport: DeviceSecurityReport | undefined
const pendingLoginRequests = new Map<string, PendingLoginRequest>()
const recentOAuthCallbacks = new Map<string, NodeJS.Timeout>()
let companionRunning = false
let lastError = ''
let isQuitting = false
let launchInTray = process.argv.includes(START_IN_TRAY_ARGUMENT)
const approvals = new ToastApprovalManager(APP_USER_MODEL_ID)

function appDataPath(fileName: string): string { return path.join(app.getPath('userData'), fileName) }
function iconPath(): string { return app.isPackaged ? path.join(process.resourcesPath, 'app.ico') : path.join(__dirname, '../assets/app.ico') }
function currentBootMarker(): string { return String(Math.floor(Date.now() / 1000 - os.uptime())) }
function encodeProtected(value: string): string {
  if (!safeStorage.isEncryptionAvailable()) throw new Error('Windows 数据保护服务不可用，无法安全保存敏感信息。')
  return safeStorage.encryptString(value).toString('base64')
}
function decodeProtected(value: string): string { return safeStorage.decryptString(Buffer.from(value, 'base64')) }
async function readJson<T>(fileName: string): Promise<T | null> {
  try { return JSON.parse(await fs.readFile(appDataPath(fileName), 'utf8')) as T }
  catch (error: unknown) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null; throw new Error('无法读取本机配置。') }
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
function statusFloatHeightForWidth(width: number): number { return Math.round(width / STATUS_FLOAT_ASPECT_RATIO) }
function statusFloatWidthForHeight(height: number): number { return Math.round(height * STATUS_FLOAT_ASPECT_RATIO) }
function normalizeStatusFloatWidth(value: unknown): number {
  const numeric = typeof value === 'number' ? value : Number(value)
  if (!Number.isFinite(numeric)) return STATUS_FLOAT_DEFAULT_WIDTH
  return Math.min(STATUS_FLOAT_MAX_WIDTH, Math.max(STATUS_FLOAT_MIN_WIDTH, Math.round(numeric)))
}
function statusFloatSizeFromPreferences(preferences: Pick<Preferences, 'floatWidth'>): Pick<StatusFloatBounds, 'width' | 'height'> {
  const width = normalizeStatusFloatWidth(preferences.floatWidth)
  return { width, height: statusFloatHeightForWidth(width) }
}
function normalizeStatusFloatOpacity(value: unknown): number {
  const numeric = typeof value === 'number' ? value : Number(value)
  if (!Number.isFinite(numeric)) return 88
  return Math.min(100, Math.max(35, Math.round(numeric)))
}
function defaultPreferences(): Preferences { return { launchAtLogin: false, requireWindowsHello: false, loginMode: 'webview', showStatusFloat: true, floatWidth: STATUS_FLOAT_DEFAULT_WIDTH, floatHeight: STATUS_FLOAT_DEFAULT_HEIGHT, floatOpacity: 88, lockStatusFloat: false } }
function defaultStore(): TenantStore { return { activeTenantId: BUILT_IN_TENANTS[0].id, customTenants: [], deletedBuiltInTenantIds: [], preferences: defaultPreferences() } }
function cleanTenant(raw: unknown): Tenant | null {
  if (!raw || typeof raw !== 'object') return null
  const item = raw as Partial<Tenant>
  if (!item.id || !item.displayName || !item.endpoint || !item.clientId || !item.orgName || !item.appName || !item.certificate) return null
  return {
    id: String(item.id), displayName: String(item.displayName), endpoint: String(item.endpoint), clientId: String(item.clientId),
    orgName: String(item.orgName), appName: String(item.appName), certificate: String(item.certificate),
    allowedOrigins: Array.isArray(item.allowedOrigins) ? item.allowedOrigins.filter((origin): origin is string => typeof origin === 'string') : [],
    deviceName: String(item.deviceName || ''), createdAt: String(item.createdAt || new Date().toISOString()),
    updatedAt: String(item.updatedAt || new Date().toISOString()), source: 'custom',
  }
}
async function getStore(): Promise<TenantStore> {
  const stored = await readJson<Record<string, unknown>>(TENANT_STORE_FILE)
  if (!stored) return defaultStore()
  const rawPreferences = stored.preferences && typeof stored.preferences === 'object' ? stored.preferences as Partial<Preferences> : {}
  const store: TenantStore = {
    activeTenantId: typeof stored.activeTenantId === 'string' ? stored.activeTenantId : BUILT_IN_TENANTS[0].id,
    customTenants: Array.isArray(stored.customTenants) ? stored.customTenants.map(cleanTenant).filter((tenant): tenant is Tenant => Boolean(tenant)) : [],
    deletedBuiltInTenantIds: Array.isArray(stored.deletedBuiltInTenantIds) ? stored.deletedBuiltInTenantIds.filter((id): id is string => typeof id === 'string') : [],
    preferences: {
      launchAtLogin: Boolean(rawPreferences.launchAtLogin), requireWindowsHello: Boolean(rawPreferences.requireWindowsHello),
      loginMode: rawPreferences.loginMode === 'browser' ? 'browser' : 'webview', showStatusFloat: rawPreferences.showStatusFloat !== false,
      floatWidth: normalizeStatusFloatWidth(rawPreferences.floatWidth), floatHeight: statusFloatHeightForWidth(normalizeStatusFloatWidth(rawPreferences.floatWidth)), floatOpacity: normalizeStatusFloatOpacity(rawPreferences.floatOpacity), lockStatusFloat: Boolean(rawPreferences.lockStatusFloat),
    },
  }
  // 3.0 不再支持编辑内置租户，也不保留历史共享密钥字段。
  if ('builtInOverrides' in stored || JSON.stringify(stored).includes('clientSecretEncrypted')) await writeJson(TENANT_STORE_FILE, store)
  return store
}
function listTenants(store: TenantStore): Tenant[] {
  return [
    ...BUILT_IN_TENANTS.filter((preset) => !store.deletedBuiltInTenantIds.includes(preset.id)).map((preset) => defaultTenant(preset.id)),
    ...store.customTenants,
  ]
}
async function getActiveTenant(store?: TenantStore): Promise<Tenant> {
  const currentStore = store ?? await getStore()
  const tenant = listTenants(currentStore).find((item) => item.id === currentStore.activeTenantId)
  if (!tenant) throw new Error('请先添加并选择一个租户。')
  return tenant
}
async function getTenantById(tenantId: string): Promise<Tenant> {
  const tenant = listTenants(await getStore()).find((item) => item.id === tenantId)
  if (!tenant) throw new Error('登录请求对应的租户已不存在，请重新发起登录。')
  return tenant
}
function rememberLoginRequest(state: string, tenantId: string, codeVerifier: string): void {
  const previous = pendingLoginRequests.get(state)
  if (previous) clearTimeout(previous.timeout)
  pendingLoginRequests.set(state, { tenantId, codeVerifier, timeout: setTimeout(() => pendingLoginRequests.delete(state), 10 * 60 * 1000) })
}
function consumeLoginRequest(state: string): PendingLoginRequest | null {
  const request = pendingLoginRequests.get(state)
  if (!request) return null
  clearTimeout(request.timeout)
  pendingLoginRequests.delete(state)
  return request
}
function isDuplicateOAuthCallback(url: URL): boolean {
  const key = [url.searchParams.get('state') || '', url.searchParams.get('code') || '', url.searchParams.get('error') || ''].join('|')
  if (recentOAuthCallbacks.has(key)) return true
  recentOAuthCallbacks.set(key, setTimeout(() => recentOAuthCallbacks.delete(key), 15_000))
  return false
}
function validateNewTenant(input: TenantInput): Tenant {
  const displayName = String(input.displayName || '').trim()
  const endpoint = normalizeEndpoint(String(input.endpoint || ''))
  const clientId = String(input.clientId || '').trim()
  const orgName = String(input.orgName || '').trim()
  const appName = String(input.appName || '').trim()
  const certificate = String(input.certificate || '').trim()
  if (!displayName || !clientId || !orgName || !appName || !certificate.includes('BEGIN CERTIFICATE')) throw new Error('请填写租户名称、客户端 ID、组织、应用名称和有效证书。')
  const timestamp = new Date().toISOString()
  return { id: crypto.randomUUID(), displayName, endpoint, clientId, orgName, appName, certificate, allowedOrigins: parseAllowedOrigins(input.allowedOrigins), deviceName: String(input.deviceName || '').trim(), createdAt: timestamp, updatedAt: timestamp, source: 'custom' }
}
function createIdentityClient(tenant: Tenant): IdentityClient { return new IdentityClient({ endpoint: tenant.endpoint, clientId: tenant.clientId, certificate: tenant.certificate }) }
function tokenExpiration(token: string): number | undefined {
  try { const [, payload] = token.split('.'); if (!payload) return undefined; const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as { exp?: number }; return typeof data.exp === 'number' ? data.exp * 1000 : undefined } catch { return undefined }
}
function isSessionExpired(stored: StoredSession): boolean { return Boolean(stored.expiresAt && stored.expiresAt <= Date.now()) }
async function getStoredSession(): Promise<StoredSession | null> { return readJson<StoredSession>(SESSION_FILE) }
async function clearStoredSession(): Promise<void> { await fs.rm(appDataPath(SESSION_FILE), { force: true }) }
async function clearIdentityCookies(): Promise<void> { await electronSession.defaultSession.clearStorageData({ storages: ['cookies'] }) }
async function requestServerLogout(stored: StoredSession | null, tenant: Tenant | null): Promise<void> {
  if (!stored || !tenant) return
  try {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 8_000)
    try {
      await electronSession.defaultSession.fetch(new URL('/api/logout', tenant.endpoint).toString(), {
        method: 'POST', headers: { Authorization: `Bearer ${decodeProtected(stored.accessTokenEncrypted)}`, 'Content-Type': 'application/json' }, body: '{}', signal: controller.signal,
      })
    } finally { clearTimeout(timer) }
  } catch { /* 无网络时仍执行本机注销，防止下次恢复旧账号。 */ }
}
async function stopCompanion(): Promise<void> {
  if (sessionExpiryTimer) { clearTimeout(sessionExpiryTimer); sessionExpiryTimer = null }
  approvals.cancelAll()
  if (companion) { await companion.stop(); companion = null }
  companionPort = null; companionRunning = false
}
async function standardLogout(options: { clearCookies?: boolean; hideAuthWindow?: boolean } = {}): Promise<void> {
  const stored = await getStoredSession()
  let tenant: Tenant | null = null
  if (stored) { try { tenant = await getTenantById(stored.tenantId) } catch { tenant = null } }
  await stopCompanion()
  await requestServerLogout(stored, tenant)
  await clearStoredSession()
  if (options.clearCookies !== false) await clearIdentityCookies()
  if (options.hideAuthWindow !== false && authWindow) { authWindow.close(); authWindow = null }
}
async function showNativeSsoApproval(input: { applicationName?: string; userName: string; displayName?: string }): Promise<boolean> {
  const store = await getStore()
  const allowed = await approvals.request({ applicationName: input.applicationName || '受信任网页', userName: input.userName, displayName: input.displayName || input.userName })
  if (!allowed) return false
  if (store.preferences.requireWindowsHello) await verifyWithWindowsHello(`您正在请求登录${input.applicationName || '该'}应用，\n请使用您的凭据授权该应用访问您的账号。`)
  return true
}
function scheduleSessionExpiry(stored: StoredSession): void {
  if (sessionExpiryTimer) clearTimeout(sessionExpiryTimer)
  if (!stored.expiresAt) return
  sessionExpiryTimer = setTimeout(async () => { lastError = '登录会话已过期，请重新登录。'; await stopCompanion(); publishStatus() }, Math.max(1_000, stored.expiresAt - Date.now()))
}
async function activateSession(tenant: Tenant, stored: StoredSession): Promise<void> {
  await stopCompanion()
  if (!stored.deviceSecretEncrypted || isSessionExpired(stored)) throw new Error('登录会话无效，请重新登录。')
  const nativeSso = new NativeSsoService({
    endpoint: tenant.endpoint, preferredPort: DEFAULT_PORT,
    session: { accessToken: decodeProtected(stored.accessTokenEncrypted), deviceSecret: decodeProtected(stored.deviceSecretEncrypted), userName: stored.userName, displayName: stored.displayName, avatar: stored.avatar },
    approve: showNativeSsoApproval,
  })
  try { companionPort = await nativeSso.start(); companion = nativeSso; companionRunning = true; lastError = ''; scheduleSessionExpiry(stored) }
  catch (error) { await nativeSso.stop().catch(() => undefined); throw error }
}
async function invalidateSessionAfterSystemRestart(): Promise<boolean> {
  const stored = await getStoredSession()
  if (!stored || stored.bootMarker === currentBootMarker()) return false
  await standardLogout()
  lastError = '检测到系统重新启动，已按安全策略退出上次登录账户。'
  return true
}
async function restoreSession(): Promise<void> {
  const [store, stored] = await Promise.all([getStore(), getStoredSession()])
  if (!stored || stored.tenantId !== store.activeTenantId || isSessionExpired(stored)) return
  try { await activateSession(await getActiveTenant(store), stored) } catch { lastError = '设备服务未能恢复，请重新登录。' }
}
async function hydrateSessionEmail(stored: StoredSession, tenant: Tenant): Promise<StoredSession> {
  if (stored.email || stored.emailLookupAttempted) return stored
  stored.emailLookupAttempted = true
  try {
    const profile = await createIdentityClient(tenant).getUserInfo(decodeProtected(stored.accessTokenEncrypted))
    if (profile.email) {
      stored.email = profile.email
      if (profile.displayName || profile.preferred_username) stored.displayName = profile.displayName || profile.preferred_username || stored.displayName
    }
  } catch { /* 账户资料接口暂不可用时保留原会话；悬浮窗会给出明确提示。 */ }
  await writeJson(SESSION_FILE, stored)
  return stored
}
async function refreshSecurityReport(): Promise<DeviceSecurityReport> { securityReport = await collectDeviceSecurityReport(); publishStatus(); return securityReport }
function scheduleSecurityRefresh(): void { if (securityRefreshTimer) clearInterval(securityRefreshTimer); securityRefreshTimer = setInterval(() => { void refreshSecurityReport() }, SECURITY_REFRESH_INTERVAL) }
function currentNetworkFingerprint(): string {
  return Object.entries(os.networkInterfaces()).flatMap(([name, addresses]) => (addresses ?? [])
    .filter((address) => address.family === 'IPv4' && !address.internal)
    .map((address) => `${name}:${address.address}:${address.netmask}`)).sort().join('|')
}
function scheduleNetworkChangeRefresh(): void {
  if (networkChangeWatchTimer) clearInterval(networkChangeWatchTimer)
  let previousFingerprint = currentNetworkFingerprint()
  networkChangeWatchTimer = setInterval(() => {
    const nextFingerprint = currentNetworkFingerprint()
    if (nextFingerprint === previousFingerprint) return
    previousFingerprint = nextFingerprint
    if (networkChangeRefreshTimer) clearTimeout(networkChangeRefreshTimer)
    // 等待 DHCP、VPN 或 Wi-Fi 切换完成后再读取 PowerShell 网络接口，避免采集到中间状态。
    networkChangeRefreshTimer = setTimeout(() => { void refreshSecurityReport() }, 1_000)
  }, 2_000)
}
async function getStatus(): Promise<Status> {
  const store = await getStore(); const tenant = listTenants(store).find((item) => item.id === store.activeTenantId); const stored = await getStoredSession(); let currentSession = stored?.tenantId === store.activeTenantId ? stored : null
  if (currentSession && tenant && !isSessionExpired(currentSession)) currentSession = await hydrateSessionEmail(currentSession, tenant)
  return {
    configured: Boolean(tenant?.clientId && tenant?.certificate), signedIn: Boolean(currentSession && !isSessionExpired(currentSession)), companionRunning,
    userName: currentSession?.userName, displayName: currentSession?.displayName, email: currentSession?.email, devicePort: companionRunning ? companionPort ?? undefined : undefined,
    lastError: lastError || undefined, activeTenantId: tenant?.id, activeTenantName: tenant?.displayName, activeTenantOrgName: tenant?.orgName,
    requireWindowsHello: store.preferences.requireWindowsHello, loginMode: store.preferences.loginMode, floatOpacity: store.preferences.floatOpacity, securityReport,
  }
}
function publishStatus(): void { void getStatus().then((status) => { mainWindow?.webContents.send('status:changed', status); statusFloatWindow?.webContents.send('status:changed', status) }) }
function createPkceVerifier(): string { return crypto.randomBytes(48).toString('base64url') }
function createPkceChallenge(verifier: string): string { return crypto.createHash('sha256').update(verifier).digest('base64url') }
function createSignInUrl(tenant: Tenant, state: string, codeVerifier: string): string {
  const url = new URL('/login/oauth/authorize', tenant.endpoint)
  url.search = new URLSearchParams({ client_id: tenant.clientId, response_type: 'code', redirect_uri: CALLBACK_URI, scope: 'openid profile email offline_access device_sso', state, code_challenge: createPkceChallenge(codeVerifier), code_challenge_method: 'S256' }).toString()
  return url.toString()
}
function userFacingError(error: unknown): string {
  const message = error instanceof Error ? error.message : '操作未完成。'
  if (/token-exchange is not supported/i.test(message)) return '您尝试登录的网页应用尚未启用设备登录授权，请联系该应用管理员。'
  if (/client_secret.*cross organizations|across organizations/i.test(message)) return '当前网页应用与已选租户不属于同一组织，请切换到对应租户后重试。'
  if (/device_secret/i.test(message)) return '身份服务未返回设备登录凭据，请联系管理员检查服务配置。'
  if (/Native SSO|identity service/i.test(message)) return '设备登录服务未能完成本次请求，请稍后重试。'
  return message
}
function isProtocolUrl(url: string): boolean { return url.toLowerCase().startsWith(`${PROTOCOL}:`) }
async function handleProtocolUrl(rawUrl: string): Promise<void> {
  const url = new URL(rawUrl)
  if (url.hostname === 'approval') { approvals.handleProtocolUrl(rawUrl); return }
  if (url.hostname === 'show') { showMainWindow(); return }
  if (url.hostname !== 'oauth' || isDuplicateOAuthCallback(url)) return
  const code = url.searchParams.get('code'); const state = url.searchParams.get('state')
  if (!code || !state) throw new Error('登录回调信息不完整，请返回网页后重新操作。')
  const request = consumeLoginRequest(state)
  if (!request) throw new Error('本次登录请求已失效，请返回网页后重新操作。')
  const tenant = await getTenantById(request.tenantId); const sdk = createIdentityClient(tenant); const tokens = await sdk.getAuthToken(code, request.codeVerifier); const user = sdk.parseAndVerifyAccessToken(tokens.access_token)
  if (!user.name || !tokens.device_secret) throw new Error('身份服务未返回有效的设备登录凭据。')
  const profile = user.email ? user : await sdk.getUserInfo(tokens.access_token).catch(() => user)
  const stored: StoredSession = {
    tenantId: tenant.id, accessTokenEncrypted: encodeProtected(tokens.access_token), refreshTokenEncrypted: tokens.refresh_token ? encodeProtected(tokens.refresh_token) : undefined,
    deviceSecretEncrypted: encodeProtected(tokens.device_secret), userName: user.name, displayName: profile.displayName || profile.preferred_username || user.displayName || user.name, email: profile.email || user.email || '', avatar: profile.avatar || user.avatar || '', expiresAt: tokenExpiration(tokens.access_token), bootMarker: currentBootMarker(),
  }
  await writeJson(SESSION_FILE, stored); await activateSession(tenant, stored)
  if (authWindow) { authWindow.close(); authWindow = null }
  publishStatus()
}
function showMainWindow(): void { if (!mainWindow) { createMainWindow(); return }; if (mainWindow.isMinimized()) mainWindow.restore(); mainWindow.show(); mainWindow.focus() }
function createMainWindow(): void {
  if (mainWindow) return
  mainWindow = new BrowserWindow({ width: 980, height: 790, minWidth: 820, minHeight: 660, title: PRODUCT_NAME, icon: iconPath(), backgroundColor: '#f7f9fc', show: false, webPreferences: { preload: path.join(__dirname, '../preload/index.js'), contextIsolation: true, sandbox: true, nodeIntegration: false } })
  mainWindow.webContents.setWindowOpenHandler(({ url }) => { void shell.openExternal(url); return { action: 'deny' } })
  void mainWindow.loadFile(path.join(__dirname, '../renderer/index.html'))
  mainWindow.once('ready-to-show', () => { if (!launchInTray) mainWindow?.show() })
  mainWindow.on('close', (event) => { if (!isQuitting) { event.preventDefault(); mainWindow?.hide() } })
  mainWindow.on('closed', () => { mainWindow = null })
}
function createAuthWindow(url: string): void {
  authWindow?.close()
  authWindow = new BrowserWindow({ width: 540, height: 760, minWidth: 440, minHeight: 620, title: '账户登录', icon: iconPath(), backgroundColor: '#ffffff', parent: mainWindow ?? undefined, modal: Boolean(mainWindow?.isVisible()), show: true, webPreferences: { contextIsolation: true, sandbox: true, nodeIntegration: false } })
  const capture = (target: string): void => { if (isProtocolUrl(target)) void handleProtocolUrl(target).catch((error) => { lastError = userFacingError(error); publishStatus() }) }
  authWindow.webContents.on('will-navigate', (event, target) => { if (isProtocolUrl(target)) { event.preventDefault(); capture(target) } })
  authWindow.webContents.on('will-redirect', (event, target) => { if (isProtocolUrl(target)) { event.preventDefault(); capture(target) } })
  authWindow.on('closed', () => { authWindow = null })
  void authWindow.loadURL(url)
}
async function startLogin(): Promise<void> {
  const [store, tenant] = await Promise.all([getStore(), getActiveTenant()])
  const state = crypto.randomBytes(32).toString('base64url'); const codeVerifier = createPkceVerifier(); rememberLoginRequest(state, tenant.id, codeVerifier)
  const url = createSignInUrl(tenant, state, codeVerifier)
  if (store.preferences.loginMode === 'browser') await shell.openExternal(url); else createAuthWindow(url)
}
function defaultStatusFloatBounds(preferences?: Preferences): StatusFloatBounds { const area = screen.getPrimaryDisplay().workArea; const size = statusFloatSizeFromPreferences(preferences ?? defaultPreferences()); return { ...size, x: area.x + area.width - size.width - 24, y: area.y + 24 } }
function isVisibleBounds(bounds: StatusFloatBounds): boolean { return screen.getAllDisplays().some((display) => { const area = display.workArea; return bounds.x + 100 < area.x + area.width && bounds.x + bounds.width > area.x && bounds.y + 100 < area.y + area.height && bounds.y + bounds.height > area.y }) }
function applyStatusFloatPreferences(window: BrowserWindow, preferences: Preferences): void {
  const size = statusFloatSizeFromPreferences(preferences)
  window.setMinimumSize(STATUS_FLOAT_MIN_WIDTH, STATUS_FLOAT_MIN_HEIGHT)
  window.setAspectRatio(STATUS_FLOAT_ASPECT_RATIO)
  if (window.getBounds().width !== size.width || window.getBounds().height !== size.height) window.setSize(size.width, size.height)
  window.setMovable(!preferences.lockStatusFloat)
  window.setResizable(!preferences.lockStatusFloat)
}
async function saveStatusFloatBounds(): Promise<void> {
  if (!statusFloatWindow) return
  const bounds = statusFloatWindow.getBounds()
  await writeJson(STATUS_FLOAT_BOUNDS_FILE, bounds)
  const store = await getStore()
  if (!store.preferences.lockStatusFloat && (store.preferences.floatWidth !== bounds.width || store.preferences.floatHeight !== bounds.height)) {
    store.preferences.floatWidth = normalizeStatusFloatWidth(bounds.width)
    store.preferences.floatHeight = statusFloatHeightForWidth(store.preferences.floatWidth)
    await writeJson(TENANT_STORE_FILE, store)
  }
}
function reassertStatusFloatDesktopLayer(): void {
  const floatWindow = statusFloatWindow
  if (!floatWindow || floatWindow.isDestroyed()) return
  floatWindow.setAlwaysOnTop(false)
  void attachWindowToDesktop(floatWindow).then(() => { if (!floatWindow.isDestroyed()) floatWindow.setAlwaysOnTop(false) })
}
async function setStatusFloatVisible(visible: boolean): Promise<void> {
  if (!visible) { statusFloatWindow?.hide(); return }
  const store = await getStore()
  if (!statusFloatWindow) {
    const saved = await readJson<StatusFloatBounds>(STATUS_FLOAT_BOUNDS_FILE); const position = saved && isVisibleBounds(saved) ? saved : defaultStatusFloatBounds(store.preferences); const size = statusFloatSizeFromPreferences(store.preferences); const bounds = { x: position.x, y: position.y, ...size }
    statusFloatWindow = new BrowserWindow({ ...bounds, minWidth: STATUS_FLOAT_MIN_WIDTH, minHeight: STATUS_FLOAT_MIN_HEIGHT, frame: false, transparent: true, backgroundColor: '#00000000', resizable: !store.preferences.lockStatusFloat, movable: !store.preferences.lockStatusFloat, alwaysOnTop: false, skipTaskbar: true, title: '云端验证设备认证状态', icon: iconPath(), show: false, webPreferences: { preload: path.join(__dirname, '../preload/index.js'), contextIsolation: true, sandbox: true, nodeIntegration: false } })
    statusFloatWindow.setAspectRatio(STATUS_FLOAT_ASPECT_RATIO)
    await attachWindowToDesktop(statusFloatWindow)
    statusFloatWindow.setAlwaysOnTop(false)
    statusFloatWindow.setVisibleOnAllWorkspaces(false)
    const persist = (): void => { if (statusFloatBoundsSaveTimer) clearTimeout(statusFloatBoundsSaveTimer); statusFloatBoundsSaveTimer = setTimeout(() => { void saveStatusFloatBounds() }, 400) }
    statusFloatWindow.on('move', persist); statusFloatWindow.on('resize', persist)
    statusFloatWindow.on('closed', () => { statusFloatWindow = null })
    await statusFloatWindow.loadFile(path.join(__dirname, '../renderer/float.html'))
  }
  applyStatusFloatPreferences(statusFloatWindow, store.preferences)
  statusFloatWindow.showInactive(); void getStatus().then((status) => statusFloatWindow?.webContents.send('status:changed', status))
}
function createTray(): void {
  tray = new Tray(iconPath()); tray.setToolTip(PRODUCT_NAME)
  tray.setContextMenu(Menu.buildFromTemplate([{ label: '显示主窗口', click: showMainWindow }, { type: 'separator' }, { label: '退出', click: () => { isQuitting = true; app.quit() } }]))
  tray.on('click', showMainWindow)
}
function registerProtocol(): void { if (process.defaultApp && process.argv.length >= 2) app.setAsDefaultProtocolClient(PROTOCOL, process.execPath, [path.resolve(process.argv[1])]); else app.setAsDefaultProtocolClient(PROTOCOL) }
function extractProtocolUrl(argv: string[]): string | undefined { return argv.find((argument) => isProtocolUrl(argument)) }
async function selectTenant(tenantId: string): Promise<Tenant> {
  const store = await getStore(); const next = listTenants(store).find((tenant) => tenant.id === tenantId)
  if (!next) throw new Error('所选租户不存在。'); if (store.activeTenantId === tenantId) return next
  const result = await dialog.showMessageBox({ type: 'warning', buttons: ['切换租户', '取消'], defaultId: 1, cancelId: 1, title: '确认切换租户', message: `切换到“${next.displayName}”后，当前账户将退出。是否继续？`, detail: '为保护不同组织的身份信息，应用会停止设备服务并清除当前账户的登录信息。', noLink: true })
  if (result.response !== 0) throw new Error('已取消切换租户。')
  await standardLogout(); store.activeTenantId = tenantId; await writeJson(TENANT_STORE_FILE, store); lastError = ''; publishStatus(); return next
}
async function addTenant(input: TenantInput): Promise<Tenant> {
  const store = await getStore(); const next = validateNewTenant(input)
  if (listTenants(store).some((tenant) => tenant.displayName === next.displayName)) throw new Error('租户显示名称已存在。')
  store.customTenants.push(next); await writeJson(TENANT_STORE_FILE, store); publishStatus(); return next
}
async function deleteTenant(tenantId: string): Promise<void> {
  const store = await getStore(); const tenant = listTenants(store).find((item) => item.id === tenantId)
  if (!tenant) throw new Error('要删除的租户不存在。'); if (listTenants(store).length <= 1) throw new Error('至少需要保留一个租户。')
  const result = await dialog.showMessageBox({ type: 'warning', buttons: ['删除租户', '取消'], defaultId: 1, cancelId: 1, title: '确认删除租户', message: `确定删除“${tenant.displayName}”吗？`, detail: '该租户的本机登录状态将一并删除。', noLink: true })
  if (result.response !== 0) return
  if (tenant.source === 'built-in') store.deletedBuiltInTenantIds = [...new Set([...store.deletedBuiltInTenantIds, tenant.id])]; else store.customTenants = store.customTenants.filter((item) => item.id !== tenant.id)
  if (store.activeTenantId === tenant.id) { await standardLogout(); store.activeTenantId = listTenants(store)[0]?.id ?? '' }
  await writeJson(TENANT_STORE_FILE, store); publishStatus()
}
function applyLaunchAtLogin(enabled: boolean): void { if (process.platform === 'win32') app.setLoginItemSettings({ openAtLogin: enabled, openAsHidden: true, args: enabled ? [START_IN_TRAY_ARGUMENT] : [] }) }
async function resetToDefaults(): Promise<void> {
  const result = await dialog.showMessageBox({ type: 'warning', buttons: ['重置', '取消'], defaultId: 1, cancelId: 1, title: '重置为默认状态', message: '确定重置本应用的本机状态吗？', detail: '将退出当前账户、清除本机登录信息和自定义租户，并恢复默认登录方式、系统设置及悬浮窗位置。', noLink: true })
  if (result.response !== 0) throw new Error('已取消重置。')
  authWindow?.close(); authWindow = null
  await standardLogout()
  applyLaunchAtLogin(false)
  await Promise.all([fs.rm(appDataPath(TENANT_STORE_FILE), { force: true }), fs.rm(appDataPath(STATUS_FLOAT_BOUNDS_FILE), { force: true })])
  securityReport = undefined
  statusFloatWindow?.destroy(); statusFloatWindow = null
  await setStatusFloatVisible(true)
  lastError = ''
  publishStatus()
}
function registerIpc(): void {
  ipcMain.handle('app:load', async () => { const store = await getStore(); return { tenants: listTenants(store), activeTenant: await getActiveTenant(store), preferences: store.preferences, helloAvailability: await getWindowsHelloAvailability(), status: await getStatus() } })
  ipcMain.handle('tenant:select', async (_event, tenantId: string) => selectTenant(tenantId))
  ipcMain.handle('tenant:add', async (_event, input: TenantInput) => addTenant(input))
  ipcMain.handle('tenant:delete', async (_event, tenantId: string) => deleteTenant(tenantId))
  ipcMain.handle('preferences:save', async (_event, input: PreferenceInput) => {
    const store = await getStore(); const nextHello = input.requireWindowsHello === undefined ? store.preferences.requireWindowsHello : Boolean(input.requireWindowsHello)
    if (nextHello !== store.preferences.requireWindowsHello) await verifyWithWindowsHello('确认更改登录授权验证设置')
    const requestedWidth = input.floatSizeSource === 'height' ? statusFloatWidthForHeight(Number(input.floatHeight)) : input.floatWidth === undefined ? store.preferences.floatWidth : Number(input.floatWidth)
    const floatWidth = normalizeStatusFloatWidth(requestedWidth)
    store.preferences = {
      launchAtLogin: input.launchAtLogin === undefined ? store.preferences.launchAtLogin : Boolean(input.launchAtLogin), requireWindowsHello: nextHello,
      loginMode: input.loginMode === 'browser' ? 'browser' : 'webview', showStatusFloat: input.showStatusFloat === undefined ? store.preferences.showStatusFloat : Boolean(input.showStatusFloat),
      floatWidth, floatHeight: statusFloatHeightForWidth(floatWidth), floatOpacity: input.floatOpacity === undefined ? store.preferences.floatOpacity : normalizeStatusFloatOpacity(input.floatOpacity), lockStatusFloat: input.lockStatusFloat === undefined ? store.preferences.lockStatusFloat : Boolean(input.lockStatusFloat),
    }
    applyLaunchAtLogin(store.preferences.launchAtLogin); await writeJson(TENANT_STORE_FILE, store); await setStatusFloatVisible(store.preferences.showStatusFloat); publishStatus(); return store.preferences
  })
  ipcMain.handle('auth:status', getStatus); ipcMain.handle('auth:login', startLogin)
  ipcMain.handle('auth:logout', async () => { await standardLogout(); lastError = ''; publishStatus() })
  ipcMain.handle('security:refresh', refreshSecurityReport)
  ipcMain.handle('app:reset', resetToDefaults)
}
const gotLock = app.requestSingleInstanceLock()
if (!gotLock) app.quit()
else {
  app.on('second-instance', (_event, commandLine) => { const callbackUrl = extractProtocolUrl(commandLine); if (callbackUrl) { void handleProtocolUrl(callbackUrl).catch((error) => { lastError = userFacingError(error); publishStatus() }); return }; showMainWindow() })
  app.on('open-url', (event, url) => { event.preventDefault(); void handleProtocolUrl(url).catch((error) => { lastError = userFacingError(error); publishStatus() }) })
  void app.whenReady().then(async () => {
    app.setName(PRODUCT_NAME); app.setAppUserModelId(APP_USER_MODEL_ID); Menu.setApplicationMenu(null)
    const loginItemSettings = app.getLoginItemSettings(); launchInTray = launchInTray || Boolean(loginItemSettings.wasOpenedAtLogin)
    registerProtocol(); registerIpc(); const store = await getStore(); applyLaunchAtLogin(store.preferences.launchAtLogin); createTray()
    const restarted = await invalidateSessionAfterSystemRestart(); scheduleSecurityRefresh(); scheduleNetworkChangeRefresh(); void refreshSecurityReport(); await setStatusFloatVisible(store.preferences.showStatusFloat)
    if (!launchInTray) { createMainWindow(); if (!restarted) await restoreSession() }
    else if (store.preferences.loginMode === 'webview') { await startLogin().catch((error) => { lastError = userFacingError(error); publishStatus() }) }
    else if (!restarted) await restoreSession()
    publishStatus(); const startupCallback = extractProtocolUrl(process.argv); if (startupCallback) await handleProtocolUrl(startupCallback); app.on('activate', showMainWindow)
  })
  app.on('window-all-closed', () => undefined)
  app.on('before-quit', () => { isQuitting = true; if (securityRefreshTimer) clearInterval(securityRefreshTimer); if (networkChangeWatchTimer) clearInterval(networkChangeWatchTimer); if (networkChangeRefreshTimer) clearTimeout(networkChangeRefreshTimer); if (statusFloatBoundsSaveTimer) clearTimeout(statusFloatBoundsSaveTimer); void stopCompanion() })
}
