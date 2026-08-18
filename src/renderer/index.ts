type PublicTenant = {
  id: string
  displayName: string
  endpoint: string
  clientId: string
  orgName: string
  appName: string
  certificate: string
  allowedOrigins: string[]
  deviceName: string
  source: 'built-in' | 'custom'
}
type Preferences = { launchAtLogin: boolean; requireWindowsHello: boolean; loginMode: 'webview' | 'browser'; showStatusFloat: boolean; floatWidth: number; floatHeight: number; floatOpacity: number; lockStatusFloat: boolean }
type PreferenceInput = Partial<Preferences> & { floatSizeSource?: 'width' | 'height' }
type HelloAvailability = { available: boolean; message: string }
type SecurityCheck = { id: 'password' | 'bitlocker' | 'antivirus' | 'signatures' | 'firewall'; title: string; state: 'pass' | 'warning' | 'unknown'; detail: string }
type DeviceSecurityReport = { checks: SecurityCheck[]; risk: 'pass' | 'warning' | 'danger'; issueCount: number; unknownCount: number; checkedAt: string; localIp: string; publicAccess: boolean; platformSupported: boolean }
type Status = {
  configured: boolean; signedIn: boolean; companionRunning: boolean; userName?: string; displayName?: string; email?: string; devicePort?: number
  lastError?: string; activeTenantId?: string; activeTenantName?: string; activeTenantOrgName?: string
  requireWindowsHello: boolean; loginMode: 'webview' | 'browser'; floatOpacity: number; securityReport?: DeviceSecurityReport
}
type AppData = { tenants: PublicTenant[]; activeTenant: PublicTenant; preferences: Preferences; helloAvailability: HelloAvailability; status: Status }
type TenantInput = Partial<Omit<PublicTenant, 'source'>> & { allowedOrigins?: string[] }

interface Window {
  cloudVerifyDevice: {
    loadApp(): Promise<AppData>
    selectTenant(tenantId: string): Promise<PublicTenant>
    addTenant(tenant: TenantInput): Promise<PublicTenant>
    deleteTenant(tenantId: string): Promise<void>
    savePreferences(preferences: PreferenceInput): Promise<Preferences>
    getStatus(): Promise<Status>
    login(): Promise<void>
    logout(): Promise<void>
    refreshSecurity(): Promise<DeviceSecurityReport>
    resetToDefaults(): Promise<void>
    onStatusChanged(listener: (status: Status) => void): () => void
  }
}

function byId<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id)
  if (!element) throw new Error(`页面组件不可用：${id}`)
  return element as T
}

const elements = {
  openSettings: byId<HTMLButtonElement>('open-settings'),
  systemSettings: byId<HTMLElement>('system-settings'),
  tenantSelect: byId<HTMLSelectElement>('tenant-select'),
  addTenant: byId<HTMLButtonElement>('add-tenant'),
  deleteTenant: byId<HTMLButtonElement>('delete-tenant'),
  activeTenantName: byId<HTMLElement>('active-tenant-name'),
  statusTitle: byId<HTMLElement>('status-title'),
  statusBadge: byId<HTMLElement>('status-badge'),
  statusDetail: byId<HTMLElement>('status-detail'),
  statusError: byId<HTMLElement>('status-error'),
  devicePort: byId<HTMLElement>('device-port'),
  accountName: byId<HTMLElement>('account-name'),
  login: byId<HTMLButtonElement>('login-button'),
  logout: byId<HTMLButtonElement>('logout-button'),
  securityTitle: byId<HTMLElement>('security-title'),
  securitySummary: byId<HTMLElement>('security-summary'),
  securityList: byId<HTMLElement>('security-list'),
  securityCheckedAt: byId<HTMLElement>('security-checked-at'),
  refreshSecurity: byId<HTMLButtonElement>('refresh-security'),
  launchAtLogin: byId<HTMLInputElement>('launch-at-login'),
  loginMode: byId<HTMLSelectElement>('login-mode'),
  showStatusFloat: byId<HTMLInputElement>('show-status-float'),
  floatWidth: byId<HTMLInputElement>('float-width'),
  floatHeight: byId<HTMLInputElement>('float-height'),
  floatOpacity: byId<HTMLInputElement>('float-opacity'),
  floatOpacityValue: byId<HTMLOutputElement>('float-opacity-value'),
  lockStatusFloat: byId<HTMLInputElement>('lock-status-float'),
  requireWindowsHello: byId<HTMLInputElement>('require-windows-hello'),
  helloHelp: byId<HTMLElement>('hello-help'),
  settingsMessage: byId<HTMLElement>('settings-message'),
  resetToDefaults: byId<HTMLButtonElement>('reset-to-defaults'),
  tenantEditor: byId<HTMLElement>('tenant-editor'),
  cancelTenantEdit: byId<HTMLButtonElement>('cancel-tenant-edit'),
  tenantForm: byId<HTMLFormElement>('tenant-form'),
  tenantDisplayName: byId<HTMLInputElement>('tenant-display-name'),
  tenantEndpoint: byId<HTMLInputElement>('tenant-endpoint'),
  tenantClientId: byId<HTMLInputElement>('tenant-client-id'),
  tenantOrgName: byId<HTMLInputElement>('tenant-org-name'),
  tenantAppName: byId<HTMLInputElement>('tenant-app-name'),
  tenantDeviceName: byId<HTMLInputElement>('tenant-device-name'),
  tenantCertificate: byId<HTMLTextAreaElement>('tenant-certificate'),
  tenantAllowedOrigins: byId<HTMLTextAreaElement>('tenant-allowed-origins'),
  saveTenant: byId<HTMLButtonElement>('save-tenant'),
  tenantFormMessage: byId<HTMLElement>('tenant-form-message'),
}

let currentData: AppData | null = null

function setMessage(element: HTMLElement, message = '', isError = false): void {
  element.textContent = message
  element.classList.toggle('form-message-error', isError)
}

function renderStatus(status: Status): void {
  elements.statusError.hidden = !status.lastError
  elements.statusError.textContent = status.lastError || ''
  elements.activeTenantName.textContent = status.activeTenantName || '—'
  elements.accountName.textContent = status.signedIn ? status.displayName || status.userName || '已登录' : '—'
  elements.devicePort.textContent = status.companionRunning ? `127.0.0.1:${status.devicePort ?? 47321}` : '未启动'
  if (status.companionRunning) {
    elements.statusTitle.textContent = '设备认证服务正在运行'
    elements.statusDetail.textContent = '网页请求将通过 Windows 通知中心发送到此设备，由您选择授权或拒绝。'
    elements.statusBadge.textContent = '已就绪'; elements.statusBadge.className = 'badge badge-success'
  } else if (status.signedIn) {
    elements.statusTitle.textContent = '已登录，设备认证服务未启动'
    elements.statusDetail.textContent = '设备认证服务需要重新启动，请退出账户后再次登录。'
    elements.statusBadge.textContent = '需要处理'; elements.statusBadge.className = 'badge badge-warning'
  } else if (status.configured) {
    elements.statusTitle.textContent = '租户已配置，等待登录'
    elements.statusDetail.textContent = status.loginMode === 'webview' ? '点击登录账户后，将在应用内登录窗口中完成安全登录。' : '点击登录账户后，将在系统默认浏览器中完成安全登录。'
    elements.statusBadge.textContent = '待登录'; elements.statusBadge.className = 'badge badge-neutral'
  } else {
    elements.statusTitle.textContent = '需要完成租户配置'
    elements.statusDetail.textContent = '请检查租户的服务地址、客户端 ID、组织、应用名称和证书。'
    elements.statusBadge.textContent = '待配置'; elements.statusBadge.className = 'badge badge-neutral'
  }
  elements.login.hidden = status.companionRunning
  elements.logout.hidden = !status.signedIn
  elements.login.disabled = !status.configured
  renderSecurity(status.securityReport)
}

function riskText(report: DeviceSecurityReport): { title: string; summary: string } {
  if (!report.platformSupported) return { title: '当前环境暂不支持检测', summary: '设备安全态势仅在 Windows 设备上提供。' }
  if (report.issueCount === 0) return { title: '通过检测', summary: '未发现需要处理的安全风险。系统暂未返回的检查项目不会计入风险。' }
  if (report.risk === 'danger') return { title: '高危风险', summary: `发现 ${report.issueCount} 项明确的安全问题，请尽快检查设备设置。` }
  return { title: '存在隐患', summary: `发现 ${report.issueCount} 项需要处理的安全问题。` }
}

function renderSecurity(report?: DeviceSecurityReport): void {
  if (!report) {
    elements.securityTitle.textContent = '正在进行安全检查…'
    elements.securitySummary.textContent = '将通过本机 Windows 管理接口检查设备登录凭据、C 盘 BitLocker、杀毒软件、病毒库和 Windows 防火墙。本功能仅展示状态，不修改系统设置。'
    elements.securityList.replaceChildren()
    elements.securityCheckedAt.textContent = '正在读取检测时间…'
    return
  }
  const copy = riskText(report)
  elements.securityTitle.textContent = copy.title
  elements.securitySummary.textContent = copy.summary
  elements.securityList.replaceChildren(...report.checks.map((check) => {
    const card = document.createElement('div')
    card.className = `security-check security-check-${check.state}`
    const name = document.createElement('strong'); name.textContent = check.title
    const description = document.createElement('span'); description.textContent = check.detail
    card.append(name, description)
    return card
  }))
  const checked = new Date(report.checkedAt)
  elements.securityCheckedAt.textContent = `最近检测：${Number.isNaN(checked.getTime()) ? '刚刚' : checked.toLocaleString('zh-CN')} · 局域网 IP：${report.localIp}${report.publicAccess ? '（公网）' : ''}`
}

function renderTenants(data: AppData): void {
  elements.tenantSelect.replaceChildren(...data.tenants.map((tenant) => {
    const option = document.createElement('option')
    option.value = tenant.id; option.textContent = tenant.displayName; option.selected = tenant.id === data.activeTenant.id
    return option
  }))
  elements.deleteTenant.disabled = data.tenants.length <= 1
}

function renderPreferences(data: AppData): void {
  elements.launchAtLogin.checked = data.preferences.launchAtLogin
  elements.loginMode.value = data.preferences.loginMode
  elements.showStatusFloat.checked = data.preferences.showStatusFloat
  elements.floatWidth.value = String(data.preferences.floatWidth)
  elements.floatHeight.value = String(data.preferences.floatHeight)
  elements.floatOpacity.value = String(data.preferences.floatOpacity)
  elements.floatOpacityValue.value = `${data.preferences.floatOpacity}%`
  elements.floatOpacityValue.textContent = `${data.preferences.floatOpacity}%`
  elements.floatWidth.disabled = !data.preferences.showStatusFloat
  elements.floatHeight.disabled = !data.preferences.showStatusFloat
  elements.floatOpacity.disabled = !data.preferences.showStatusFloat
  elements.lockStatusFloat.checked = data.preferences.lockStatusFloat
  elements.lockStatusFloat.disabled = !data.preferences.showStatusFloat
  elements.requireWindowsHello.checked = data.preferences.requireWindowsHello
  elements.requireWindowsHello.disabled = !data.helloAvailability.available
  elements.helloHelp.textContent = data.helloAvailability.available ? '开启后，授权每次网页登录前均需完成一次 Windows Hello 验证。' : data.helloAvailability.message
}

function readAllowedOrigins(): string[] { return elements.tenantAllowedOrigins.value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean) }
function openTenantEditor(): void { elements.tenantEditor.hidden = false; elements.tenantForm.reset(); setMessage(elements.tenantFormMessage); elements.tenantEditor.scrollIntoView({ behavior: 'smooth', block: 'start' }) }
function closeTenantEditor(): void { elements.tenantEditor.hidden = true; elements.tenantForm.reset(); setMessage(elements.tenantFormMessage) }

async function reload(): Promise<void> {
  const data = await window.cloudVerifyDevice.loadApp()
  currentData = data; renderTenants(data); renderPreferences(data); renderStatus(data.status)
}

async function handleTenantSelect(): Promise<void> {
  const previous = currentData?.activeTenant.id; const selected = elements.tenantSelect.value
  if (!previous || selected === previous) return
  elements.tenantSelect.disabled = true
  try { await window.cloudVerifyDevice.selectTenant(selected); await reload() }
  catch (error) { elements.tenantSelect.value = previous; setMessage(elements.settingsMessage, error instanceof Error ? error.message : '租户切换未完成。', true) }
  finally { elements.tenantSelect.disabled = false }
}

async function handleAddTenant(event: SubmitEvent): Promise<void> {
  event.preventDefault()
  if (!elements.tenantForm.reportValidity()) return
  elements.saveTenant.disabled = true; setMessage(elements.tenantFormMessage, '正在添加租户…')
  try {
    await window.cloudVerifyDevice.addTenant({
      displayName: elements.tenantDisplayName.value, endpoint: elements.tenantEndpoint.value, clientId: elements.tenantClientId.value,
      orgName: elements.tenantOrgName.value, appName: elements.tenantAppName.value, deviceName: elements.tenantDeviceName.value,
      certificate: elements.tenantCertificate.value, allowedOrigins: readAllowedOrigins(),
    })
    await reload(); closeTenantEditor()
  } catch (error) { setMessage(elements.tenantFormMessage, error instanceof Error ? error.message : '添加租户未完成。', true) }
  finally { elements.saveTenant.disabled = false }
}

async function savePreferences(floatSizeSource?: 'width' | 'height'): Promise<void> {
  const previous = currentData?.preferences
  if (!previous) return
  setMessage(elements.settingsMessage, '正在保存设置…')
  try {
    await window.cloudVerifyDevice.savePreferences({
      launchAtLogin: elements.launchAtLogin.checked, requireWindowsHello: elements.requireWindowsHello.checked,
      loginMode: elements.loginMode.value === 'browser' ? 'browser' : 'webview', showStatusFloat: elements.showStatusFloat.checked,
      floatWidth: Number(elements.floatWidth.value), floatHeight: Number(elements.floatHeight.value), floatOpacity: Number(elements.floatOpacity.value), lockStatusFloat: elements.lockStatusFloat.checked, floatSizeSource,
    })
    await reload(); setMessage(elements.settingsMessage, '系统设置已保存。')
  } catch (error) {
    elements.launchAtLogin.checked = previous.launchAtLogin; elements.loginMode.value = previous.loginMode
    elements.showStatusFloat.checked = previous.showStatusFloat; elements.floatWidth.value = String(previous.floatWidth); elements.floatHeight.value = String(previous.floatHeight)
    elements.floatOpacity.value = String(previous.floatOpacity); elements.floatOpacityValue.value = `${previous.floatOpacity}%`; elements.floatOpacityValue.textContent = `${previous.floatOpacity}%`
    elements.lockStatusFloat.checked = previous.lockStatusFloat; elements.requireWindowsHello.checked = previous.requireWindowsHello
    setMessage(elements.settingsMessage, error instanceof Error ? error.message : '系统设置未保存。', true)
  }
}

async function handleLogin(): Promise<void> {
  elements.login.disabled = true
  try {
    await window.cloudVerifyDevice.login()
    const mode = currentData?.preferences.loginMode === 'browser' ? '默认浏览器' : '应用内登录窗口'
    setMessage(elements.settingsMessage, `已打开${mode}，请完成账户登录。`)
  } catch (error) { setMessage(elements.settingsMessage, error instanceof Error ? error.message : '登录未启动。', true); elements.systemSettings.hidden = false }
  finally { elements.login.disabled = false }
}

async function handleLogout(): Promise<void> {
  elements.logout.disabled = true
  try { await window.cloudVerifyDevice.logout(); await reload() }
  catch (error) { setMessage(elements.settingsMessage, error instanceof Error ? error.message : '退出未完成。', true) }
  finally { elements.logout.disabled = false }
}

async function handleRefreshSecurity(): Promise<void> {
  elements.refreshSecurity.disabled = true
  try { await window.cloudVerifyDevice.refreshSecurity(); renderStatus(await window.cloudVerifyDevice.getStatus()) }
  catch { elements.securitySummary.textContent = '本次安全检测未能完成，请稍后刷新重试。' }
  finally { elements.refreshSecurity.disabled = false }
}

async function handleResetToDefaults(): Promise<void> {
  elements.resetToDefaults.disabled = true
  setMessage(elements.settingsMessage, '等待确认重置…')
  try { await window.cloudVerifyDevice.resetToDefaults(); await reload(); setMessage(elements.settingsMessage, '已恢复默认状态。') }
  catch (error) { setMessage(elements.settingsMessage, error instanceof Error ? error.message : '重置未完成。', true) }
  finally { elements.resetToDefaults.disabled = false }
}

function bindEvents(): void {
  elements.openSettings.addEventListener('click', () => { elements.systemSettings.hidden = !elements.systemSettings.hidden; elements.openSettings.textContent = elements.systemSettings.hidden ? '系统设置' : '收起设置' })
  elements.tenantSelect.addEventListener('change', () => void handleTenantSelect())
  elements.addTenant.addEventListener('click', openTenantEditor)
  elements.deleteTenant.addEventListener('click', () => { if (currentData) void window.cloudVerifyDevice.deleteTenant(currentData.activeTenant.id).then(reload).catch((error) => setMessage(elements.settingsMessage, error.message, true)) })
  elements.cancelTenantEdit.addEventListener('click', closeTenantEditor)
  elements.tenantForm.addEventListener('submit', (event) => void handleAddTenant(event))
  elements.launchAtLogin.addEventListener('change', () => void savePreferences())
  elements.loginMode.addEventListener('change', () => void savePreferences())
  elements.showStatusFloat.addEventListener('change', () => void savePreferences())
  elements.floatWidth.addEventListener('change', () => void savePreferences('width'))
  elements.floatHeight.addEventListener('change', () => void savePreferences('height'))
  elements.floatOpacity.addEventListener('input', () => { elements.floatOpacityValue.value = `${elements.floatOpacity.value}%`; elements.floatOpacityValue.textContent = `${elements.floatOpacity.value}%` })
  elements.floatOpacity.addEventListener('change', () => void savePreferences())
  elements.lockStatusFloat.addEventListener('change', () => void savePreferences())
  elements.requireWindowsHello.addEventListener('change', () => void savePreferences())
  elements.resetToDefaults.addEventListener('click', () => void handleResetToDefaults())
  elements.login.addEventListener('click', () => void handleLogin())
  elements.logout.addEventListener('click', () => void handleLogout())
  elements.refreshSecurity.addEventListener('click', () => void handleRefreshSecurity())
}

async function initialize(): Promise<void> {
  bindEvents()
  if (!window.cloudVerifyDevice) { renderStatus({ configured: false, signedIn: false, companionRunning: false, lastError: '应用组件未正确加载。请退出后重新启动应用。', requireWindowsHello: false, loginMode: 'webview', floatOpacity: 88 }); return }
  window.cloudVerifyDevice.onStatusChanged(renderStatus)
  try { await reload() }
  catch { renderStatus({ configured: false, signedIn: false, companionRunning: false, lastError: '无法读取本机配置，请重新启动应用。', requireWindowsHello: false, loginMode: 'webview', floatOpacity: 88 }) }
}

document.addEventListener('DOMContentLoaded', () => void initialize())
