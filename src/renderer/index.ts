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
  hasClientSecret: boolean
}

type Preferences = { launchAtLogin: boolean; requireWindowsHello: boolean }
type HelloAvailability = { available: boolean; message: string }
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
  requireWindowsHello: boolean
}

type AppData = {
  tenants: PublicTenant[]
  activeTenant: PublicTenant
  preferences: Preferences
  helloAvailability: HelloAvailability
  status: Status
}

type TenantInput = Partial<Omit<PublicTenant, 'hasClientSecret' | 'source'>> & { clientSecret?: string; allowedOrigins?: string[] }

interface Window {
  cloudVerifyDevice: {
    loadApp(): Promise<AppData>
    selectTenant(tenantId: string): Promise<PublicTenant>
    saveTenant(tenant: TenantInput): Promise<PublicTenant>
    deleteTenant(tenantId: string): Promise<void>
    savePreferences(preferences: Preferences): Promise<Preferences>
    getStatus(): Promise<Status>
    login(): Promise<void>
    logout(): Promise<void>
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
  tenantSecretState: byId<HTMLElement>('tenant-secret-state'),
  addTenant: byId<HTMLButtonElement>('add-tenant'),
  editTenant: byId<HTMLButtonElement>('edit-tenant'),
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
  launchAtLogin: byId<HTMLInputElement>('launch-at-login'),
  requireWindowsHello: byId<HTMLInputElement>('require-windows-hello'),
  helloHelp: byId<HTMLElement>('hello-help'),
  settingsMessage: byId<HTMLElement>('settings-message'),
  tenantEditor: byId<HTMLElement>('tenant-editor'),
  tenantEditorTitle: byId<HTMLElement>('tenant-editor-title'),
  cancelTenantEdit: byId<HTMLButtonElement>('cancel-tenant-edit'),
  tenantForm: byId<HTMLFormElement>('tenant-form'),
  tenantId: byId<HTMLInputElement>('tenant-id'),
  tenantDisplayName: byId<HTMLInputElement>('tenant-display-name'),
  tenantEndpoint: byId<HTMLInputElement>('tenant-endpoint'),
  tenantClientId: byId<HTMLInputElement>('tenant-client-id'),
  tenantOrgName: byId<HTMLInputElement>('tenant-org-name'),
  tenantAppName: byId<HTMLInputElement>('tenant-app-name'),
  tenantDeviceName: byId<HTMLInputElement>('tenant-device-name'),
  tenantClientSecret: byId<HTMLInputElement>('tenant-client-secret'),
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
    elements.statusTitle.textContent = '设备服务正在运行'
    elements.statusDetail.textContent = '网页请求将通过 Windows 通知中心发送到此设备，由您选择允许或拒绝。'
    elements.statusBadge.textContent = '已就绪'
    elements.statusBadge.className = 'badge badge-success'
  } else if (status.signedIn) {
    elements.statusTitle.textContent = '已登录，设备服务未启动'
    elements.statusDetail.textContent = '设备服务需要重新启动，请退出账户后再次登录。'
    elements.statusBadge.textContent = '需要处理'
    elements.statusBadge.className = 'badge badge-warning'
  } else if (status.configured) {
    elements.statusTitle.textContent = '租户已配置，等待登录'
    elements.statusDetail.textContent = '登录账户后，设备服务会自动启动。'
    elements.statusBadge.textContent = '待登录'
    elements.statusBadge.className = 'badge badge-neutral'
  } else {
    elements.statusTitle.textContent = '需要完成租户配置'
    elements.statusDetail.textContent = '请由管理员编辑当前租户并安全保存客户端密钥。'
    elements.statusBadge.textContent = '待配置'
    elements.statusBadge.className = 'badge badge-neutral'
  }
  elements.login.hidden = status.companionRunning
  elements.logout.hidden = !status.signedIn
  elements.login.disabled = !status.configured
}

function renderTenants(data: AppData): void {
  elements.tenantSelect.replaceChildren(...data.tenants.map((tenant) => {
    const option = document.createElement('option')
    option.value = tenant.id
    option.textContent = tenant.displayName
    option.selected = tenant.id === data.activeTenant.id
    return option
  }))
  elements.tenantSecretState.textContent = data.activeTenant.hasClientSecret
    ? '客户端密钥已安全保存。'
    : '需要由管理员保存客户端密钥。'
  elements.deleteTenant.disabled = data.tenants.length <= 1
}

function renderPreferences(data: AppData): void {
  elements.launchAtLogin.checked = data.preferences.launchAtLogin
  elements.requireWindowsHello.checked = data.preferences.requireWindowsHello
  elements.requireWindowsHello.disabled = !data.helloAvailability.available
  elements.helloHelp.textContent = data.helloAvailability.available
    ? '开启后，批准每次网页登录前均需完成一次 Windows Hello 验证。'
    : data.helloAvailability.message
}

function readAllowedOrigins(): string[] {
  return elements.tenantAllowedOrigins.value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean)
}

function openTenantEditor(tenant?: PublicTenant): void {
  elements.tenantEditor.hidden = false
  elements.tenantEditorTitle.textContent = tenant ? `编辑租户：${tenant.displayName}` : '添加租户'
  elements.tenantId.value = tenant?.id || ''
  elements.tenantDisplayName.value = tenant?.displayName || ''
  elements.tenantEndpoint.value = tenant?.endpoint || ''
  elements.tenantClientId.value = tenant?.clientId || ''
  elements.tenantOrgName.value = tenant?.orgName || ''
  elements.tenantAppName.value = tenant?.appName || ''
  elements.tenantDeviceName.value = tenant?.deviceName || ''
  elements.tenantCertificate.value = tenant?.certificate || ''
  elements.tenantAllowedOrigins.value = tenant?.allowedOrigins.join('\n') || ''
  elements.tenantClientSecret.value = ''
  elements.tenantClientSecret.placeholder = tenant?.hasClientSecret ? '已安全保存；留空则保留原值' : '首次保存时必填；保存后不会再次显示'
  setMessage(elements.tenantFormMessage)
  elements.tenantEditor.scrollIntoView({ behavior: 'smooth', block: 'start' })
}

function closeTenantEditor(): void {
  elements.tenantEditor.hidden = true
  elements.tenantForm.reset()
  setMessage(elements.tenantFormMessage)
}

async function reload(): Promise<void> {
  const data = await window.cloudVerifyDevice.loadApp()
  currentData = data
  renderTenants(data)
  renderPreferences(data)
  renderStatus(data.status)
}

async function handleTenantSelect(): Promise<void> {
  const previous = currentData?.activeTenant.id
  const selected = elements.tenantSelect.value
  if (!previous || selected === previous) return
  elements.tenantSelect.disabled = true
  try {
    await window.cloudVerifyDevice.selectTenant(selected)
    await reload()
  } catch (error) {
    elements.tenantSelect.value = previous
    setMessage(elements.settingsMessage, error instanceof Error ? error.message : '租户切换未完成。', true)
  } finally {
    elements.tenantSelect.disabled = false
  }
}

async function handleSaveTenant(event: SubmitEvent): Promise<void> {
  event.preventDefault()
  if (!elements.tenantForm.reportValidity()) return
  const existing = currentData?.tenants.find((tenant) => tenant.id === elements.tenantId.value)
  if (!existing?.hasClientSecret && !elements.tenantClientSecret.value.trim()) {
    setMessage(elements.tenantFormMessage, '首次保存此租户必须填写客户端密钥。', true)
    elements.tenantClientSecret.focus()
    return
  }
  elements.saveTenant.disabled = true
  setMessage(elements.tenantFormMessage, '正在安全保存…')
  try {
    await window.cloudVerifyDevice.saveTenant({
      id: elements.tenantId.value || undefined,
      displayName: elements.tenantDisplayName.value,
      endpoint: elements.tenantEndpoint.value,
      clientId: elements.tenantClientId.value,
      orgName: elements.tenantOrgName.value,
      appName: elements.tenantAppName.value,
      deviceName: elements.tenantDeviceName.value,
      clientSecret: elements.tenantClientSecret.value,
      certificate: elements.tenantCertificate.value,
      allowedOrigins: readAllowedOrigins(),
    })
    await reload()
    closeTenantEditor()
  } catch (error) {
    setMessage(elements.tenantFormMessage, error instanceof Error ? error.message : '租户保存未完成。', true)
  } finally {
    elements.saveTenant.disabled = false
  }
}

async function savePreferences(): Promise<void> {
  const previous = currentData?.preferences
  if (!previous) return
  setMessage(elements.settingsMessage, '正在保存设置…')
  try {
    await window.cloudVerifyDevice.savePreferences({
      launchAtLogin: elements.launchAtLogin.checked,
      requireWindowsHello: elements.requireWindowsHello.checked,
    })
    await reload()
    setMessage(elements.settingsMessage, '系统设置已保存。')
  } catch (error) {
    elements.launchAtLogin.checked = previous.launchAtLogin
    elements.requireWindowsHello.checked = previous.requireWindowsHello
    setMessage(elements.settingsMessage, error instanceof Error ? error.message : '系统设置未保存。', true)
  }
}

async function handleLogin(): Promise<void> {
  elements.login.disabled = true
  try {
    await window.cloudVerifyDevice.login()
  } catch (error) {
    setMessage(elements.settingsMessage, error instanceof Error ? error.message : '登录未启动。', true)
    elements.systemSettings.hidden = false
  } finally {
    elements.login.disabled = false
  }
}

async function handleLogout(): Promise<void> {
  elements.logout.disabled = true
  try {
    await window.cloudVerifyDevice.logout()
    await reload()
  } catch (error) {
    setMessage(elements.settingsMessage, error instanceof Error ? error.message : '退出未完成。', true)
  } finally {
    elements.logout.disabled = false
  }
}

function bindEvents(): void {
  elements.openSettings.addEventListener('click', () => {
    elements.systemSettings.hidden = !elements.systemSettings.hidden
    elements.openSettings.textContent = elements.systemSettings.hidden ? '系统设置' : '收起设置'
  })
  elements.tenantSelect.addEventListener('change', () => void handleTenantSelect())
  elements.addTenant.addEventListener('click', () => openTenantEditor())
  elements.editTenant.addEventListener('click', () => openTenantEditor(currentData?.activeTenant))
  elements.deleteTenant.addEventListener('click', () => {
    if (currentData) void window.cloudVerifyDevice.deleteTenant(currentData.activeTenant.id).then(reload).catch((error) => setMessage(elements.settingsMessage, error.message, true))
  })
  elements.cancelTenantEdit.addEventListener('click', closeTenantEditor)
  elements.tenantForm.addEventListener('submit', (event) => void handleSaveTenant(event))
  elements.launchAtLogin.addEventListener('change', () => void savePreferences())
  elements.requireWindowsHello.addEventListener('change', () => void savePreferences())
  elements.login.addEventListener('click', () => void handleLogin())
  elements.logout.addEventListener('click', () => void handleLogout())
}

async function initialize(): Promise<void> {
  bindEvents()
  if (!window.cloudVerifyDevice) {
    renderStatus({ configured: false, signedIn: false, companionRunning: false, lastError: '应用组件未正确加载。请退出后重新启动应用。', requireWindowsHello: false })
    return
  }
  window.cloudVerifyDevice.onStatusChanged(renderStatus)
  try {
    await reload()
  } catch (error) {
    renderStatus({ configured: false, signedIn: false, companionRunning: false, lastError: '无法读取本机配置，请重新启动应用。', requireWindowsHello: false })
  }
}

document.addEventListener('DOMContentLoaded', () => void initialize())
