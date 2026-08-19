import { contextBridge, ipcRenderer } from 'electron'

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
  createdAt: string
  updatedAt: string
  source: 'built-in' | 'custom'
}

type Preferences = {
  launchAtLogin: boolean
  requireWindowsHello: boolean
  loginMode: 'webview' | 'browser'
  showStatusFloat: boolean
  floatWidth: number
  floatHeight: number
  floatOpacity: number
  lockStatusFloat: boolean
  allowPublicNetwork: boolean
}
type PreferenceInput = Partial<Preferences>

type HelloAvailability = { available: boolean; message: string }
type SecurityCheck = { id: 'password' | 'bitlocker' | 'antivirus' | 'signatures' | 'firewall'; title: string; state: 'pass' | 'warning' | 'unknown'; detail: string }
type DeviceSecurityReport = { checks: SecurityCheck[]; risk: 'pass' | 'warning' | 'danger'; issueCount: number; unknownCount: number; checkedAt: string; localIp: string; publicAccess: boolean; platformSupported: boolean }
type Status = {
  configured: boolean
  signedIn: boolean
  companionRunning: boolean
  userName?: string
  displayName?: string
  email?: string
  devicePort?: number
  lastError?: string
  activeTenantId?: string
  activeTenantName?: string
  activeTenantOrgName?: string
  requireWindowsHello: boolean
  loginMode: 'webview' | 'browser'
  floatOpacity: number
  securityReport?: DeviceSecurityReport
}
type TenantInput = { displayName?: string; endpoint?: string; clientId?: string; orgName?: string; appName?: string; certificate?: string; allowedOrigins?: string[]; deviceName?: string }
type AppData = { tenants: PublicTenant[]; activeTenant: PublicTenant; preferences: Preferences; helloAvailability: HelloAvailability; hasPublicNetworkPassword: boolean; status: Status }
type PublicNetworkUnlockResult = { accepted: boolean; message?: string }

const api = {
  loadApp: (): Promise<AppData> => ipcRenderer.invoke('app:load'),
  selectTenant: (tenantId: string): Promise<PublicTenant> => ipcRenderer.invoke('tenant:select', tenantId),
  addTenant: (tenant: TenantInput): Promise<PublicTenant> => ipcRenderer.invoke('tenant:add', tenant),
  deleteTenant: (tenantId: string): Promise<void> => ipcRenderer.invoke('tenant:delete', tenantId),
  savePreferences: (preferences: PreferenceInput): Promise<Preferences> => ipcRenderer.invoke('preferences:save', preferences),
  getStatus: (): Promise<Status> => ipcRenderer.invoke('auth:status'),
  login: (): Promise<void> => ipcRenderer.invoke('auth:login'),
  logout: (): Promise<void> => ipcRenderer.invoke('auth:logout'),
  refreshSecurity: (): Promise<DeviceSecurityReport> => ipcRenderer.invoke('security:refresh'),
  resetToDefaults: (): Promise<void> => ipcRenderer.invoke('app:reset'),
  unlockPublicNetwork: (password: string): Promise<PublicNetworkUnlockResult> => ipcRenderer.invoke('public-network:unlock', password),
  cancelPublicNetworkUnlock: (): Promise<boolean> => ipcRenderer.invoke('public-network:cancel-unlock'),
  onPublicNetworkPasswordPromptChange: (listener: (visible: boolean) => void): (() => void) => {
    const show = (): void => listener(true)
    const hide = (): void => listener(false)
    ipcRenderer.on('public-network:show-password-prompt', show)
    ipcRenderer.on('public-network:hide-password-prompt', hide)
    return () => { ipcRenderer.removeListener('public-network:show-password-prompt', show); ipcRenderer.removeListener('public-network:hide-password-prompt', hide) }
  },
  onStatusChanged: (listener: (status: Status) => void): (() => void) => {
    const handler = (_event: Electron.IpcRendererEvent, status: Status): void => listener(status)
    ipcRenderer.on('status:changed', handler)
    return () => ipcRenderer.removeListener('status:changed', handler)
  },
}

contextBridge.exposeInMainWorld('cloudVerifyDevice', api)
