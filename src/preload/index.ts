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
  hasClientSecret: boolean
}

type LoginMode = 'webview' | 'browser'
type Preferences = {
  launchAtLogin: boolean
  requireWindowsHello: boolean
  loginMode: LoginMode
  showStatusFloat: boolean
}

type HelloAvailability = { available: boolean; message: string }
type SecurityCheckState = 'pass' | 'warning' | 'unknown'
type SecurityCheck = { id: string; title: string; state: SecurityCheckState; detail: string }
type DeviceSecurityReport = {
  checks: SecurityCheck[]
  risk: 'pass' | 'warning' | 'danger'
  issueCount: number
  checkedAt: string
  localIp: string
  publicAccess: boolean
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
  requireWindowsHello: boolean
  securityReport?: DeviceSecurityReport
}

type TenantInput = {
  id?: string
  displayName?: string
  endpoint?: string
  clientId?: string
  orgName?: string
  appName?: string
  certificate?: string
  allowedOrigins?: string[]
  deviceName?: string
  clientSecret?: string
}

const api = {
  loadApp: (): Promise<{ tenants: PublicTenant[]; activeTenant: PublicTenant; preferences: Preferences; helloAvailability: HelloAvailability; status: Status }> => ipcRenderer.invoke('app:load'),
  selectTenant: (tenantId: string): Promise<PublicTenant> => ipcRenderer.invoke('tenant:select', tenantId),
  saveTenant: (tenant: TenantInput): Promise<PublicTenant> => ipcRenderer.invoke('tenant:save', tenant),
  deleteTenant: (tenantId: string): Promise<void> => ipcRenderer.invoke('tenant:delete', tenantId),
  savePreferences: (preferences: Preferences): Promise<Preferences> => ipcRenderer.invoke('preferences:save', preferences),
  getStatus: (): Promise<Status> => ipcRenderer.invoke('auth:status'),
  refreshSecurity: (): Promise<DeviceSecurityReport> => ipcRenderer.invoke('security:refresh'),
  login: (): Promise<void> => ipcRenderer.invoke('auth:login'),
  logout: (): Promise<void> => ipcRenderer.invoke('auth:logout'),
  onStatusChanged: (listener: (status: Status) => void): (() => void) => {
    const handler = (_event: Electron.IpcRendererEvent, status: Status): void => listener(status)
    ipcRenderer.on('status:changed', handler)
    return () => ipcRenderer.removeListener('status:changed', handler)
  },
}

contextBridge.exposeInMainWorld('cloudVerifyDevice', api)
