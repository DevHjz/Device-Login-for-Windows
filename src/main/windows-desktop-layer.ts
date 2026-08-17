import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import type { BrowserWindow } from 'electron'

const execFileAsync = promisify(execFile)

function encodePowerShell(script: string): string {
  return Buffer.from(script, 'utf16le').toString('base64')
}

function nativeHandleAsDecimal(window: BrowserWindow): string | null {
  const handle = window.getNativeWindowHandle()
  if (handle.length >= 8) return handle.readBigUInt64LE(0).toString()
  if (handle.length >= 4) return String(handle.readUInt32LE(0))
  return null
}

/**
 * 将独立状态窗口设为 Windows 桌面 Progman 的受控窗口。
 * 这样它不需要普通的 topmost 层级：激活的应用窗口会覆盖它，而回到桌面时会随桌面显示。
 * 若系统策略阻止该 Win32 调用，函数静默返回 false，调用方保留普通非置顶窗口行为。
 */
export async function attachWindowToDesktop(window: BrowserWindow): Promise<boolean> {
  if (process.platform !== 'win32' || window.isDestroyed()) return false
  const nativeHandle = nativeHandleAsDecimal(window)
  if (!nativeHandle) return false
  const script = `
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class CloudVerifyDesktopLayer {
  [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr FindWindow(string className, string windowName);
  [DllImport("user32.dll", EntryPoint="SetWindowLongPtrW", SetLastError=true)]
  public static extern IntPtr SetWindowLongPtr(IntPtr hWnd, int nIndex, IntPtr dwNewLong);
}
'@
$floatWindow = [IntPtr]::new([Int64]::Parse('${nativeHandle}'))
$desktopWindow = [CloudVerifyDesktopLayer]::FindWindow('Progman', $null)
if ($floatWindow -eq [IntPtr]::Zero -or $desktopWindow -eq [IntPtr]::Zero) { 'false'; exit 0 }
[void][CloudVerifyDesktopLayer]::SetWindowLongPtr($floatWindow, -8, $desktopWindow)
'true'
`
  try {
    const { stdout } = await execFileAsync('powershell.exe', [
      '-NoProfile',
      '-NonInteractive',
      '-ExecutionPolicy', 'Bypass',
      '-EncodedCommand', encodePowerShell(script),
    ], { windowsHide: true, timeout: 8_000, maxBuffer: 64 * 1024 })
    return stdout.trim().endsWith('true')
  } catch {
    return false
  }
}
