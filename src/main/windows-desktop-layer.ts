import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import type { BrowserWindow } from 'electron'

const execFileAsync = promisify(execFile)

function encodePowerShell(script: string): string { return Buffer.from(script, 'utf16le').toString('base64') }

function nativeHandleAsDecimal(window: BrowserWindow): string | null {
  const handle = window.getNativeWindowHandle()
  if (handle.length >= 8) return handle.readBigUInt64LE(0).toString()
  if (handle.length >= 4) return String(handle.readUInt32LE(0))
  return null
}

/**
 * 将状态窗附着到 Windows 桌面 Progman，而非普通应用的 topmost 层。
 * SetParent 使状态窗成为桌面子窗口：普通应用位于其上方，Win+D 返回桌面时仍会显示。
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
  [DllImport("user32.dll", SetLastError=true)]
  public static extern IntPtr SetParent(IntPtr hWndChild, IntPtr hWndNewParent);
  [DllImport("user32.dll", EntryPoint="GetWindowLongPtrW", SetLastError=true)]
  public static extern IntPtr GetWindowLongPtr(IntPtr hWnd, int nIndex);
  [DllImport("user32.dll", EntryPoint="SetWindowLongPtrW", SetLastError=true)]
  public static extern IntPtr SetWindowLongPtr(IntPtr hWnd, int nIndex, IntPtr dwNewLong);
  [DllImport("user32.dll", SetLastError=true)]
  public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int x, int y, int cx, int cy, uint flags);
}
'@
$GWL_STYLE = -16
$WS_CHILD = 0x40000000
$WS_POPUP = [int]0x80000000
$HWND_TOP = [IntPtr]::Zero
$SWP_NOSIZE = 0x0001
$SWP_NOMOVE = 0x0002
$SWP_NOACTIVATE = 0x0010
$SWP_FRAMECHANGED = 0x0020
$floatWindow = [IntPtr]::new([Int64]::Parse('${nativeHandle}'))
$desktopWindow = [CloudVerifyDesktopLayer]::FindWindow('Progman', $null)
if ($floatWindow -eq [IntPtr]::Zero -or $desktopWindow -eq [IntPtr]::Zero) { 'false'; exit 0 }
$style = [CloudVerifyDesktopLayer]::GetWindowLongPtr($floatWindow, $GWL_STYLE).ToInt64()
$newStyle = (($style -bor $WS_CHILD) -band (-bnot $WS_POPUP))
[void][CloudVerifyDesktopLayer]::SetWindowLongPtr($floatWindow, $GWL_STYLE, [IntPtr]::new($newStyle))
[void][CloudVerifyDesktopLayer]::SetParent($floatWindow, $desktopWindow)
[void][CloudVerifyDesktopLayer]::SetWindowPos($floatWindow, $HWND_TOP, 0, 0, 0, 0, ($SWP_NOMOVE -bor $SWP_NOSIZE -bor $SWP_NOACTIVATE -bor $SWP_FRAMECHANGED))
'true'
`
  try {
    const { stdout } = await execFileAsync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encodePowerShell(script),
    ], { windowsHide: true, timeout: 8_000, maxBuffer: 64 * 1024 })
    return stdout.trim().endsWith('true')
  } catch { return false }
}
