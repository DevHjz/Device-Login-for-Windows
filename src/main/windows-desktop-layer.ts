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
 * 将状态窗置于 Explorer 桌面宿主层，而非普通应用的置顶层。
 * 优先选取承载壁纸的 WorkerW；该层会在 Win+D 后保留，但普通应用窗口仍位于其上方。
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
  public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
  [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr FindWindow(string className, string windowName);
  [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr FindWindowEx(IntPtr parent, IntPtr childAfter, string className, string windowName);
  [DllImport("user32.dll", SetLastError=true)]
  public static extern bool EnumWindows(EnumWindowsProc callback, IntPtr lParam);
  [DllImport("user32.dll", SetLastError=true)]
  public static extern IntPtr SendMessage(IntPtr hWnd, uint message, IntPtr wParam, IntPtr lParam);
  [DllImport("user32.dll", SetLastError=true)]
  public static extern IntPtr SetParent(IntPtr hWndChild, IntPtr hWndNewParent);
  [DllImport("user32.dll", EntryPoint="GetWindowLongPtrW", SetLastError=true)]
  public static extern IntPtr GetWindowLongPtr(IntPtr hWnd, int nIndex);
  [DllImport("user32.dll", EntryPoint="SetWindowLongPtrW", SetLastError=true)]
  public static extern IntPtr SetWindowLongPtr(IntPtr hWnd, int nIndex, IntPtr dwNewLong);
  [DllImport("user32.dll", SetLastError=true)]
  public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int x, int y, int cx, int cy, uint flags);
  [DllImport("user32.dll", SetLastError=true)]
  public static extern bool ShowWindowAsync(IntPtr hWnd, int command);

  public static IntPtr FindDesktopHost() {
    IntPtr progman = FindWindow("Progman", null);
    if (progman == IntPtr.Zero) return IntPtr.Zero;
    // Explorer 支持此未公开消息来确保 WorkerW 桌面宿主存在。
    SendMessage(progman, 0x052C, IntPtr.Zero, IntPtr.Zero);
    IntPtr worker = IntPtr.Zero;
    EnumWindows(delegate(IntPtr topLevel, IntPtr ignored) {
      IntPtr view = FindWindowEx(topLevel, IntPtr.Zero, "SHELLDLL_DefView", null);
      if (view != IntPtr.Zero) {
        worker = FindWindowEx(IntPtr.Zero, topLevel, "WorkerW", null);
        return false;
      }
      return true;
    }, IntPtr.Zero);
    return worker != IntPtr.Zero ? worker : progman;
  }
}
'@
$GWL_STYLE = -16
$WS_CHILD = 0x40000000
$WS_POPUP = [int]0x80000000
$HWND_TOP = [IntPtr]::Zero
$SW_SHOWNOACTIVATE = 4
$SWP_NOSIZE = 0x0001
$SWP_NOMOVE = 0x0002
$SWP_NOACTIVATE = 0x0010
$SWP_FRAMECHANGED = 0x0020
$floatWindow = [IntPtr]::new([Int64]::Parse('${nativeHandle}'))
$desktopHost = [CloudVerifyDesktopLayer]::FindDesktopHost()
if ($floatWindow -eq [IntPtr]::Zero -or $desktopHost -eq [IntPtr]::Zero) { 'false'; exit 0 }
$style = [CloudVerifyDesktopLayer]::GetWindowLongPtr($floatWindow, $GWL_STYLE).ToInt64()
$newStyle = (($style -bor $WS_CHILD) -band (-bnot $WS_POPUP))
[void][CloudVerifyDesktopLayer]::SetWindowLongPtr($floatWindow, $GWL_STYLE, [IntPtr]::new($newStyle))
[void][CloudVerifyDesktopLayer]::SetParent($floatWindow, $desktopHost)
[void][CloudVerifyDesktopLayer]::SetWindowPos($floatWindow, $HWND_TOP, 0, 0, 0, 0, ($SWP_NOMOVE -bor $SWP_NOSIZE -bor $SWP_NOACTIVATE -bor $SWP_FRAMECHANGED))
[void][CloudVerifyDesktopLayer]::ShowWindowAsync($floatWindow, $SW_SHOWNOACTIVATE)
'true'
`
  try {
    const { stdout } = await execFileAsync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encodePowerShell(script),
    ], { windowsHide: true, timeout: 8_000, maxBuffer: 64 * 1024 })
    return stdout.trim().endsWith('true')
  } catch { return false }
}


/** 检测 Explorer 的 Progman/WorkerW 桌面宿主是否已恢复。 */
export async function isDesktopHostAvailable(): Promise<boolean> {
  if (process.platform !== 'win32') return false
  const script = `
$explorer = @(Get-Process -Name explorer -ErrorAction SilentlyContinue)
if ($explorer.Count -eq 0) { 'false'; exit 0 }
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class CloudVerifyDesktopProbe {
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr FindWindow(string className, string windowName);
}
'@
if ([CloudVerifyDesktopProbe]::FindWindow('Progman', $null) -ne [IntPtr]::Zero) { 'true' } else { 'false' }
`
  try {
    const { stdout } = await execFileAsync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encodePowerShell(script),
    ], { windowsHide: true, timeout: 5_000, maxBuffer: 8 * 1024 })
    return stdout.trim().endsWith('true')
  } catch { return false }
}
