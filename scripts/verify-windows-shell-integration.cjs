const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')

const root = path.join(__dirname, '..')
const mainProcess = fs.readFileSync(path.join(root, 'src', 'main', 'index.ts'), 'utf8')
const windowsHello = fs.readFileSync(path.join(root, 'src', 'main', 'windows-hello.ts'), 'utf8')

assert.match(mainProcess, /Menu\.setApplicationMenu\(null\)/)
assert.match(mainProcess, /START_IN_TRAY_ARGUMENT/)
assert.match(mainProcess, /openAsHidden:\s*true/)
assert.match(mainProcess, /if \(callbackUrl\)[\s\S]*?return/)
assert.match(windowsHello, /'-STA'/)
assert.doesNotMatch(windowsHello, /'-NonInteractive'/)
assert.match(windowsHello, /MakeGenericMethod\(\$resultType\)/)
assert.match(windowsHello, /IAsyncOperation`1/)

console.log('Windows shell integration verification passed.')
