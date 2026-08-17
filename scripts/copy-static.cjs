const fs = require('node:fs');
const path = require('node:path');

const rendererSource = path.join(__dirname, '..', 'src', 'renderer');
const rendererTarget = path.join(__dirname, '..', 'dist', 'renderer');
const assetsSource = path.join(__dirname, '..', 'assets');
const assetsTarget = path.join(__dirname, '..', 'dist', 'assets');

fs.mkdirSync(rendererTarget, { recursive: true });
for (const file of ['index.html', 'styles.css', 'float.html', 'float.css', 'float.js']) {
  fs.copyFileSync(path.join(rendererSource, file), path.join(rendererTarget, file));
}
fs.mkdirSync(assetsTarget, { recursive: true });
for (const file of ['logo.png', 'app.ico']) {
  fs.copyFileSync(path.join(assetsSource, file), path.join(assetsTarget, file));
}
