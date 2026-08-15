const assert = require('node:assert/strict');
const http = require('node:http');
const { NativeSsoService } = require('../dist/main/native-sso.js');

function startServer() {
  return new Promise((resolve) => {
    const server = http.createServer((request, response) => {
      request.resume();
      request.on('end', () => {
        response.setHeader('Content-Type', 'application/json');
        response.end(JSON.stringify({
          error: 'unsupported_grant_type',
          error_description: 'grant_type: urn:ietf:params:oauth:grant-type:token-exchange is not supported in this application',
        }));
      });
    });
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      resolve({ server, endpoint: `http://127.0.0.1:${address.port}` });
    });
  });
}

async function main() {
  const fake = await startServer();
  const service = new NativeSsoService({
    endpoint: fake.endpoint,
    preferredPort: 0,
    session: {
      accessToken: 'access-token',
      deviceSecret: 'device-secret',
      userName: 'Developer',
      displayName: 'Developer',
      avatar: '',
    },
    approve: async () => true,
  });

  try {
    const port = await service.start();
    const response = await fetch(`http://127.0.0.1:${port}/native-sso/authorize`, {
      method: 'POST',
      headers: { Origin: fake.endpoint, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        serverUrl: fake.endpoint,
        clientId: 'target-client',
        scope: 'openid device_sso',
      }),
    });
    const body = await response.json();
    assert.equal(body.status, 'denied');
    assert.match(body.message, /网页应用尚未启用设备登录授权/);
    assert.doesNotMatch(body.message, /target-client|Token Exchange/);
    console.log('Unsupported grant configuration diagnostic check passed.');
  } finally {
    await service.stop();
    await new Promise((resolve) => fake.server.close(resolve));
  }
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
