const assert = require('node:assert/strict');
const http = require('node:http');
const { NativeSsoService } = require('../dist/main/native-sso.js');

function startFakeIdentityService() {
  return new Promise((resolve, reject) => {
    const server = http.createServer((request, response) => {
      if (request.method !== 'POST' || new URL(request.url, 'http://127.0.0.1').pathname !== '/api/login/oauth/access_token') {
        response.statusCode = 404;
        response.end();
        return;
      }
      request.resume();
      request.on('end', () => {
        const params = new URL(request.url, 'http://127.0.0.1').searchParams;
        try {
          assert.equal(params.get('client_id'), 'target-client');
          assert.equal(params.get('grant_type'), 'urn:ietf:params:oauth:grant-type:token-exchange');
          assert.equal(params.get('subject_token'), 'desktop-access-token');
          assert.equal(params.get('subject_token_type'), 'urn:ietf:params:oauth:token-type:access_token');
          assert.equal(params.get('actor_token'), 'native-device-secret');
          assert.equal(params.get('actor_token_type'), 'urn:openid:params:token-type:device-secret');
          assert.ok(params.get('scope').split(' ').includes('device_sso'));
          response.setHeader('Content-Type', 'application/json');
          response.end(JSON.stringify({ access_token: 'native-sso-token' }));
        } catch (error) {
          response.statusCode = 500;
          response.end(JSON.stringify({ error: error.message }));
        }
      });
    });
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      resolve({ server, endpoint: `http://127.0.0.1:${address.port}` });
    });
  });
}

async function main() {
  const fake = await startFakeIdentityService();
  let approvals = 0;
  const service = new NativeSsoService({
    endpoint: fake.endpoint,
    preferredPort: 0,
    session: {
      accessToken: 'desktop-access-token',
      deviceSecret: 'native-device-secret',
      userName: 'Developer',
      displayName: 'Developer',
      avatar: '',
    },
    approve: async () => {
      approvals += 1;
      return true;
    },
  });

  try {
    const port = await service.start();
    const originHeaders = { Origin: fake.endpoint };
    const status = await fetch(`http://127.0.0.1:${port}/native-sso/status?serverUrl=${encodeURIComponent(fake.endpoint)}&clientId=target-client`, { headers: originHeaders });
    const statusBody = await status.json();
    assert.equal(statusBody.available, true);
    assert.equal(statusBody.userName, 'Developer');

    const authorize = await fetch(`http://127.0.0.1:${port}/native-sso/authorize`, {
      method: 'POST',
      headers: { ...originHeaders, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        serverUrl: fake.endpoint,
        clientId: 'target-client',
        applicationName: 'Target App',
        responseType: 'code',
        redirectUri: 'https://target.example/callback',
        scope: 'openid profile email',
        state: 'state-value',
        codeChallenge: 'pkce-value',
      }),
    });
    const authorizeBody = await authorize.json();
    assert.equal(authorizeBody.status, 'approved');
    assert.equal(authorizeBody.accessToken, 'native-sso-token');
    assert.equal(approvals, 1);
    console.log('Native SSO protocol compatibility check passed.');
  } finally {
    await service.stop();
    await new Promise((resolve) => fake.server.close(resolve));
  }
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
