const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = (...parts) => fs.readFileSync(path.join(root, ...parts), 'utf8');

const main = read('src', 'main', 'index.ts');
const identityClient = read('src', 'main', 'identity-client.ts');
const preload = read('src', 'preload', 'index.ts');
const renderer = read('src', 'renderer', 'index.ts');
const html = read('src', 'renderer', 'index.html');
const workflow = read('.github', 'workflows', 'windows-release.yml');

assert.match(main, /code_challenge_method: 'S256'/);
assert.match(main, /store\.preferences\.loginMode === 'browser'/);
assert.match(main, /shell\.openExternal\(url\)/);
assert.match(main, /function createAuthWindow\(url: string\)/);
assert.match(main, /codeVerifier = createPkceVerifier\(\)/);
assert.match(identityClient, /code_verifier: codeVerifier/);
assert.doesNotMatch(identityClient, /clientSecret/);
assert.doesNotMatch(identityClient, /client_secret/);
assert.doesNotMatch(preload, /clientSecret/);
assert.doesNotMatch(renderer, /clientSecret|hasClientSecret/);
assert.doesNotMatch(html, /tenant-client-secret/);
assert.match(html, /id="public-network-password" type="password"/);
assert.doesNotMatch(workflow, /secrets\.|CLIENT_SECRET|client-secret/i);

function startTokenEndpoint() {
  return new Promise((resolve, reject) => {
    const server = http.createServer((request, response) => {
      if (request.method !== 'POST' || request.url !== '/api/login/oauth/access_token') {
        response.statusCode = 404;
        response.end();
        return;
      }
      let body = '';
      request.on('data', (chunk) => { body += chunk; });
      request.on('end', () => {
        try {
          const payload = JSON.parse(body);
          assert.deepEqual(payload, {
            client_id: 'public-native-client',
            grant_type: 'authorization_code',
            code: 'authorization-code',
            code_verifier: 'one-time-pkce-verifier',
          });
          assert.equal(Object.hasOwn(payload, 'client_secret'), false);
          response.setHeader('Content-Type', 'application/json');
          response.end(JSON.stringify({ access_token: 'test-access-token' }));
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

async function mainTest() {
  const fake = await startTokenEndpoint();
  try {
    const { IdentityClient } = require('../dist/main/identity-client.js');
    const client = new IdentityClient({
      endpoint: fake.endpoint,
      clientId: 'public-native-client',
      certificate: 'unused-in-token-request-test',
    });
    const tokens = await client.getAuthToken('authorization-code', 'one-time-pkce-verifier');
    assert.equal(tokens.access_token, 'test-access-token');
    console.log('Public native-client and PKCE verification passed.');
  } finally {
    await new Promise((resolve) => fake.server.close(resolve));
  }
}

mainTest().catch((error) => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
