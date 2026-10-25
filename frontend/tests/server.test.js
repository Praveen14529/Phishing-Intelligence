const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const { once } = require('node:events');
const test = require('node:test');

async function getFreePort() {
  const listener = net.createServer();
  listener.listen(0, '127.0.0.1');
  await once(listener, 'listening');
  const { port } = listener.address();
  await new Promise(resolve => listener.close(resolve));
  return port;
}

async function request(port, requestPath, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: requestPath, ...options }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve({
        status: response.statusCode,
        body: Buffer.concat(chunks).toString(),
      }));
    });
    req.on('error', reject);
    req.end(options.body);
  });
}

test('serves the dashboard and rejects paths outside the frontend root', async t => {
  const port = await getFreePort();
  const server = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
    env: { ...process.env, PORT: String(port) },
    stdio: 'ignore',
  });
  t.after(() => server.kill());

  let response;
  for (let attempt = 0; attempt < 30; attempt += 1) {
    try {
      response = await request(port, '/');
      break;
    } catch {
      await new Promise(resolve => setTimeout(resolve, 50));
    }
  }

  assert.equal(response.status, 200);
  assert.match(response.body, /PhishGuard/);
  assert.equal((await request(port, '/..%2f..%2fpackage.json')).status, 403);
});

test('forwards API requests to the configured backend', async t => {
  const backend = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ path: req.url, method: req.method }));
  });
  backend.listen(0, '127.0.0.1');
  await once(backend, 'listening');
  t.after(() => backend.close());

  const port = await getFreePort();
  const server = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
    env: {
      ...process.env,
      PORT: String(port),
      API_PROXY_TARGET: `http://127.0.0.1:${backend.address().port}`,
    },
    stdio: 'ignore',
  });
  t.after(() => server.kill());

  let response;
  for (let attempt = 0; attempt < 30; attempt += 1) {
    try {
      response = await request(port, '/api/v1/stats?range=7d');
      break;
    } catch {
      await new Promise(resolve => setTimeout(resolve, 50));
    }
  }

  assert.equal(response.status, 200);
  assert.deepEqual(JSON.parse(response.body), {
    path: '/api/v1/stats?range=7d',
    method: 'GET',
  });
});