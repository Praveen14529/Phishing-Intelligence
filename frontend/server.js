const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

const root = path.join(__dirname, 'dist');
const staticRoot = fs.existsSync(root) ? root : __dirname;
const proxyTarget = new URL(process.env.API_PROXY_TARGET || 'http://127.0.0.1:8000');
const contentTypes = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
};

http.createServer((request, response) => {
  const requestUrl = new URL(request.url, 'http://localhost');

  if (requestUrl.pathname.startsWith('/api/')) {
    const proxyRequest = http.request(proxyTarget, {
      method: request.method,
      path: `${requestUrl.pathname}${requestUrl.search}`,
      headers: { ...request.headers, host: proxyTarget.host },
    }, proxyResponse => {
      response.writeHead(proxyResponse.statusCode || 502, proxyResponse.headers);
      proxyResponse.pipe(response);
    });
    proxyRequest.on('error', () => {
      response.writeHead(502, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ detail: 'Backend is unavailable' }));
    });
    request.pipe(proxyRequest);
    return;
  }

  if (request.method !== 'GET' && request.method !== 'HEAD') {
    response.writeHead(405, { allow: 'GET, HEAD' });
    response.end();
    return;
  }

  let pathname;
  try {
    pathname = decodeURIComponent(requestUrl.pathname);
  } catch {
    response.writeHead(400);
    response.end();
    return;
  }

  const filePath = path.resolve(staticRoot, `.${pathname}`);
  if (filePath !== staticRoot && !filePath.startsWith(`${staticRoot}${path.sep}`)) {
    response.writeHead(403);
    response.end();
    return;
  }

  const target = pathname.endsWith('/') ? path.join(filePath, 'index.html') : filePath;
  fs.readFile(target, (error, contents) => {
    if (error) {
      response.writeHead(404);
      response.end('Not found');
      return;
    }
    response.writeHead(200, {
      'content-type': contentTypes[path.extname(target)] || 'application/octet-stream',
    });
    response.end(request.method === 'HEAD' ? undefined : contents);
  });
}).listen(Number(process.env.PORT || 4200), '0.0.0.0');