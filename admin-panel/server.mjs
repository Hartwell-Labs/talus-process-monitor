// ── Talus Admin Panel — local server ──────────────────────────────────────
//
// Serves the UI on http://localhost:8787 and proxies admin API calls to the
// production worker. The ADMIN_TOKEN lives ONLY on this machine (file or env)
// — the browser never sees it, and the panel can be run anywhere.
//
//   node server.mjs                      # token from ~/.secrets/talus/admin_token
//   TALUS_ADMIN_TOKEN=xxx node server.mjs
//   TALUS_UPSTREAM=https://... node server.mjs
//
import http from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { join, extname, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.TALUS_PORT ?? 8787);
const HOST = process.env.TALUS_HOST ?? '127.0.0.1';
const UPSTREAM = process.env.TALUS_UPSTREAM ?? 'https://lic.hartwell-labs.pl';

// ── Admin token resolution (never logged, never sent to the browser) ──────
function load_token() {
  if (process.env.TALUS_ADMIN_TOKEN) return process.env.TALUS_ADMIN_TOKEN.trim();
  const candidates = [
    process.env.TALUS_ADMIN_TOKEN_FILE,
    join(__dirname, '.dev.vars'),
    join(process.env.HOME ?? '', '.secrets', 'talus', 'admin_token'),
  ].filter(Boolean);
  for (const p of candidates) {
    try {
      if (existsSync(p)) {
        return readFileSync(p, 'utf8').split(/\r?\n/)[0].trim();
      }
    } catch {
      /* ignore and continue */
    }
  }
  return null;
}

const ADMIN_TOKEN = load_token();
if (!ADMIN_TOKEN) {
  console.error('No admin token found. Set TALUS_ADMIN_TOKEN or create ~/.secrets/talus/admin_token');
  process.exit(1);
}

// ── Static UI ─────────────────────────────────────────────────────────────
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
};

function serve_static(res, name) {
  const path = join(__dirname, 'public', name);
  try {
    const data = readFileSync(path);
    res.writeHead(200, { 'content-type': MIME[extname(name)] ?? 'application/octet-stream' });
    res.end(data);
  } catch {
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
  }
}

// ── Proxy to the worker ───────────────────────────────────────────────────
const ALLOWED = new Set([
  '/api/v1/admin/stats',
  '/api/v1/admin/revoke',
  '/api/v1/admin/unrevoke',
  '/api/v1/admin/activations',
  '/api/v1/admin/free-seat',
  '/api/v1/health',
]);

async function proxy(req, res, pathname) {
  if (!ALLOWED.has(pathname)) {
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ success: false, message: 'unknown endpoint' }));
    return;
  }
  const body = await new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => resolve(data));
  });
  try {
    const upstream = await fetch(`${UPSTREAM}${pathname}`, {
      method: req.method,
      headers: {
        'content-type': 'application/json',
        ...(req.method === 'POST' || pathname.startsWith('/api/v1/admin/')
          ? { authorization: `Bearer ${ADMIN_TOKEN}` }
          : {}),
      },
      body: ['POST', 'PUT'].includes(req.method) && body ? body : undefined,
    });
    const text = await upstream.text();
    res.writeHead(upstream.status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(text);
  } catch (err) {
    res.writeHead(502, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ success: false, message: 'upstream unreachable' }));
  }
}

// ── Server ────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.pathname.startsWith('/api/')) {
    return proxy(req, res, url.pathname);
  }
  if (url.pathname === '/' || url.pathname === '/index.html') return serve_static(res, 'index.html');
  if (url.pathname === '/app.js') return serve_static(res, 'app.js');
  if (url.pathname === '/style.css') return serve_static(res, 'style.css');
  res.writeHead(404).end('not found');
});

server.listen(PORT, HOST, () => {
  console.log(`Talus admin panel:  http://${HOST}:${PORT}`);
  console.log(`Upstream:           ${UPSTREAM}`);
  console.log(`Admin token:        loaded (${ADMIN_TOKEN.length} chars) — stays on this machine`);
});
