// ── downloads.js — R2-backed artifact distribution ────────────────────────
//
// Served on the custom domain download.hartwell-labs.pl by the same Worker as
// the license API, so both lines share one deployment and one secret store.
//
//   GET /                              landing page with both lines
//   GET /mit/<version>/<file>          public, cacheable, no license
//   GET /enterprise/<version>/<file>   requires X-Talus-License
//
// The R2 bucket is private. It has no public bucket domain: every byte goes
// through this handler, which is what makes the Enterprise line enforceable.
//
// Free-tier budget (R2: 10 GB storage, 1M Class A, 10M Class B per month):
//   • MIT responses are cached at the edge as immutable, so a repeat download
//     does not reach R2 and costs no Class B operation.
//   • Enterprise responses are never cached (a licensed binary must not be
//     served from a shared cache), so each Enterprise download is one Class B.
//   • Uploads are the only Class A traffic; there is no listing on this path.
//   • Objects are small (25 MB for Enterprise), so storage stays far below
//     10 GB unless every historical build is kept forever. The publish script
//     keeps only the current and previous version per line.

import { is_canonical, is_pretty, decode_pretty } from './format.js';
import { resolve_key } from './store-bridge.js';

const DOWNLOAD_HOST = 'download.hartwell-labs.pl';
const ALLOWED_LINES = new Set(['mit', 'enterprise']);
const MAX_LICENSE_LEN = 8192;
const MAX_KEY_LEN = 256;
// 8 GiB, leaving 2 GiB of 10 GiB headroom for manifests and in-flight uploads.
const MAX_STORAGE_BYTES = 8 * 1024 * 1024 * 1024;

// ── Release publishing (GitHub Actions OIDC) ──────────────────────────────
// Uploads are authenticated by the workflow's short-lived OIDC token, not by
// a Cloudflare API token stored in GitHub. That keeps R2 write credentials out
// of every repository and lets the release workflow publish as itself.
const PUBLISH_AUDIENCE = 'talus-downloads';
const PUBLISH_REPOS = new Set([
  'Hartwell-Labs/talus-process-monitor',
  'Hartwell-Labs/talus-enterprise',
]);
const OIDC_JWKS_URL = 'https://token.actions.githubusercontent.com/.well-known/jwks';
const MAX_ARTIFACT_BYTES = 100 * 1024 * 1024; // Workers request body ceiling
const VERSION_RE = /^[0-9]+\.[0-9]+\.[0-9]+$/;

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
    },
  });
}

function not_found() {
  return json({ success: false, message: 'not found' }, 404);
}

async function read_manifest(env, line) {
  const object = await env.DOWNLOADS.get(`${line}/index.json`);
  if (!object) return null;
  try {
    return JSON.parse(await object.text());
  } catch {
    return null;
  }
}

function escape_html(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

function latest_version(manifest) {
  const versions = manifest?.versions || [];
  return versions.length ? versions[versions.length - 1] : null;
}

function file_rows(line, entry) {
  if (!entry?.files?.length) return '<p class="empty">No artifacts published yet.</p>';
  return `<ul>${entry.files
    .map((file) => {
      const name = escape_html(file.name);
      const mb = (file.size / 1024 / 1024).toFixed(1);
      if (line === 'mit') {
        return `<li><a href="/mit/${encodeURIComponent(entry.version)}/${encodeURIComponent(
          file.name,
        )}">${name}</a> <span>${mb} MB</span></li>`;
      }
      return `<li><span class="file">${name}</span> <span>${mb} MB</span></li>`;
    })
    .join('')}</ul>`;
}

async function landing_page(env, ctx) {
  const [mit, enterprise] = await Promise.all([
    read_manifest(env, 'mit'),
    read_manifest(env, 'enterprise'),
  ]);
  const mit_latest = latest_version(mit);
  const enterprise_latest = latest_version(enterprise);

  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Talus downloads — MIT and Enterprise</title>
<style>
  :root { color-scheme: light dark; --bg:#0b1120; --card:#111c33; --text:#e6edf7; --dim:#94a3b8; --line:#1e2d4a; --accent:#7dd3fc; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--text); font:16px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif; }
  main { max-width: 860px; margin: 0 auto; padding: 48px 20px 72px; }
  h1 { font-size: 30px; letter-spacing:-.02em; margin:0 0 6px; }
  p.lead { color:var(--dim); margin:0 0 32px; }
  section { background:var(--card); border:1px solid var(--line); border-radius:14px; padding:22px 22px 18px; margin:0 0 18px; }
  h2 { font-size:19px; margin:0 0 4px; }
  .tag { display:inline-block; font-size:12px; letter-spacing:.08em; text-transform:uppercase; color:var(--accent); margin-bottom:8px; }
  ul { margin:12px 0 0; padding-left:18px; }
  li { margin:6px 0; }
  li span { color:var(--dim); font-size:13px; margin-left:8px; }
  a { color:var(--accent); text-decoration:none; }
  a:hover { text-decoration:underline; }
  code, pre { font-family: ui-monospace,SFMono-Regular,Menlo,monospace; font-size:13px; }
  pre { background:#08101f; border:1px solid var(--line); border-radius:10px; padding:12px 14px; overflow:auto; }
  .empty { color:var(--dim); }
  footer { color:var(--dim); font-size:13px; margin-top:28px; }
</style>
</head>
<body>
<main>
  <h1>Talus downloads</h1>
  <p class="lead">Two lines, one private bucket. MIT is public; Enterprise requires a live license.</p>

  <section>
    <span class="tag">Line 1 — MIT</span>
    <h2>Community edition${mit_latest ? ` · v${escape_html(mit_latest.version)}` : ''}</h2>
    <p class="empty">Public, immutable artifacts. Cached at the edge, so repeat downloads do not hit storage.</p>
    ${file_rows('mit', mit_latest)}
  </section>

  <section>
    <span class="tag">Line 2 — Enterprise</span>
    <h2>Licensed edition${enterprise_latest ? ` · v${escape_html(enterprise_latest.version)}` : ''}</h2>
    <p class="empty">Send your license in the <code>X-Talus-License</code> header. The key must exist in the license database, be unrevoked, unexpired and <code>tier = enterprise</code>.</p>
    ${file_rows('enterprise', enterprise_latest)}
    <pre>curl -fLO -H "X-Talus-License: $TALUS_LICENSE" \\
  https://download.hartwell-labs.pl/enterprise/${
    enterprise_latest ? encodeURIComponent(enterprise_latest.version) : '0.8.4'
  }/talus-monitor-enterprise</pre>
  </section>

  <footer>
    Talus is built by Hartwell Labs. MIT detection core ·
    <a href="https://wiki.hartwell-labs.pl/projects/talus-process-monitor/">documentation</a> ·
    <a href="https://github.com/Hartwell-Labs/talus-process-monitor">source</a>
  </footer>
</main>
</body>
</html>`;

  const response = new Response(html, {
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'public, max-age=300',
      'x-content-type-options': 'nosniff',
    },
  });
  if (ctx?.waitUntil && typeof caches !== 'undefined') {
    ctx.waitUntil(caches.default.put(new Request('https://download.hartwell-labs.pl/'), response.clone()));
  }
  return response;
}

/// Object keys are version/file paths. Reject anything that could escape the
/// line prefix or confuse a downstream cache.
function safe_key(key) {
  if (!key || key.length > MAX_KEY_LEN) return false;
  if (key.includes('..') || key.includes('\\') || key.includes('//')) return false;
  return /^[A-Za-z0-9._/-]+$/.test(key);
}

function filename_of(key) {
  return key.split('/').pop() || 'download';
}

async function authorize(env, raw_key) {
  // Cheap rejection first: a missing or oversized header must not touch the
  // database, and it must not report a server error just because DB is absent.
  if (!raw_key || raw_key.length > MAX_LICENSE_LEN) {
    return { ok: false, status: 401, message: 'missing or oversized X-Talus-License' };
  }
  if (!env.LICENSE_PUBLIC_KEYS) {
    return { ok: false, status: 500, message: 'server misconfigured: missing LICENSE_PUBLIC_KEYS' };
  }

  // Same key formats as activation: short store keys resolve to the canonical
  // signed form, native Talus keys are already canonical.
  let effective = raw_key.trim();
  if (!is_canonical(effective) && !is_pretty(effective)) {
    if (!env.DB) return { ok: false, status: 500, message: 'server misconfigured: missing DB' };
    const resolved = await resolve_key(env, effective);
    if (resolved.kind === 'unknown') {
      return { ok: false, status: 404, message: 'license not found' };
    }
    effective = resolved.license_key || effective;
  }

  if (is_pretty(effective)) {
    try {
      // decode_pretty needs a synchronous digest: the pretty-key checksum is
      // verified inline, and WebCrypto's digest is async-only.
      effective = decode_pretty(effective, sha256_hex_sync);
    } catch {
      return { ok: false, status: 400, message: 'invalid license key' };
    }
  }

  const parts = effective.split('.');
  if (parts.length !== 2) return { ok: false, status: 400, message: 'invalid license key' };

  let payload_bytes;
  let sig_bytes;
  try {
    payload_bytes = base64_decode(parts[0]);
    sig_bytes = base64_decode(parts[1]);
  } catch {
    return { ok: false, status: 400, message: 'invalid license encoding' };
  }
  if (sig_bytes.length !== 64) return { ok: false, status: 401, message: 'invalid signature' };

  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(payload_bytes));
  } catch {
    return { ok: false, status: 400, message: 'invalid license payload' };
  }

  const kid = payload.kid || 'v1';
  if (kid === 'test') return { ok: false, status: 401, message: 'invalid signature' };

  const keys = parse_public_keys(env.LICENSE_PUBLIC_KEYS);
  const hex = keys && keys[kid];
  if (!hex) return { ok: false, status: 401, message: 'unknown signing key' };

  let pub;
  try {
    pub = hex_decode(hex);
  } catch {
    return { ok: false, status: 500, message: 'server misconfigured: bad public key' };
  }

  if (!(await verify_ed25519(pub, sig_bytes, payload_bytes))) {
    return { ok: false, status: 401, message: 'invalid signature' };
  }

  const license_id = typeof payload.license_id === 'string' ? payload.license_id : '';
  const tier = typeof payload.tier === 'string' ? payload.tier : '';
  if (!license_id || !tier) {
    return { ok: false, status: 400, message: 'license payload missing fields' };
  }

  const expires_at = typeof payload.expires_at === 'string' ? payload.expires_at : '';
  if (expires_at && new Date(expires_at).getTime() <= Date.now()) {
    return { ok: false, status: 403, message: 'license expired' };
  }

  // "Exists" is a database fact, not just a valid signature: a refunded or
  // never-issued key must not download the licensed binary.
  if (!env.DB) return { ok: false, status: 500, message: 'server misconfigured: missing DB' };
  const row = await env.DB.prepare(
    'SELECT license_id, tier, revoked, expires_at FROM licenses WHERE license_id = ?1',
  )
    .bind(license_id)
    .first();

  if (!row) return { ok: false, status: 404, message: 'license not found' };
  if (row.revoked) return { ok: false, status: 403, message: 'license revoked' };
  if (row.expires_at && new Date(row.expires_at).getTime() <= Date.now()) {
    return { ok: false, status: 403, message: 'license expired' };
  }
  if (tier !== 'enterprise') {
    return { ok: false, status: 403, message: 'enterprise license required' };
  }

  return { ok: true, license_id, tier };
}

function range_for(request) {
  const raw = request.headers.get('range');
  if (!raw) return null;
  const match = /^bytes=(\d*)-(\d*)$/.exec(raw.trim());
  if (!match) return null;
  const start = match[1] === '' ? null : Number(match[1]);
  const end = match[2] === '' ? null : Number(match[2]);
  if (start === null && end === null) return null;
  if (start !== null && end !== null && end < start) return null;
  if (start === null) return { suffix: end };
  return { offset: start, length: end === null ? undefined : end - start + 1 };
}

export async function handle_download_request(request, env, ctx) {
  if (!env.DOWNLOADS) {
    return json({ success: false, message: 'server misconfigured: missing DOWNLOADS' }, 500);
  }

  const url = new URL(request.url);
  // `wrangler dev` rewrites the request URL to localhost, so local smoke tests
  // opt in explicitly. Production never sets this variable.
  const host_ok = url.hostname === DOWNLOAD_HOST || env.DOWNLOAD_DEV_ALLOW_ANY === '1';
  if (!host_ok) return not_found();

  if (url.pathname.startsWith('/publish/')) {
    return handle_publish(request, env, url);
  }

  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return json({ success: false, message: 'method not allowed' }, 405);
  }

  if (url.pathname === '/' || url.pathname === '/index.html') {
    return landing_page(env, ctx);
  }

  const parts = url.pathname.split('/').filter(Boolean);
  if (parts.length < 2) return not_found();

  const line = parts[0];
  if (!ALLOWED_LINES.has(line)) return not_found();

  const key = parts.slice(1).join('/');
  if (!safe_key(key)) return not_found();

  if (line === 'enterprise') {
    const auth = await authorize(env, request.headers.get('x-talus-license') || '');
    if (!auth.ok) return json({ success: false, message: auth.message }, auth.status);
  }

  // MIT is immutable and public: the edge cache removes repeat R2 reads, which
  // is the difference between a cache-friendly mirror and a Class B bill.
  const cache = typeof caches !== 'undefined' ? caches.default : null;
  if (line === 'mit' && request.method === 'GET' && cache) {
    const hit = await cache.match(request);
    if (hit) return hit;
  }

  const object_key = `${line}/${key}`;
  const range = range_for(request);
  let object;
  try {
    object =
      request.method === 'HEAD'
        ? await env.DOWNLOADS.head(object_key)
        : await env.DOWNLOADS.get(object_key, range ? { range } : undefined);
  } catch {
    return json({ success: false, message: 'storage unavailable' }, 503);
  }
  if (!object) return not_found();

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set('content-type', 'application/octet-stream');
  headers.set('content-disposition', `attachment; filename="${filename_of(key)}"`);
  headers.set('x-content-type-options', 'nosniff');
  headers.set('etag', object.httpEtag || '');
  headers.set('accept-ranges', 'bytes');

  const is_range = Boolean(range && object.range);
  if (is_range) {
    if (object.range.offset !== undefined && object.range.length !== undefined) {
      headers.set(
        'content-range',
        `bytes ${object.range.offset}-${object.range.offset + object.range.length - 1}/${object.size}`,
      );
    }
    headers.set('content-length', String(object.range.length ?? ''));
  } else {
    headers.set('content-length', String(object.size));
  }

  if (line === 'mit') {
    headers.set('cache-control', 'public, max-age=31536000, immutable');
  } else {
    // A licensed binary must never land in a shared cache.
    headers.set('cache-control', 'private, no-store');
  }

  const response = new Response(request.method === 'HEAD' ? null : object.body, {
    status: is_range ? 206 : 200,
    headers,
  });

  if (line === 'mit' && request.method === 'GET' && cache && ctx?.waitUntil) {
    ctx.waitUntil(cache.put(request, response.clone()));
  }
  return response;
}

// ── Release publishing ────────────────────────────────────────────────────

function base64url_decode(s) {
  let b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) b64 += '=';
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

let jwks_cache = { at: 0, keys: null };

async function github_jwks() {
  if (jwks_cache.keys && Date.now() - jwks_cache.at < 60 * 60 * 1000) return jwks_cache.keys;
  const res = await fetch(OIDC_JWKS_URL);
  if (!res.ok) throw new Error(`jwks ${res.status}`);
  const body = await res.json();
  jwks_cache = { at: Date.now(), keys: body.keys || [] };
  return jwks_cache.keys;
}

/// Verifies a GitHub Actions OIDC token and returns the claims, or null.
/// The repository, tag ref and audience checks below are the actual
/// authorization: a token from any other repo or branch cannot publish.
async function github_oidc_claims(request, version) {
  const auth = request.headers.get('authorization') || '';
  const match = /^Bearer\s+(.+)$/i.exec(auth);
  if (!match) return null;
  const parts = match[1].split('.');
  if (parts.length !== 3) return null;

  let header;
  let payload;
  try {
    header = JSON.parse(new TextDecoder().decode(base64url_decode(parts[0])));
    payload = JSON.parse(new TextDecoder().decode(base64url_decode(parts[1])));
  } catch {
    return null;
  }
  if (header.alg !== 'RS256' || !header.kid) return null;

  let jwk;
  try {
    jwk = (await github_jwks()).find((k) => k.kid === header.kid);
  } catch {
    return null;
  }
  if (!jwk) return null;

  let ok = false;
  try {
    const key = await crypto.subtle.importKey(
      'jwk',
      { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    );
    ok = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      key,
      base64url_decode(parts[2]),
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
    );
  } catch {
    return null;
  }
  if (!ok) return null;

  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.includes(PUBLISH_AUDIENCE)) return null;
  if (!PUBLISH_REPOS.has(payload.repository)) return null;
  if (payload.event_name !== 'release' && payload.event_name !== 'push') return null;
  // Only a tag matching the version being published may write that version.
  if (payload.ref !== `refs/tags/v${version}`) return null;
  if (typeof payload.exp !== 'number' || payload.exp * 1000 <= Date.now()) return null;

  return payload;
}

async function handle_publish(request, env, url) {
  // /publish/<line>/<version>/<file>   PUT one artifact
  // /publish/<line>/<version>/finalize POST publish the manifest
  const parts = url.pathname.split('/').filter(Boolean);
  if (parts.length < 4 || parts[0] !== 'publish') return not_found();

  const line = parts[1];
  const version = parts[2];
  const rest = parts.slice(3).join('/');
  if (!ALLOWED_LINES.has(line) || !VERSION_RE.test(version)) return not_found();

  const claims = await github_oidc_claims(request, version);
  if (!claims) return json({ success: false, message: 'unauthorized publisher' }, 401);

  if (rest === 'finalize') {
    if (request.method !== 'POST') return json({ success: false, message: 'method not allowed' }, 405);
    return finalize_release(env, line, version, request);
  }

  if (request.method !== 'PUT') return json({ success: false, message: 'method not allowed' }, 405);
  if (!safe_key(rest) || rest.includes('/')) return not_found();

  const declared = Number(request.headers.get('content-length') || 0);
  if (!request.body) return json({ success: false, message: 'empty body' }, 400);
  if (declared > MAX_ARTIFACT_BYTES) {
    return json({ success: false, message: 'artifact too large' }, 413);
  }

  try {
    await env.DOWNLOADS.put(`${line}/${version}/${rest}`, request.body, {
      httpMetadata: { contentType: 'application/octet-stream' },
      customMetadata: { repository: claims.repository, release: `v${version}` },
    });
  } catch (err) {
    return json({ success: false, message: `storage write failed: ${err.message}` }, 503);
  }

  return json({ success: true, line, version, file: rest });
}

async function finalize_release(env, line, version, request) {
  let body;
  try {
    body = await request_json_limited(request);
  } catch {
    return json({ success: false, message: 'invalid finalize payload' }, 400);
  }

  const names = Array.isArray(body?.files) ? body.files : [];
  if (!names.length || names.length > 32) {
    return json({ success: false, message: 'files[] required' }, 400);
  }

  const files = [];
  for (const item of names) {
    const name = typeof item === 'string' ? item : item?.name;
    if (typeof name !== 'string' || !safe_key(name) || name.includes('/')) {
      return json({ success: false, message: 'invalid file name' }, 400);
    }
    const object = await env.DOWNLOADS.head(`${line}/${version}/${name}`);
    if (!object) return json({ success: false, message: `missing upload: ${name}` }, 400);
    const entry = { name, size: object.size };
    const sha256 = typeof item?.sha256 === 'string' ? item.sha256 : '';
    if (/^[0-9a-f]{64}$/.test(sha256)) entry.sha256 = sha256;
    files.push(entry);
  }

  const manifest = (await read_manifest(env, line)) || { line, versions: [] };
  const versions = (manifest.versions || []).filter((v) => v.version !== version);
  versions.push({ version, published_at: new Date().toISOString(), files });

  // Retention keeps storage inside the free tier (and bounds the landing page).
  while (versions.length > 2) {
    const pruned = versions.shift();
    for (const file of pruned.files || []) {
      await env.DOWNLOADS.delete(`${line}/${pruned.version}/${file.name}`);
    }
  }

  const total = versions.reduce(
    (n, v) => n + (v.files || []).reduce((m, f) => m + (f.size || 0), 0),
    0,
  );
  if (total > MAX_STORAGE_BYTES) {
    return json({ success: false, message: 'storage budget exceeded' }, 507);
  }

  await env.DOWNLOADS.put(
    `${line}/index.json`,
    JSON.stringify({ line, versions }, null, 2),
    { httpMetadata: { contentType: 'application/json' } },
  );

  // The landing page is edge-cached for a few minutes; drop it on publish so
  // the new version is visible immediately.
  if (typeof caches !== 'undefined') {
    await caches.default.delete(new Request('https://download.hartwell-labs.pl/'));
  }

  return json({ success: true, line, version, versions: versions.map((v) => v.version) });
}

async function request_json_limited(request) {
  const text = await request.text();
  if (text.length > 16 * 1024) throw new Error('too large');
  return JSON.parse(text);
}

// ── Minimal verification helpers ──────────────────────────────────────────
// Kept local so the download path cannot accidentally inherit activation
// side effects (seat registration, rate-limit counters) from index.js.

function parse_public_keys(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const map = {};
  for (const pair of raw.split(',')) {
    const [kid, hex] = pair.split(':');
    if (kid && hex) map[kid.trim()] = hex.trim();
  }
  return Object.keys(map).length > 0 ? map : null;
}

function hex_decode(s) {
  if (!/^[0-9a-fA-F]+$/.test(s) || s.length % 2 !== 0) throw new Error('bad hex');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function base64_decode(s) {
  let b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) b64 += '=';
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function verify_ed25519(public_key, signature, data) {
  try {
    const key = await crypto.subtle.importKey('raw', public_key, { name: 'Ed25519' }, false, [
      'verify',
    ]);
    return await crypto.subtle.verify({ name: 'Ed25519' }, key, signature, data);
  } catch {
    return false;
  }
}

// ── Synchronous SHA-256 ───────────────────────────────────────────────────
// The pretty-key codec verifies its checksum in a synchronous function, so
// WebCrypto (async-only) cannot be used there. Small, self-contained, and
// used only for that checksum — the license signature itself is verified
// with WebCrypto below.
const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

function sha256_hex_sync(bytes) {
  const h = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ];
  const len = bytes.length;
  const padded = new Uint8Array((((len + 8) >> 6) + 1) << 6);
  padded.set(bytes);
  padded[len] = 0x80;
  const bits = len * 8;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 4, bits >>> 0);
  view.setUint32(padded.length - 8, Math.floor(bits / 2 ** 32));

  const w = new Uint32Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e;
      e = (d + t1) >>> 0;
      d = c; c = b; b = a;
      a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0;
    h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }
  return h.map((x) => x.toString(16).padStart(8, '0')).join('');
}

// Exported for the local tests; not part of the Worker API.
export const __test = {
  handle_download_request,
  handle_publish,
  github_oidc_claims,
  authorize,
  safe_key,
  range_for,
  MAX_STORAGE_BYTES,
};
