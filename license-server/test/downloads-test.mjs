import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { handle_download_request, __test } from '../src/downloads.js';
import { to_pretty } from '../src/format.js';

function signed_license({ tier = 'enterprise', expires = '2099-01-01T00:00:00Z' } = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const payload = {
    kid: 'v2',
    license_id: 'TALUS-TEST-0001',
    tier,
    expires_at: expires,
  };
  const bytes = Buffer.from(JSON.stringify(payload));
  const sig = crypto.sign(null, bytes, privateKey);
  return {
    key: `${bytes.toString('base64')}.${sig.toString('base64')}`,
    pub_hex: raw.toString('hex'),
  };
}

function fake_env(license = null, pub_hex = '00') {
  const objects = new Map([
    [
      'mit/0.8.4/talus-monitor',
      {
        body: 'mit-binary',
        size: 10,
        httpEtag: '"abc"',
        writeHttpMetadata(headers) {
          headers.set('content-type', 'application/octet-stream');
        },
      },
    ],
    [
      'enterprise/0.8.4/talus-monitor-enterprise',
      {
        body: 'ent-binary',
        size: 10,
        httpEtag: '"def"',
        writeHttpMetadata(headers) {
          headers.set('content-type', 'application/octet-stream');
        },
      },
    ],
    [
      'mit/index.json',
      {
        async text() {
          return JSON.stringify({
            line: 'mit',
            versions: [
              { version: '0.8.4', notes: 'Security: Burst detection now skips /proc, /sys, /dev; per-PID state evicted after 10 min TTL.', files: [{ name: 'talus-monitor', size: 9190248 }] },
            ],
          });
        },
      },
    ],
    [
      'enterprise/index.json',
      {
        async text() {
          return JSON.stringify({
            line: 'enterprise',
            versions: [
              {
                version: '0.8.3',
                published_at: '2026-10-01T00:00:00Z',
                notes: 'Enterprise licensing system with Ed25519-signed binary, signature verification, and SBOM inclusion.',
                files: [{ name: 'talus-monitor-enterprise', size: 24900000 }],
              },
              {
                version: '0.8.4',
                published_at: '2026-11-11T00:00:00Z',
                files: [
                  { name: 'talus-monitor-enterprise', size: 24912840 },
                  { name: 'talus-monitor-enterprise.sig', size: 96 },
                ],
              },
            ],
          });
        },
      },
    ],
  ]);
  return {
    DOWNLOADS: {
      async get(key) {
        return objects.get(key) || null;
      },
      async head(key) {
        return objects.get(key) || null;
      },
    },
    DB: {
      prepare() {
        return {
          bind() {
            return {
              async first() {
                return license;
              },
            };
          },
        };
      },
    },
    LICENSE_PUBLIC_KEYS: `v2:${pub_hex}`,
  };
}

const base = 'https://download.hartwell-labs.pl';

test('safe_key rejects traversal and empty keys', () => {
  assert.equal(__test.safe_key('0.8.4/talus-monitor'), true);
  assert.equal(__test.safe_key('../etc/passwd'), false);
  assert.equal(__test.safe_key('0.8.4/../../x'), false);
  assert.equal(__test.safe_key('a//b'), false);
  assert.equal(__test.safe_key(''), false);
  assert.equal(__test.safe_key('a b'), false);
});

test('MIT download is public, immutable, and streamed', async () => {
  const res = await handle_download_request(
    new Request(`${base}/mit/0.8.4/talus-monitor`),
    fake_env(),
  );
  assert.equal(res.status, 200);
  assert.equal(await res.text(), 'mit-binary');
  assert.match(res.headers.get('cache-control'), /immutable/);
  assert.equal(res.headers.get('content-disposition'), 'attachment; filename="talus-monitor"');
});

test('unknown MIT object is 404', async () => {
  const res = await handle_download_request(
    new Request(`${base}/mit/0.8.4/nope`),
    fake_env(),
  );
  assert.equal(res.status, 404);
});

test('Enterprise without a license never reaches storage', async () => {
  const res = await handle_download_request(
    new Request(`${base}/enterprise/0.8.4/talus-monitor-enterprise`),
    fake_env(),
  );
  assert.equal(res.status, 401);
  assert.match(await res.text(), /X-Talus-License/);
});

test('Enterprise with a forged key is rejected before storage', async () => {
  const res = await handle_download_request(
    new Request(`${base}/enterprise/0.8.4/talus-monitor-enterprise`, {
      headers: { 'x-talus-license': 'eyJsaWNlbnNlX2lkIjoieCJ9.AAAA' },
    }),
    fake_env(),
  );
  assert.equal(res.status, 401);
});

test('valid Enterprise license streams with no-store', async () => {
  const signed = signed_license();
  const env = fake_env(
    { license_id: 'TALUS-TEST-0001', tier: 'enterprise', revoked: 0, expires_at: null },
    signed.pub_hex,
  );
  const res = await handle_download_request(
    new Request(`${base}/enterprise/0.8.4/talus-monitor-enterprise`, {
      headers: { 'x-talus-license': signed.key },
    }),
    env,
  );
  assert.equal(res.status, 200);
  assert.equal(await res.text(), 'ent-binary');
  assert.equal(res.headers.get('cache-control'), 'private, no-store');
});

test('a signed community license cannot download Enterprise', async () => {
  const signed = signed_license({ tier: 'community' });
  const env = fake_env(
    { license_id: 'TALUS-TEST-0001', tier: 'community', revoked: 0, expires_at: null },
    signed.pub_hex,
  );
  const res = await handle_download_request(
    new Request(`${base}/enterprise/0.8.4/talus-monitor-enterprise`, {
      headers: { 'x-talus-license': signed.key },
    }),
    env,
  );
  assert.equal(res.status, 403);
  assert.match(await res.text(), /enterprise license required/);
});

test('a valid key with no database row is not a license', async () => {
  const signed = signed_license();
  const res = await handle_download_request(
    new Request(`${base}/enterprise/0.8.4/talus-monitor-enterprise`, {
      headers: { 'x-talus-license': signed.key },
    }),
    fake_env(null, signed.pub_hex),
  );
  assert.equal(res.status, 404);
  assert.match(await res.text(), /license not found/);
});

 test('pretty (customer-facing) keys are accepted', async () => {
  const signed = signed_license();
  const sha = async (bytes) =>
    [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))]
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  const pretty = await to_pretty(signed.key, sha);
  const env = fake_env(
    { license_id: 'TALUS-TEST-0001', tier: 'enterprise', revoked: 0, expires_at: null },
    signed.pub_hex,
  );
  const res = await handle_download_request(
    new Request(`${base}/enterprise/0.8.4/talus-monitor-enterprise`, {
      headers: { 'x-talus-license': pretty },
    }),
    env,
  );
  assert.equal(res.status, 200);
});

test('landing page lists both lines with the latest versions', async () => {
  const res = await handle_download_request(new Request(`${base}/`), fake_env());
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /Line 1 — MIT/);
  assert.match(html, /Line 2 — Enterprise/);
  assert.match(html, /\/mit\/0\.8\.4\/talus-monitor/);
  assert.match(html, /talus-monitor-enterprise/);
  // The licensed binary is described, never linked without a license header.
  assert.doesNotMatch(html, /href="\/enterprise\//);
  // The configurator is not a Talus line: it links straight at its GitHub
  // release asset and is never served from this host (no R2 copy).
  assert.match(html, /id="configurator"/);
  assert.match(html, /This is not Talus\./);
  assert.match(
    html,
    /https:\/\/github\.com\/Hartwell-Labs\/Configurator-For-Talus\/releases\/latest\/download\/talus-config/,
  );
  assert.doesNotMatch(html, /href="\/[^"]*talus-config/);
  // The history is newest first and licensed files use the key-aware button.
  assert.ok(html.indexOf('v0.8.4') < html.indexOf('v0.8.3'));
  assert.match(html, /button class="dl" type="button" data-version="0\.8\.4"/);
  assert.match(html, /Latest/);
  // The release picker is still there: one release visible at a time.
  assert.match(html, /<select id="release-enterprise"[^>]*>/);
  assert.match(html, /data-release-version="0\.8\.3" hidden/);
  // Every version gets its own file table, right under that version's header.
  assert.equal((html.match(/<table class="files-table">/g) || []).length, 3);
  assert.match(html, /<th>File<\/th><th>Size<\/th><th><\/th>/);
  assert.match(
    html,
    /data-release-version="0\.8\.4">\s*<div class="release-head">[\s\S]*?<table class="files-table">/,
  );
  // Changes are their own table per version: change, file, description.
  assert.equal((html.match(/<table class="changes-table">/g) || []).length, 3);
  assert.equal(
    (html.match(/<th>Change<\/th><th>File \/ subfolder<\/th><th>Description<\/th>/g) || [])
      .length,
    3,
  );
  assert.doesNotMatch(html, /class="release-notes"/);
  assert.ok(
    html.indexOf('data-release-version="0.8.3"') <
      html.indexOf('Enterprise licensing system with Ed25519'),
  );
  assert.match(html, /<td class="c-name">v0\.8\.3<\/td>/);
  assert.match(html, /<td class="c-file">mit\/0\.8\.4\/<\/td>/);
  assert.match(html, /<td class="c-file">enterprise\/0\.8\.4\/<\/td>/);
  // No second, detached table block at the bottom of the card.
  assert.doesNotMatch(html, /data-tables=/);
  assert.ok(html.indexOf('<table class="files-table">') < html.indexOf('Source ↗'));
  assert.match(html, /data-version="0\.8\.3" data-file="talus-monitor-enterprise"/);
  assert.match(html, /data-version="0\.8\.4" data-file="talus-monitor-enterprise\.sig"/);
  assert.match(html, /talus-monitor-enterprise\.sig<\/td>/);
  // Small verification files get a real unit instead of a rounded-down 0.0 MB.
  assert.match(html, /96 B/);
  assert.doesNotMatch(html, />0\.0 MB</);

  // The inline downloader must at least parse: a broken script would leave
  // the Enterprise buttons doing nothing in the browser.
  const script = html.match(/<script>([\s\S]*)<\/script>/)?.[1];
  assert.ok(script);
  assert.doesNotThrow(() => new Function(script));
});

test('a newest-first manifest still reports the real latest release', async () => {
  const env = {
    ...fake_env(),
    DOWNLOADS: {
      async get(key) {
        if (key !== 'mit/index.json') return null;
        return {
          async text() {
            return JSON.stringify({
              line: 'mit',
              versions: [
                { version: '0.9.0', files: [{ name: 'talus-monitor', size: 10 }] },
                { version: '0.8.4', files: [{ name: 'talus-monitor', size: 10 }] },
              ],
            });
          },
        };
      },
      async head() {
        return null;
      },
    },
  };
  const res = await handle_download_request(new Request(`${base}/`), env);
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /Community edition · v0\.9\.0/);
  assert.ok(html.indexOf('v0.9.0') < html.indexOf('v0.8.4'));
});

test('structured changes render one row per change', async () => {
  const env = {
    ...fake_env(),
    DOWNLOADS: {
      async get(key) {
        if (key !== 'mit/index.json') return null;
        return {
          async text() {
            return JSON.stringify({
              line: 'mit',
              versions: [
                {
                  version: '0.9.0',
                  files: [{ name: 'talus-monitor', size: 10 }],
                  changes: [
                    {
                      name: 'Burst detection',
                      file: 'src/monitor.rs',
                      description: 'Skips /proc, /sys and /dev in the alert window.',
                    },
                    {
                      name: 'Retention',
                      file: 'license-server/scripts/r2-publish.sh',
                      description: 'Keeps five versions per line.',
                    },
                  ],
                },
              ],
            });
          },
        };
      },
      async head() {
        return null;
      },
    },
  };
  const res = await handle_download_request(new Request(`${base}/`), env);
  assert.equal(res.status, 200);
  const html = await res.text();
  const table = html.match(/<table class="changes-table">([\s\S]*?)<\/table>/)?.[1];
  assert.ok(table);
  assert.equal((table.match(/<tr[>]/g) || []).length, 3); // head row + two changes, no fallback
  assert.match(table, /Burst detection/);
  assert.match(table, /src\/monitor\.rs/);
  assert.match(table, /Keeps five versions per line\./);
  assert.doesNotMatch(table, /class="c-name">v0\.9\.0/);
});

test('landing page still renders when a manifest is missing', async () => {
  const env = {
    ...fake_env(),
    DOWNLOADS: {
      async get() {
        return null;
      },
      async head() {
        return null;
      },
    },
  };
  const res = await handle_download_request(new Request(`${base}/`), env);
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /No releases published yet\./);
  assert.doesNotMatch(html, /undefined/);
});

test('publishing requires a GitHub OIDC bearer token', async () => {
  const put = await handle_download_request(
    new Request(`${base}/publish/mit/0.8.4/talus-monitor`, { method: 'PUT', body: 'x' }),
    fake_env(),
  );
  assert.equal(put.status, 401);

  const finalize = await handle_download_request(
    new Request(`${base}/publish/mit/0.8.4/finalize`, { method: 'POST', body: '{}' }),
    fake_env(),
  );
  assert.equal(finalize.status, 401);

  // A forged token must not be treated as a valid workflow identity.
  const forged = await handle_download_request(
    new Request(`${base}/publish/mit/0.8.4/talus-monitor`, {
      method: 'PUT',
      body: 'x',
      headers: { authorization: 'Bearer a.b.c' },
    }),
    fake_env(),
  );
  assert.equal(forged.status, 401);
});

function oidc_token(claims, { kid = 'test-kid' } = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' });
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const header = encode({ alg: 'RS256', kid });
  const payload = encode(claims);
  const signature = crypto.sign('RSA-SHA256', Buffer.from(`${header}.${payload}`), privateKey);
  return {
    token: `${header}.${payload}.${signature.toString('base64url')}`,
    jwks: { keys: [{ ...jwk, kid, alg: 'RS256', use: 'sig' }] },
  };
}

test('GitHub OIDC token is accepted only for an allowed repo and matching tag', async () => {
  const now = Math.floor(Date.now() / 1000);
  const base_claims = {
    aud: 'talus-downloads',
    repository: 'Hartwell-Labs/talus-process-monitor',
    event_name: 'push',
    ref: 'refs/tags/v9.9.9',
    exp: now + 300,
  };
  const { token, jwks } = oidc_token(base_claims);

  const original_fetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url).includes('jwks')) return new Response(JSON.stringify(jwks));
    throw new Error('unexpected fetch');
  };
  try {
    const req = new Request(`${base}/publish/mit/9.9.9/talus-monitor`, {
      headers: { authorization: `Bearer ${token}` },
    });
    const claims = await __test.github_oidc_claims(req, '9.9.9');
    assert.equal(claims?.repository, 'Hartwell-Labs/talus-process-monitor');

    // A different tag, repository or audience must be rejected even with a
    // valid signature from GitHub.
    assert.equal(await __test.github_oidc_claims(req, '9.9.8'), null);

    const other = oidc_token({ ...base_claims, repository: 'someone/else' });
    globalThis.fetch = async () => new Response(JSON.stringify(other.jwks));
    const other_req = new Request(`${base}/publish/mit/9.9.9/talus-monitor`, {
      headers: { authorization: `Bearer ${other.token}` },
    });
    assert.equal(await __test.github_oidc_claims(other_req, '9.9.9'), null);
  } finally {
    globalThis.fetch = original_fetch;
  }
});

test('unknown host and non-GET methods are refused', async () => {
  const wrong = await handle_download_request(
    new Request('https://lic.hartwell-labs.pl/mit/0.8.4/talus-monitor'),
    fake_env(),
  );
  assert.equal(wrong.status, 404);

  const post = await handle_download_request(
    new Request(`${base}/mit/0.8.4/talus-monitor`, { method: 'POST' }),
    fake_env(),
  );
  assert.equal(post.status, 405);
});

test('range parsing handles open, closed, and suffix ranges', () => {
  const req = (value) => new Request(`${base}/mit/x`, { headers: { range: value } });
  assert.deepEqual(__test.range_for(req('bytes=0-9')), { offset: 0, length: 10 });
  assert.deepEqual(__test.range_for(req('bytes=10-')), { offset: 10, length: undefined });
  assert.deepEqual(__test.range_for(req('bytes=-5')), { suffix: 5 });
  assert.equal(__test.range_for(req('bytes=9-0')), null);
  assert.equal(__test.range_for(req('nonsense')), null);
});
