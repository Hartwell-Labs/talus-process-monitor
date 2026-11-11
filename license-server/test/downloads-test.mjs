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
