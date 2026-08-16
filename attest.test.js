import assert from 'node:assert/strict';
import test from 'node:test';
import { handleVerify, signAttestation, safeEqual, EXPECTED_PACKAGE } from './src/attest.js';
import { handleAdmin } from './src/admin.js';
import { rateLimit, _reset } from './src/rate-limit.js';

/** In-memory KV stand-in so tests run without Cloudflare bindings. */
const makeKv = () => {
    const map = new Map();
    return {
        async get(key) { return map.get(key) ?? null; },
        async put(key, value) { map.set(key, value); },
        async delete(key) { map.delete(key); },
        async list({ prefix, limit }) {
            const keys = [...map.keys()].filter(k => k.startsWith(prefix)).slice(0, limit ?? Infinity);
            return { keys: keys.map(name => ({ name })) };
        },
        _map: map
    };
};

const makeEnv = (overrides = {}) => ({
    BAILEY_KV: makeKv(),
    ATTEST_SECRET: 'test-secret',
    ADMIN_TOKEN: 'test-admin-token',
    ...overrides
});

const post = (path, body, env, headers = {}) => {
    const request = new Request(`https://bailey.crysnovax.link${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...headers },
        body: JSON.stringify(body)
    });
    return request;
};

const VALID_FP = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718';

test('genuine install gets a signed genuine attestation', async () => {
    const env = makeEnv();
    const res = await handleVerify(post('/api/v1/verify', {
        package: EXPECTED_PACKAGE, version: '2.7.5', fingerprint: VALID_FP
    }), env);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, 'genuine');
    assert.equal(body.fingerprint, VALID_FP);
    assert.ok(body.exp > body.iat);
    assert.equal(typeof body.sig, 'string');
    // signature is deterministic over the canonical payload
    const reSigned = await signAttestation({ status: 'genuine', fingerprint: VALID_FP, iat: body.iat, exp: body.exp }, 'test-secret');
    assert.equal(reSigned.sig, body.sig);
});

test('rebranded package is denied as rebranded', async () => {
    const env = makeEnv();
    const res = await handleVerify(post('/api/v1/verify', {
        package: '@sneaky/fork', version: '1.0.0', fingerprint: VALID_FP
    }), env);
    const body = await res.json();
    assert.equal(body.status, 'rebranded');
});

test('revoked fingerprint is denied', async () => {
    const env = makeEnv();
    const res = await handleVerify(post('/api/v1/verify', {
        package: EXPECTED_PACKAGE, version: '2.7.5', fingerprint: VALID_FP
    }), env);
    assert.equal((await res.json()).status, 'genuine');

    // revoke via admin
    const revokeRes = await handleAdmin(post('/api/v1/admin/revoke', { fingerprint: VALID_FP, reason: 'rebranded' }, env, { Authorization: 'Bearer test-admin-token' }), env, new URL('https://x/api/v1/admin/revoke'));
    assert.equal((await revokeRes.json()).revoked, true);

    // now the client is denied
    const res2 = await handleVerify(post('/api/v1/verify', {
        package: EXPECTED_PACKAGE, version: '2.7.5', fingerprint: VALID_FP
    }), env);
    assert.equal((await res2.json()).status, 'revoked');
});

test('admin API rejects missing or wrong tokens', async () => {
    const env = makeEnv();
    const noToken = await handleAdmin(post('/api/v1/admin/revoke', { fingerprint: VALID_FP }), env, new URL('https://x/api/v1/admin/revoke'));
    assert.equal(noToken.status, 401);
    const badToken = await handleAdmin(
        post('/api/v1/admin/revoke', { fingerprint: VALID_FP }, env, { Authorization: 'Bearer wrong' }),
        env,
        new URL('https://x/api/v1/admin/revoke')
    );
    assert.equal(badToken.status, 401);
});

test('owner fingerprints are always genuine even when revoked', async () => {
    const env = makeEnv({ OWNER_FINGERPRINTS: VALID_FP });
    await handleAdmin(post('/api/v1/admin/revoke', { fingerprint: VALID_FP }, env, { Authorization: 'Bearer test-admin-token' }), env, new URL('https://x/api/v1/admin/revoke'));
    const res = await handleVerify(post('/api/v1/verify', { package: EXPECTED_PACKAGE, version: '2.7.5', fingerprint: VALID_FP }), env);
    assert.equal((await res.json()).status, 'genuine');
});

test('admin unrevoke restores genuine status', async () => {
    const env = makeEnv();
    await handleAdmin(post('/api/v1/admin/revoke', { fingerprint: VALID_FP }, env, { Authorization: 'Bearer test-admin-token' }), env, new URL('https://x/api/v1/admin/revoke'));
    await handleAdmin(post('/api/v1/admin/unrevoke', { fingerprint: VALID_FP }, env, { Authorization: 'Bearer test-admin-token' }), env, new URL('https://x/api/v1/admin/unrevoke'));
    const res = await handleVerify(post('/api/v1/verify', { package: EXPECTED_PACKAGE, version: '2.7.5', fingerprint: VALID_FP }), env);
    assert.equal((await res.json()).status, 'genuine');
});

test('bad request shapes are rejected', async () => {
    const env = makeEnv();
    const short = await handleVerify(post('/api/v1/verify', { package: EXPECTED_PACKAGE, fingerprint: 'short' }), env);
    assert.equal(short.status, 400);
    const empty = await handleVerify(new Request('https://x/api/v1/verify', { method: 'POST', body: 'not-json' }), env);
    assert.equal(empty.status, 400);
});

test('rate limiter blocks over-limit clients', () => {
    _reset();
    const ip = '1.2.3.4';
    let allowed = 0;
    for (let i = 0; i < 200; i++) {
        if (rateLimit(ip)) allowed++;
    }
    assert.equal(allowed, 120);
    assert.equal(rateLimit('other-ip'), true);
});

test('safeEqual is constant-time-safe and rejects length mismatches', () => {
    assert.equal(safeEqual('abc', 'abc'), true);
    assert.equal(safeEqual('abc', 'abd'), false);
    assert.equal(safeEqual('a', 'abc'), false);
    assert.equal(safeEqual('', 'abc'), false);
});

