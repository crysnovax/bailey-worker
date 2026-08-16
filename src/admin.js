/**
 * Admin API — revocation control for the operator (Crysnovax).
 *
 * All routes require `Authorization: Bearer <ADMIN_TOKEN>`.
 *
 *   POST /api/v1/admin/revoke   { fingerprint, reason? }   → blacklist an install
 *   POST /api/v1/admin/unrevoke { fingerprint }             → whitelist it again
 *   GET  /api/v1/admin/revoked                              → list blacklist
 *   GET  /api/v1/admin/stats                                → install registry summary
 */

import { revokeFingerprint, unrevokeFingerprint, listRevoked, listInstalls } from './kv.js';
import { safeEqual } from './attest.js';

const json = (body, status = 200) => new Response(JSON.stringify(body), {
    status,
    headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff'
    }
});

const FINGERPRINT_RE = /^[A-Za-z0-9:_-]{16,128}$/;

const authenticate = (request, env) => {
    const header = request.headers.get('Authorization') || '';
    const token = header.startsWith('Bearer ') ? header.slice('Bearer '.length) : '';
    if (!env.ADMIN_TOKEN || !safeEqual(token, env.ADMIN_TOKEN)) {
        return false;
    }
    return true;
};

const readBody = async (request) => {
    try {
        const text = await request.text();
        if (text.length > 1024) {
            return null;
        }
        return JSON.parse(text);
    }
    catch {
        return null;
    }
};

export const handleAdmin = async (request, env, url) => {
    if (!authenticate(request, env)) {
        return json({ error: 'unauthorized' }, 401);
    }

    if (url.pathname === '/api/v1/admin/revoke' && request.method === 'POST') {
        const body = await readBody(request);
        const fingerprint = body?.fingerprint || '';
        if (!FINGERPRINT_RE.test(fingerprint)) {
            return json({ error: 'bad_request', hint: 'invalid fingerprint' }, 400);
        }
        const ok = await revokeFingerprint(env, fingerprint, body?.reason);
        return json({ ok, fingerprint, revoked: true });
    }

    if (url.pathname === '/api/v1/admin/unrevoke' && request.method === 'POST') {
        const body = await readBody(request);
        const fingerprint = body?.fingerprint || '';
        if (!FINGERPRINT_RE.test(fingerprint)) {
            return json({ error: 'bad_request', hint: 'invalid fingerprint' }, 400);
        }
        const ok = await unrevokeFingerprint(env, fingerprint);
        return json({ ok, fingerprint, revoked: false });
    }

    if (url.pathname === '/api/v1/admin/revoked' && request.method === 'GET') {
        const revoked = await listRevoked(env);
        return json({ revoked, count: revoked.length });
    }

    if (url.pathname === '/api/v1/admin/stats' && request.method === 'GET') {
        const [revoked, installs] = await Promise.all([listRevoked(env), listInstalls(env, 100)]);
        const byStatus = {};
        for (const install of installs) {
            const key = install.status || 'unknown';
            byStatus[key] = (byStatus[key] || 0) + 1;
        }
        return json({
            counts: {
                revoked: revoked.length,
                installs: installs.length,
                byStatus
            },
            recent: installs.slice(-25)
        });
    }

    return json({ error: 'not_found' }, 404);
};

