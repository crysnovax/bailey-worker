/**
 * bailey.crysnovax.link — attestation & revocation API for @crysnovax/baileys.
 *hy
 * Routes:
 *   GET  /api/v1/health                → liveness
 *   POST /api/v1/verify                → client attestation (see src/attest.js)
 *   POST /api/v1/admin/revoke          → operator: blacklist an install
 *   POST /api/v1/admin/unrevoke        → operator: whitelist an install
 *   GET  /api/v1/admin/revoked         → operator: blacklist
 *   GET  /api/v1/admin/stats           → operator: registry summary
 */

import { handleVerify } from './attest.js';
import { handleAdmin } from './admin.js';
import { rateLimit } from './rate-limit.js';

const json = (body, status = 200) => new Response(JSON.stringify(body), {
    status,
    headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff'
    }
});

const CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
};

export default {
    async fetch(request, env) {
        const url = new URL(request.url);

        if (request.method === 'OPTIONS') {
            return new Response(null, { status: 204, headers: CORS_HEADERS });
        }

        // Per-IP rate limit on every route (admin included — the token
        // still gates access, this just slows brute-forcing).
        const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
        if (!rateLimit(ip)) {
            return json({ error: 'rate_limited', retryAfterSec: 60 }, 429);
        }

        if (url.pathname === '/api/v1/health') {
            return json({ ok: true, service: 'bailey-attest' });
        }

        if (url.pathname === '/api/v1/verify' && request.method === 'POST') {
            return handleVerify(request, env);
        }

        if (url.pathname.startsWith('/api/v1/admin')) {
            return handleAdmin(request, env, url);
        }

        return json({ error: 'not_found' }, 404);
    }
};
