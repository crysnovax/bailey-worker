/**
 * Client attestation endpoint.
 *
 * The @crysnovax/baileys client phones home on socket connect with its
 * package identity + a machine fingerprint. This worker decides whether
 * the install is genuine, revoked, or a rebranded copy, and answers with
 * an HMAC-signed attestation the client can cache.
 *
 * Rules:
 *  - package must claim the genuine npm name       → else status "rebranded"
 *  - fingerprint must not be in the revoked list   → else status "revoked"
 *  - everything else                               → status "genuine"
 *
 * KV failures fail open (genuine), so the service never brick-rolls a
 * legitimate user because of a transient backend error.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';
import { isRevoked, recordInstall } from './kv.js';

export const EXPECTED_PACKAGE = '@crysnovax/baileys';
export const ATTESTATION_TTL_MS = 24 * 60 * 60 * 1000; // 24h

const MAX_BODY_BYTES = 1024;
const FINGERPRINT_RE = /^[A-Za-z0-9:_-]{16,128}$/;
const VERSION_RE = /^[0-9A-Za-z.+-]{1,64}$/;

const json = (body, status = 200) => new Response(JSON.stringify(body), {
    status,
    headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff'
    }
});

/** HMAC-SHA256 signature over the stable attestation fields. */
export const signAttestation = (payload, secret) => {
    const { sig, ...rest } = payload;
    const canonical = JSON.stringify(rest);
    const digest = createHmac('sha256', secret).update(canonical).digest('hex');
    return { ...rest, sig: digest };
};

/** Constant-time check of a presented token against the expected one. */
export const safeEqual = (a, b) => {
    if (typeof a !== 'string' || typeof b !== 'string' || a.length === 0 || b.length === 0) {
        return false;
    }
    const bufA = Buffer.from(a);
    const bufB = Buffer.from(b);
    return bufA.length === bufB.length && timingSafeEqual(bufA, bufB);
};

const readBody = async (request) => {
    try {
        const text = await request.text();
        if (text.length > MAX_BODY_BYTES) {
            return null;
        }
        return JSON.parse(text);
    }
    catch {
        return null;
    }
};

export const handleVerify = async (request, env) => {
    const body = await readBody(request);
    if (!body || typeof body !== 'object') {
        return json({ error: 'bad_request', hint: 'valid JSON body required' }, 400);
    }

    const fingerprint = typeof body.fingerprint === 'string' ? body.fingerprint : '';
    const pkg = typeof body.package === 'string' ? body.package : '';
    const version = typeof body.version === 'string' ? body.version : '';

    if (!FINGERPRINT_RE.test(fingerprint)) {
        return json({ error: 'bad_request', hint: 'invalid fingerprint' }, 400);
    }
    if (pkg !== EXPECTED_PACKAGE) {
        // Rebranded copy — deny premium, and log the fingerprint so the
        // operator can see exactly which machines are running a fork.
        await recordInstall(env, {
            fingerprint,
            package: pkg || '(missing)',
            version,
            status: 'rebranded'
        });
        return json(signAttestation({
            status: 'rebranded',
            fingerprint,
            iat: Date.now()
        }, env.ATTEST_SECRET || 'dev-only-secret'));
    }

    // Owner escape hatch: maintainer machines (OWNER_FINGERPRINTS) are ALWAYS
    // genuine, even if accidentally revoked — the operator can never lock
    // themselves out of their own installs.
    const owners = (env.OWNER_FINGERPRINTS || '').split(',').map(s => s.trim()).filter(Boolean);
    if (owners.includes(fingerprint)) {
        const now = Date.now();
        return json(signAttestation({
            status: 'genuine',
            fingerprint,
            iat: now,
            exp: now + ATTESTATION_TTL_MS
        }, env.ATTEST_SECRET || 'dev-only-secret'));
    }

    const revoked = await isRevoked(env, fingerprint);
    await recordInstall(env, {
        fingerprint,
        package: pkg,
        version: VERSION_RE.test(version) ? version : '(unknown)',
        status: revoked ? 'revoked' : 'genuine'
    });

    const now = Date.now();
    return json(signAttestation({
        status: revoked ? 'revoked' : 'genuine',
        fingerprint,
        iat: now,
        exp: now + ATTESTATION_TTL_MS
    }, env.ATTEST_SECRET || 'dev-only-secret'));
};
                                   
