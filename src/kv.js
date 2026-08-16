/**
 * KV helpers for the attestation registry.
 *
 * Every operation fails OPEN: if the KV namespace is missing or errors
 * (first deploy before setup, transient failures), the API keeps serving
 * "genuine" attestations instead of bricking legitimate users. Only an
 * explicit `revoked:` record denies an install.
 */

const PREFIX_REVOKED = 'revoked:';
const PREFIX_INSTALL = 'install:';

const safe = async (fallback, fn) => {
    try {
        return await fn();
    }
    catch {
        return fallback;
    }
};

export const isRevoked = (env, fingerprint) => safe(false, async () => {
    const record = await env.BAILEY_KV.get(PREFIX_REVOKED + fingerprint);
    return !!record;
});

export const revokeFingerprint = (env, fingerprint, reason) => safe(false, async () => {
    const record = JSON.stringify({
        revokedAt: Date.now(),
        reason: reason || 'license violation',
        admin: env.ADMIN_OPERATOR || 'unknown'
    });
    await env.BAILEY_KV.put(PREFIX_REVOKED + fingerprint, record);
    return true;
});

export const unrevokeFingerprint = (env, fingerprint) => safe(false, async () => {
    await env.BAILEY_KV.delete(PREFIX_REVOKED + fingerprint);
    return true;
});

export const listRevoked = (env) => safe([], async () => {
    const { keys } = await env.BAILEY_KV.list({ prefix: PREFIX_REVOKED });
    const out = [];
    for (const key of keys) {
        const record = await env.BAILEY_KV.get(key.name);
        out.push({
            fingerprint: key.name.slice(PREFIX_REVOKED.length),
            ...(record ? JSON.parse(record) : {})
        });
    }
    return out;
});

export const recordInstall = (env, data) => safe(false, async () => {
    const key = PREFIX_INSTALL + data.fingerprint;
    const existing = await env.BAILEY_KV.get(key);
    const prev = existing ? JSON.parse(existing) : {};
    const now = Date.now();
    const merged = {
        ...prev,
        ...data,
        firstSeen: prev.firstSeen || now,
        lastSeen: now,
        count: (prev.count || 0) + 1
    };
    await env.BAILEY_KV.put(key, JSON.stringify(merged));
    return true;
});

export const listInstalls = (env, limit = 50) => safe([], async () => {
    const { keys } = await env.BAILEY_KV.list({ prefix: PREFIX_INSTALL, limit });
    const out = [];
    for (const key of keys) {
        const record = await env.BAILEY_KV.get(key.name);
        out.push({
            fingerprint: key.name.slice(PREFIX_INSTALL.length),
            ...(record ? JSON.parse(record) : {})
        });
    }
    return out;
});
      
