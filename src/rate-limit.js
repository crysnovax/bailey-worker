/**
 * Minimal in-memory sliding-window rate limiter, keyed by client IP.
 * State is per-isolate (resets when the worker restarts) — plenty for
 * slowing down scrapers and scripted abuse; KV-backed accounting is done
 * on top via the install registry.
 */

const WINDOW_MS = 60_000;
const LIMIT_PER_WINDOW = 120;
const PRUNE_EVERY = 1000;

const buckets = new Map();
let calls = 0;

export const rateLimit = (ip) => {
    const now = Date.now();
    const bucket = buckets.get(ip);
    if (!bucket || bucket.reset <= now) {
        buckets.set(ip, { count: 1, reset: now + WINDOW_MS });
    }
    else {
        bucket.count += 1;
        if (bucket.count > LIMIT_PER_WINDOW) {
            return false;
        }
    }
    // Opportunistically prune dead entries so the map cannot grow forever
    if (++calls % PRUNE_EVERY === 0) {
        for (const [key, b] of buckets) {
            if (b.reset <= now) {
                buckets.delete(key);
            }
        }
    }
    return true;
};

/** Exported for tests. */
export const _reset = () => {
    buckets.clear();
    calls = 0;
};

