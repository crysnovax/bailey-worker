# bailey-crysnovax-worker

Attestation & revocation API for **@crysnovax/baileys**, deployed at
**bailey.crysnovax.link** (Cloudflare Workers).

It exists to make rebranding / stealing the package expensive:

- every `@crysnovax/baileys` install phones home once per process with its
  package identity and a machine fingerprint;
- the worker answers **genuine**, **revoked**, or **rebranded**;
- a **revoked** or **rebranded** answer disables premium features
  (`verifiedMe` badge, secure Meta service label) in the client;
- you, the operator, can blacklist any fingerprint in seconds.

The client **fails open**: if the worker is unreachable or the request
errors, premium features stay enabled — a stolen copy that keeps the
phone-home still gets cut off the moment you revoke it, while a network
blip never breaks a legitimate bot.

## API

| Method | Path                     | Auth              | Purpose                          |
|--------|--------------------------|-------------------|----------------------------------|
| GET    | `/api/v1/health`         | –                 | Liveness                         |
| POST   | `/api/v1/verify`         | –                 | Client attestation               |
| POST   | `/api/v1/admin/revoke`   | `Bearer` token    | Blacklist a fingerprint          |
| POST   | `/api/v1/admin/unrevoke` | `Bearer` token    | Whitelist a fingerprint          |
| GET    | `/api/v1/admin/revoked`  | `Bearer` token    | List blacklist                   |
| GET    | `/api/v1/admin/stats`    | `Bearer` token    | Install registry summary         |

`POST /api/v1/verify` body:

```json
{ "package": "@crysnovax/baileys", "version": "2.7.5", "fingerprint": "<64 hex chars>" }
```

Response (HMAC-SHA256 signed with `ATTEST_SECRET`):

```json
{ "status": "genuine", "fingerprint": "…", "iat": 1780000000000, "exp": 1780086400000, "sig": "…" }
```

## Deploy from GitHub

1. **Create a new GitHub repo** and push this folder into it
   (the `bailey-worker.zip` in the parent repo contains exactly these
   files — unzip it, `git init`, push).

2. **Cloudflare API token** — dashboard → *My Profile → API Tokens →
   Create Token → "Edit Cloudflare Workers" template*. Give it
   *Workers Scripts: Edit* and *Workers KV: Edit* on your account.

3. Add two repo **Actions secrets**:
   - `CLOUDFLARE_API_TOKEN` — the token from step 2
   - `CLOUDFLARE_ACCOUNT_ID` — your account ID (dashboard → right sidebar)

4. **Create the KV namespace** (once):
   ```bash
   npm ci
   npx wrangler kv namespace create BAILEY_KV
   ```
   Paste the returned `id` and `preview_id` into `wrangler.toml`.

5. **Push to `main`** — the workflow in
   `.github/workflows/deploy.yml` runs `wrangler deploy` automatically.

6. **Point the domain** — dashboard → your worker → *Settings →
   Domains & Routes → Add custom domain*: `bailey.crysnovax.link`
   (the zone must be on your Cloudflare account).

## Secrets

| Variable        | Where            | Purpose                                    |
|-----------------|------------------|--------------------------------------------|
| `ADMIN_TOKEN`   | Worker env        | Bearer token for `/api/v1/admin/*`         |
| `ATTEST_SECRET` | Worker env        | HMAC key that signs attestations           || `ADMIN_OPERATOR`| Worker env (opt.)| Label recorded on revocations           |
| `OWNER_FINGERPRINTS` | Worker env (opt.) | Comma-separated fingerprints that are ALWAYS genuine (your own machines) |

Set them via the dashboard (*Settings → Variables and Secrets*) — never
commit them. Locally, copy `.dev.vars.example` to `.dev.vars`.

## Revoking a stolen install

```bash
curl -X POST https://bailey.crysnovax.link/api/v1/admin/revoke \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"fingerprint":"<64 hex chars>","reason":"rebranded"}'
```

To find fingerprints worth revoking:

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://bailey.crysnovax.link/api/v1/admin/stats
```

Every install that ever phoned home is listed with its package claim —
rebranded copies show `"status": "rebranded"` and their fingerprints can
be blacklisted immediately.

## Owner escape hatch (never lock yourself out)

The operator can never brick their own installs:

1. **Worker side** — put your own machine fingerprints in the
   `OWNER_FINGERPRINTS` env var (comma-separated). Owner fingerprints
   always get `genuine`, even if you accidentally revoke them. Compute
   yours with:

   ```bash
   node -e "import('node:crypto').then(async m=>{const os=await import('node:os');console.log(m.createHash('sha256').update([os.hostname(),os.platform(),os.arch(),(os.cpus?.[0]?.model||'unknown-cpu'),process.version].join('|')).digest('hex').slice(0,32))})"
   ```

2. **Client side** — while you are actively editing the package (e.g.
   with an AI assistant), set `CRYSNOVAX_TRUST_MODE=1` in the environment
   of your dev bots. It bypasses the local integrity checks and the
   install-time guard, so a legit edit (even one that trips a soft check)
   never locks you out. Remove it for production installs.

## Local development

```bash
npm ci
cp .dev.vars.example .dev.vars   # fill in tokens
npm run dev                      # wrangler dev
npm test                         # unit tests (node --test, no wrangler needed)
```

## Design notes ("air tight" trade-offs)

- **Fail-open by design.** KV errors, missing secrets, or network issues
  never brick a genuine install. Enforcement is additive: local integrity
  checks + remote attestation + install-time guard.
- **Fingerprints are per-machine**, derived from hostname/OS/arch/CPU —
  no files are written by the client. A determined attacker can forge one;
  this layer targets AI-assisted rebranding and casual theft, where the
  default behavior (keep the phone-home code, change the name) is exactly
  what gets detected and revoked.
- **Admin routes are token-gated** with constant-time comparison and
  per-IP rate limiting on everything.
- Response bodies are signed so a middlebox cannot silently alter an
  attestation; the client trusts HTTPS + the signature-verified status.

