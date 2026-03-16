# Security Policy

## Supported Versions

| Version    | Supported             |
| ---------- | --------------------- |
| `dev-dev`  | ✅ Active development |
| `dev-main` | ✅ Stable             |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Email: **security@ignitlabs.mv**

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (optional)

We will acknowledge within **48 hours** and aim to release a fix within **7 days** for critical issues.

---

## Threat Model

This SDK is a **client-side package** installed in Laravel applications that integrate with Identity Bridge Central. It does not contain secrets — all sensitive values are injected via environment variables at runtime.

### What this SDK does

1. **JWT verification** — Validates RS256-signed JWTs issued by Identity Bridge Central using the server's public key (fetched from the JWKS endpoint)
2. **Admin SSO** — Implements the PKCE OAuth2 flow so admin users can authenticate via Identity Bridge Central
3. **Webhook processing** — Verifies HMAC-SHA256 signatures on incoming webhook payloads
4. **Shadow user provisioning** — Provisions/upserts local user records from verified JWT claims

### What is NOT in this SDK

- ❌ No private keys
- ❌ No client secrets
- ❌ No API tokens
- ❌ No user data
- ❌ No database credentials
- ❌ No business logic

All sensitive configuration is read from environment variables — see `.env.example` in the consuming application.

---

## Security Design Decisions

### JWT Algorithm Pinning

The SDK explicitly pins the JWT algorithm to **RS256** and verifies the `alg` header before decoding. This prevents algorithm confusion attacks (RS256 → HS256) where an attacker could sign a token using the public key as an HMAC secret.

```php
// Algorithm is verified in the header before decode
if (($header['alg'] ?? null) !== 'RS256') {
    throw new InvalidArgumentException('Token must use RS256 algorithm');
}
```

### PKCE Implementation

The Admin SSO flow uses PKCE (RFC 7636) with:

- `random_bytes(64)` for the code verifier (512 bits of entropy)
- SHA-256 for the code challenge
- State parameter for CSRF protection

The code verifier is stored in the session and never transmitted except during the token exchange.

### Webhook Signature Verification

Webhook payloads are verified using HMAC-SHA256:

- The webhook secret is pre-hashed with SHA-256 before use (prevents length extension)
- Comparison uses `hash_equals()` (constant-time, prevents timing attacks)
- Payloads older than 5 minutes are rejected (prevents replay of stale webhooks)
- Each webhook JTI is cached for 1 hour to prevent duplicate delivery processing

### Token Revocation

The SDK maintains a local revocation mirror in Redis/cache. When a `token.revoked` webhook is received, the JTI is cached. All subsequent JWT validations check this mirror before verifying the signature (fast-path rejection).

### JWKS Key Rotation

Public keys are fetched from the JWKS endpoint and cached locally (default 1 hour). The `key.rotated` webhook triggers an immediate cache flush so the new key is fetched on the next validation request.

---

## What Reading This Code Reveals

This is an open-source SDK. Reading the source tells you:

- The OAuth2 endpoints used (`/oauth/authorize`, `/oauth/admin/token`)
- JWT claim names (`sub`, `iss`, `aud`, `kyc_tier`, `is_staff`, etc.)
- Webhook event names (`user.registered`, `token.revoked`, etc.)
- The PKCE and HMAC algorithms used (standard, publicly documented)

**None of this grants access.** Security relies on:

- The RS256 private key (server-side only, never in this SDK)
- The `client_secret` (env var, never in this SDK)
- The `webhook_secret` (env var, never in this SDK)
- Proper TLS on all endpoints
