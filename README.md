# Ignite Identity Bridge SDK

[![Tests](https://img.shields.io/github/actions/workflow/status/ignitelabs/identitybridge/run-tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/ignitelabs/identitybridge/actions/workflows/run-tests.yml)
[![Latest Version on Packagist](https://img.shields.io/packagist/v/ignitelabs/identitybridge.svg?style=flat-square)](https://packagist.org/packages/ignitelabs/identitybridge)
[![PHP Version](https://img.shields.io/packagist/dependency-v/ignitelabs/identity-bridge/php?style=flat-square)](https://packagist.org/packages/ignitelabs/identity-bridge)
[![License](https://img.shields.io/packagist/l/ignitelabs/identity-bridge.svg?style=flat-square)](LICENSE.md)

The official Laravel SDK for **Ignite Identity Bridge Central** — a centralised Phone+OTP identity microservice for the Ignite Labs ecosystem.

Drop this package into any Ignite Labs app (Hadhiya, Hadhiya Fihaara, etc.) to get stateless RS256 JWT authentication, automatic JWKS key rotation, sub-millisecond token revocation, KYC tier middleware, shadow user auto-provisioning, a service-to-service HTTP client, and strongly typed Laravel events for all 8 identity webhook types.

---

## Quick install

```bash
composer require ignitelabs/identity-bridge
php artisan identity-bridge:install
php artisan migrate
```

---

## Minimal usage

```php
// config/auth.php
'guards' => [
    'identity' => ['driver' => 'identity', 'provider' => 'users'],
],
```

```php
// routes/api.php
use function IgniteLabs\IdentityBridge\identity;

Route::middleware('auth:identity')->group(function () {
    Route::get('/me', function () {
        $claims = identity();

        return [
            'id'       => $claims->sub(),
            'kyc_tier' => $claims->kycTier(),
            'verified' => $claims->isVerified(),
        ];
    });
});

// Require full KYC (tier 2) — returns 403 + verify_url if insufficient
Route::middleware(['auth:identity', 'kyc:2'])->group(function () {
    Route::post('/high-value', HighValueController::class);
});
```

---

## Documentation

| # | Document | Description |
|---|---|---|
| 01 | [Overview](docs/01-overview.md) | What is Identity Bridge? Non-technical intro for business readers. |
| 02 | [Installation](docs/02-installation.md) | Step-by-step setup guide. |
| 03 | [Configuration](docs/03-configuration.md) | Every config key documented. |
| 04 | [Authentication](docs/04-authentication.md) | JWT pipeline, `IdentityClaims` API, guard internals. |
| 05 | [Middleware](docs/05-middleware.md) | `verify.webhook`, `provide.shadow`, `kyc` reference. |
| 06 | [Webhooks](docs/06-webhooks.md) | All 8 events, payloads, listener examples. |
| 07 | [Service Client](docs/07-service-client.md) | `IdentityBridgeClient` / `Identity` facade reference. |
| 08 | [Commands](docs/08-commands.md) | All 4 Artisan commands. |
| 09 | [Testing](docs/09-testing.md) | Faking JWTs, webhook tests, mocking the client. |
| 10 | [Security](docs/10-security.md) | Security model for compliance and technical review. |
| 11 | [Troubleshooting](docs/11-troubleshooting.md) | Common problems and solutions. |

Start at the [documentation index](docs/00-index.md) for audience-specific routing.

---

## Requirements

- PHP 8.4+
- Laravel 12
- A running [Ignite Identity Bridge Central](https://github.com/ignitelabs/ignite-identity-bridge-central) instance

---

## License

MIT. See [LICENSE.md](LICENSE.md).
