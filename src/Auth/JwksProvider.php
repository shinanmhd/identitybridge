<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Auth;

use Firebase\JWT\JWK;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

class JwksProvider
{
    public function getKeySet(): array
    {
        $cacheKey = config('identity-bridge.cache_prefix', 'ib_sdk_').'jwks';
        $ttl = (int) config('identity-bridge.jwks_ttl', 3600);

        // Cache the raw JWKS array, not parsed keys — OpenSSLAsymmetricKey
        // objects cannot be serialized by PHP's cache drivers.
        $jwks = Cache::remember($cacheKey, $ttl, function () {
            $response = Http::get(config('identity-bridge.jwks_url'));

            return $response->json();
        });

        return JWK::parseKeySet($jwks);
    }

    public function rotateCache(): void
    {
        $cacheKey = config('identity-bridge.cache_prefix', 'ib_sdk_').'jwks';
        Cache::forget($cacheKey);
    }
}
