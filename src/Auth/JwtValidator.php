<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Auth;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use IgniteLabs\IdentityBridge\Identity\IdentityClaims;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

class JwtValidator
{
    public function __construct(private readonly JwksProvider $jwks) {}

    public function validate(string $token): ?IdentityClaims
    {
        if (empty($token)) {
            return null;
        }

        try {
            // Step 1: peek jti without sig check (fast revocation check)
            $jti = $this->peekJti($token);

            // Step 2: check local revocation mirror
            if ($jti !== null) {
                $prefix = config('identity-bridge.cache_prefix', 'ib_sdk_');
                if (Cache::has($prefix . 'revoked:' . $jti)) {
                    Log::debug('IdentityBridge: token rejected — JTI in revocation mirror', ['jti' => $jti]);
                    return null;
                }
            }

            // Step 3: get kid from header
            $kid = $this->peekKid($token);
            if ($kid === null) {
                Log::debug('IdentityBridge: token rejected — missing kid header');
                return null;
            }

            // Fetch key set and find matching key
            $keySet = $this->jwks->getKeySet();
            if (! isset($keySet[$kid])) {
                Log::debug('IdentityBridge: token rejected — unknown kid', ['kid' => $kid]);
                return null;
            }

            $key = $keySet[$kid];

            // Step 4: decode + RS256 verify
            $leeway      = (int) config('identity-bridge.jwt_leeway', 30);
            JWT::$leeway = $leeway;

            $payload = JWT::decode($token, $key instanceof Key ? $key : new Key($key, 'RS256'));
            $claims  = (array) $payload;

            // Step 5: validate issuer
            $expectedIssuer = config('identity-bridge.issuer');
            if (($claims['iss'] ?? null) !== $expectedIssuer) {
                Log::debug('IdentityBridge: token rejected — issuer mismatch', ['iss' => $claims['iss'] ?? null]);
                return null;
            }

            // Step 6: validate audience
            $expectedAudience = config('identity-bridge.audience');
            $aud = (array) ($claims['aud'] ?? []);
            if (! in_array($expectedAudience, $aud, true)) {
                Log::debug('IdentityBridge: token rejected — audience mismatch', ['aud' => $aud]);
                return null;
            }

            return new IdentityClaims($claims);

        } catch (\Throwable $e) {
            Log::debug('IdentityBridge: token validation failed', ['error' => $e->getMessage()]);
            return null;
        }
    }

    private function peekJti(string $token): ?string
    {
        try {
            $parts = explode('.', $token);
            if (count($parts) !== 3) {
                return null;
            }
            $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
            return $payload['jti'] ?? null;
        } catch (\Throwable) {
            return null;
        }
    }

    private function peekKid(string $token): ?string
    {
        try {
            $parts = explode('.', $token);
            if (count($parts) !== 3) {
                return null;
            }
            $header = json_decode(base64_decode(strtr($parts[0], '-_', '+/')), true);
            return $header['kid'] ?? null;
        } catch (\Throwable) {
            return null;
        }
    }
}
