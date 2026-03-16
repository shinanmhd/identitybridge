<?php

namespace IgniteLabs\IdentityBridge\Tests\Fixtures;

use Firebase\JWT\JWT;

class KeyFixture
{
    /**
     * Generate a fresh 2048-bit RSA keypair for testing.
     * Returns ['private' => PEM, 'public' => PEM, 'kid' => 'test-key-1']
     */
    public static function generate(string $kid = 'test-key-1'): array
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        openssl_pkey_export($resource, $privatePem);
        $details = openssl_pkey_get_details($resource);

        return [
            'private' => $privatePem,
            'public'  => $details['key'],
            'kid'     => $kid,
        ];
    }

    /**
     * Encode a JWT with the given claims, private key, and kid.
     */
    public static function makeJwt(array $claims, string $privateKey, string $kid): string
    {
        return JWT::encode($claims, $privateKey, 'RS256', $kid);
    }

    /**
     * Build a minimal JWKS array from a PEM public key and kid.
     */
    public static function makeJwks(string $publicPem, string $kid): array
    {
        $resource = openssl_pkey_get_public($publicPem);
        $details  = openssl_pkey_get_details($resource);
        $rsa      = $details['rsa'];

        return [
            'keys' => [
                [
                    'kty' => 'RSA',
                    'use' => 'sig',
                    'alg' => 'RS256',
                    'kid' => $kid,
                    'n'   => rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($rsa['n'])), '='),
                    'e'   => rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($rsa['e'])), '='),
                ],
            ],
        ];
    }

    /**
     * Build a valid claims array for testing. exp defaults to now + 900s.
     */
    public static function makeClaims(array $overrides = []): array
    {
        return array_merge([
            'sub'               => 'ib_test_identity_id',
            'iss'               => 'https://identity.ignitlabs.mv',
            'aud'               => ['test-app'],
            'jti'               => 'test-jti-' . uniqid(),
            'iat'               => time(),
            'exp'               => time() + 900,
            'kyc_tier'          => 1,
            'phone_verified'    => true,
            'is_of_legal_age'   => true,
            'aml_cleared'       => false,
            'ghost_identity_id' => null,
        ], $overrides);
    }
}
